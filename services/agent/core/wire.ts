import OpenAI from "openai";
import type { TokenCounts } from "../contracts/budget.js";
import { estimateTokens, Limiter, statusOf } from "./limiter.js";
import {
  ProviderError,
  type Message,
  type Provider,
  type ProviderEvent,
  type ToolCall,
  type ToolSchema,
  type Turn,
  type TurnRequest,
} from "./provider.js";

// Unset, the gateway's own default cuts a long emission off mid-JSON, which
// arrives as an unparseable answer rather than as a limit that was hit.
const MAX_OUTPUT_TOKENS = 12_000;

export const EMIT_TOOL = "emit";

type Body = Omit<OpenAI.Chat.ChatCompletionCreateParams, "stream" | "stream_options">;

// Not every provider honours response_format, so a 400 downgrades once to a tool
// whose parameters are the schema. Remembered per model, never process-wide.
const emitModes = new Map<string, "schema" | "tool">();

export function resetEmitMode(): void {
  emitModes.clear();
}

export function openAiSurface(client: OpenAI, model: string, limiter: Limiter, provider_type: string): Provider {
  return new OpenAiSurface(client, model, limiter, provider_type);
}

// The one surface built. The gateway routes to either provider family behind a
// model name, so a second wire buys nothing until cache_control and thinking.
class OpenAiSurface implements Provider {
  constructor(
    private readonly client: OpenAI,
    readonly model: string,
    private readonly limiter: Limiter,
    readonly provider_type: string,
  ) {}

  // Assembled before the events are emitted, so usage precedes the tool calls --
  // the order the loop needs. The transport streams; this does not re-emit the
  // deltas, because nothing downstream renders a partial turn and a half-written
  // tool call is not a tool call.
  async *stream(request: TurnRequest): AsyncGenerator<ProviderEvent> {
    const turn = request.emit === undefined ? await this.ask(request) : await this.emit(request, request.emit);
    if (turn.content !== "") yield { type: "text_delta", text: turn.content };
    yield { type: "usage", tokens: turn.tokens };
    for (const call of turn.tool_calls) yield { type: "tool_call", call };
  }

  private async ask(request: TurnRequest): Promise<Turn> {
    const tools = request.tools.length === 0 ? {} : { tools: wireTools(request.tools) };
    return turnOf(await this.call({ model: this.model, messages: wire(request.messages), ...tools }, request.signal));
  }

  private async emit(request: TurnRequest, schema: Record<string, unknown>): Promise<Turn> {
    const messages = wire(request.messages);
    if ((emitModes.get(this.model) ?? "schema") === "schema") {
      try {
        const format = { type: "json_schema" as const, json_schema: { name: "emission", strict: false, schema } };
        return turnOf(await this.call({ model: this.model, messages, response_format: format }, request.signal));
      } catch (error) {
        if (statusOf(error) !== 400) throw error;
        emitModes.set(this.model, "tool");
      }
    }

    const emit = { name: EMIT_TOOL, description: "Emit your answer.", parameters: schema };
    const turn = turnOf(
      await this.call(
        {
          model: this.model,
          messages,
          tools: [{ type: "function", function: emit }],
          tool_choice: { type: "function", function: { name: EMIT_TOOL } },
        },
        request.signal,
      ),
    );
    // The emission arrived as the tool's arguments. It is returned as content so
    // the loop validates one shape whichever mode produced it.
    const emitted = turn.tool_calls.find((call) => call.tool === EMIT_TOOL);
    return { ...turn, content: emitted === undefined ? turn.content : emitted.args, tool_calls: [] };
  }

  // Streamed, and not for the deltas: a buffered completion is subject to the
  // gateway's non-streaming request ceiling -- 30 seconds in Bifrost, which no
  // network_config setting moves and which it returns as a 504. Every call that ran
  // longer died, so a role emitting a long answer failed where one emitting a short
  // decision went through, and the caller could only record that its tool had
  // failed. The method was already named stream() and the interface already said
  // "assembled from its stream"; only the wire disagreed.
  private async call(body: Body, signal?: AbortSignal): Promise<OpenAI.Chat.ChatCompletion> {
    // Before the limiter, not only inside the request: a call still queued behind
    // a rate limit is the cheapest one to give up on.
    signal?.throwIfAborted();
    // Assembled inside run() rather than after it, so the rate-limit slot is held
    // for the whole call and a mid-stream failure is retried like any other.
    return this.limiter.run(estimateTokens(JSON.stringify(body)), async () => {
      const stream = await this.client.chat.completions.create(
        { max_tokens: MAX_OUTPUT_TOKENS, ...body, stream: true, stream_options: { include_usage: true } },
        signal ? { signal } : {},
      );
      if (!(Symbol.asyncIterator in stream)) {
        throw new ProviderError("the gateway answered a stream request with a whole completion");
      }
      return assemble(stream);
    });
  }
}

// One completion out of its chunks. A tool call arrives split across them: the
// opening fragment carries id and name, every later one carries null for both and
// another slice of the arguments, so held values are kept rather than overwritten.
async function assemble(stream: AsyncIterable<OpenAI.Chat.ChatCompletionChunk>): Promise<OpenAI.Chat.ChatCompletion> {
  const calls = new Map<number, OpenAI.Chat.ChatCompletionMessageToolCall>();
  let content = "";
  let usage: OpenAI.CompletionUsage | undefined;
  let finish: OpenAI.Chat.ChatCompletion.Choice["finish_reason"] = "stop";
  let head: OpenAI.Chat.ChatCompletionChunk | undefined;

  for await (const chunk of stream) {
    head ??= chunk;
    // Sent once, in a final chunk of its own that carries no choice at all.
    if (chunk.usage) usage = chunk.usage;
    const choice = chunk.choices[0];
    if (choice === undefined) continue;
    if (choice.finish_reason) finish = choice.finish_reason;
    content += textOf(choice.delta.content);
    for (const delta of choice.delta.tool_calls ?? []) {
      const held = calls.get(delta.index);
      calls.set(delta.index, {
        id: delta.id ?? held?.id ?? "",
        type: "function",
        function: {
          name: delta.function?.name ?? held?.function.name ?? "",
          arguments: (held?.function.arguments ?? "") + (delta.function?.arguments ?? ""),
        },
      });
    }
  }

  if (head === undefined) throw new ProviderError("the gateway closed the stream without sending anything");
  const tool_calls = [...calls.entries()].sort(([a], [b]) => a - b).map(([, call]) => call);
  return {
    id: head.id,
    created: head.created,
    model: head.model,
    object: "chat.completion",
    choices: [
      {
        index: 0,
        finish_reason: finish,
        logprobs: null,
        message: { role: "assistant", content, refusal: null, ...(tool_calls.length === 0 ? {} : { tool_calls }) },
      },
    ],
    ...(usage === undefined ? {} : { usage }),
  };
}

function turnOf(response: OpenAI.Chat.ChatCompletion): Turn {
  const tokens = tokensOf(response.usage);
  const message = response.choices[0]?.message;
  if (message === undefined) throw new ProviderError("the model returned no message", tokens);
  return { content: textOf(message.content), tool_calls: callsOf(message.tool_calls), tokens };
}

function callsOf(calls: OpenAI.Chat.ChatCompletionMessageToolCall[] | undefined): ToolCall[] {
  return (calls ?? []).flatMap((call) =>
    call.type === "function" ? [{ id: call.id, tool: call.function.name, args: call.function.arguments }] : [],
  );
}

// Some providers reply with a content-block list. Handing an array to JSON.parse
// stringifies it to [object Object], throwing away an answer the model got right.
function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => (typeof block === "object" && block !== null ? String((block as { text?: unknown }).text ?? "") : ""))
    .join("");
}

// Two surfaces disagreeing about an input token, normalised so input is always the
// total: OpenAI already counts the cached share, Anthropic excludes both counters.
function tokensOf(usage: OpenAI.CompletionUsage | undefined): TokenCounts {
  const alternate = usage as
    | (typeof usage & { cache_read_input_tokens?: number; cache_creation_input_tokens?: number })
    | undefined;
  const reported = usage?.prompt_tokens ?? 0;
  const native = alternate?.cache_read_input_tokens !== undefined || alternate?.cache_creation_input_tokens !== undefined;
  const cache_read = usage?.prompt_tokens_details?.cached_tokens ?? alternate?.cache_read_input_tokens ?? 0;
  const cache_write = alternate?.cache_creation_input_tokens ?? 0;
  return {
    input: native ? reported + cache_read + cache_write : reported,
    output: usage?.completion_tokens ?? 0,
    cache_read,
    cache_write,
  };
}

function wire(messages: readonly Message[]): OpenAI.Chat.ChatCompletionMessageParam[] {
  return messages.map((message) => {
    if (message.role === "tool") return { role: "tool", tool_call_id: message.call_id, content: message.content };
    if (message.role !== "assistant") return { role: message.role, content: message.content };
    if (message.tool_calls.length === 0) return { role: "assistant", content: message.content };
    return { role: "assistant", content: message.content, tool_calls: message.tool_calls.map(wireCall) };
  });
}

function wireCall(call: ToolCall): OpenAI.Chat.ChatCompletionMessageToolCall {
  return { id: call.id, type: "function", function: { name: call.tool, arguments: call.args } };
}

function wireTools(tools: readonly ToolSchema[]): OpenAI.Chat.ChatCompletionTool[] {
  return tools.map((tool) => ({
    type: "function",
    function: { name: tool.id, description: tool.description, parameters: tool.parameters },
  }));
}
