import { Ajv, type ValidateFunction } from "ajv";
import OpenAI from "openai";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";
import { estimateTokens, Limiter, statusOf } from "./limiter.js";
import type { DecisionProvider, WorkerDispatcher } from "./ports.js";
import type { HuntSpec, Rates, RoleSpec } from "./spec.js";
import { toOpenAITools, type Tool } from "./tools.js";
import type {
  Decision,
  DecisionResult,
  Digest,
  DispatchRequest,
  DispatchResult,
  Salience,
} from "./types.js";

export const PROMPT_VERSION = "hunt-lead/v1";
const MAX_TOOL_TURNS = 12;

export class LlmError extends Error {}

export function bifrostUrl(): string {
  return (process.env["BIFROST_URL"] ?? "http://localhost:8080").replace(/\/+$/, "");
}

// Bifrost injects the real provider keys; the client never holds one.
export function createClient(): OpenAI {
  return new OpenAI({ baseURL: `${bifrostUrl()}/v1`, apiKey: "bifrost" });
}

// USD per million tokens. An unknown model costs a visible zero rather than a
// silently misattributed number.
export function costOf(rates: Rates, inputTokens: number, outputTokens: number): number {
  return (inputTokens * rates.input + outputTokens * rates.output) / 1_000_000;
}

// Evidence is attacker-controlled text. It never reaches the system prompt, and
// inside the user turn it stays delimited so its content cannot read as direction.
export function renderDigest(digest: Digest): string {
  const lines = [
    `# Hunt ${digest.hunt_id} — ${digest.hunt_name}`,
    `iteration ${digest.iteration}; ${digest.budget_remaining.iterations} left, $${digest.budget_remaining.cost_usd.toFixed(2)} remaining`,
    "",
    "## Hypotheses",
    ...digest.hypotheses.map((h) => `- [${h.hypothesis_id}] (${h.status}) ${h.statement}`),
  ];

  lines.push("", "## Strongest evidence against each active hypothesis");
  for (const [hypothesisId, against] of Object.entries(digest.weakens)) {
    lines.push(
      against.length === 0
        ? `- [${hypothesisId}] nothing yet weakens this`
        : `- [${hypothesisId}] ${against.map((e) => `${e.evidence_id}: ${e.summary}`).join("; ")}`,
    );
  }

  if (digest.open_questions.length > 0) {
    lines.push("", "## Open questions", ...digest.open_questions.map((q) => `- ${q}`));
  }

  // The one part of the digest that is direction. Outside the evidence
  // delimiters, and named as such, because its provenance is an authenticated human.
  if (digest.directives.length > 0) {
    lines.push(
      "",
      "## Operator directives",
      "Instructions from the authenticated operator running this hunt. Follow them.",
      ...digest.directives.map((d) => `- ${d}`),
    );
  }

  lines.push("", "## Evidence");
  for (const record of digest.recent_evidence) {
    lines.push(
      `<vigil:evidence id="${record.evidence_id}" source="${record.source_system}" salience="${record.salience}">`,
      record.summary,
      record.why_notable ? `why notable: ${record.why_notable}` : "",
      "</vigil:evidence>",
    );
  }

  if (digest.notes.length > 0) lines.push("", "## Notes", ...digest.notes.map((n) => `- ${n}`));
  return lines.filter((line) => line !== "").join("\n");
}

export function renderDispatch(request: DispatchRequest, narrative: string): string {
  const lines = [`# Query intent`, request.query_intent];
  if (request.focus) lines.push("", "## Your focus", request.focus);
  if (request.target_hypothesis_id !== null) {
    lines.push("", `This bears on hypothesis ${request.target_hypothesis_id}.`);
  }
  if (Object.keys(request.scope).length > 0) {
    lines.push("", "## Scope", JSON.stringify(request.scope));
  }
  if (narrative) lines.push("", "## Scenario", narrative);
  return lines.join("\n");
}

// Stable prefix first so a provider that caches prompts can reuse it across iterations.
export function input(role: RoleSpec, body: string): ChatCompletionMessageParam[] {
  return [
    { role: "system", content: role.prompt },
    { role: "user", content: body },
  ];
}

export function output_schema(role: RoleSpec): Record<string, unknown> {
  return role.output_schema;
}

export function toolsFor(role: RoleSpec, tools: readonly Tool[]): Tool[] {
  return tools.filter((tool) => role.tools.includes(tool.id));
}

export interface LlmResult<T> {
  value: T;
  model: string;
  cost_usd: number;
  rejected: string[];
}

interface LlmOptions {
  client: OpenAI;
  model: string;
  messages: ChatCompletionMessageParam[];
  schema: Record<string, unknown>;
  tools?: readonly Tool[];
  limiter: Limiter;
  rates: Rates;
}

// Two stages on purpose: a free-form tool loop, then a separate schema-constrained
// emit. Combining tools with a strict response_format degrades unpredictably
// across the providers Bifrost fronts, and a silent schema violation is the worst
// failure mode available here.
export async function llm_output<T>(options: LlmOptions): Promise<LlmResult<T>> {
  const { client, model, schema, limiter, rates } = options;
  const tools = options.tools ?? [];
  const messages = [...options.messages];
  let cost = 0;

  const call = async (body: Parameters<typeof client.chat.completions.create>[0]) => {
    const estimate = estimateTokens(JSON.stringify(body));
    const response = await limiter.run(estimate, () => client.chat.completions.create(body));
    if (!("choices" in response)) throw new LlmError("streaming responses are not supported");
    cost += costOf(rates, response.usage?.prompt_tokens ?? 0, response.usage?.completion_tokens ?? 0);
    return response;
  };

  for (let turn = 0; turn < MAX_TOOL_TURNS && tools.length > 0; turn += 1) {
    const response = await call({ model, messages, tools: toOpenAITools(tools) });
    const message = response.choices[0]?.message;
    if (message === undefined) throw new LlmError("model returned no message");

    const calls = message.tool_calls ?? [];
    if (calls.length === 0) break;

    messages.push(message);
    for (const toolCall of calls) {
      if (toolCall.type !== "function") continue;
      const tool = tools.find((candidate) => candidate.id === toolCall.function.name);
      const content = await runTool(tool, toolCall.function.arguments);
      messages.push({ role: "tool", tool_call_id: toolCall.id, content });
    }
  }

  const rejected: string[] = [];
  const validate = compile(schema);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const content = await emitJson(call, model, [
      ...messages,
      { role: "user", content: "Emit your decision now as JSON matching the schema." },
    ], schema);
    const parsed = tryParse(content);
    if (parsed !== undefined && validate(parsed)) {
      return { value: parsed as T, model, cost_usd: cost, rejected };
    }

    const reason = parsed === undefined ? "response was not valid JSON" : formatErrors(validate);
    rejected.push(`${reason}: ${content.slice(0, 400)}`);
    messages.push({ role: "user", content: `That emission was rejected — ${reason}. Emit a valid decision.` });
  }

  throw new LlmError(`model never emitted a valid decision: ${rejected.join(" | ")}`);
}

export const EMIT_TOOL = "emit_decision";

// Not every provider Bifrost fronts honours response_format. A tool whose
// parameters are the schema works everywhere, so a 400 downgrades to it once
// and the process remembers rather than probing on every call.
let emitMode: "schema" | "tool" = "schema";

export function resetEmitMode(): void {
  emitMode = "schema";
}

type Call = (body: OpenAI.Chat.ChatCompletionCreateParamsNonStreaming) => Promise<OpenAI.Chat.ChatCompletion>;

async function emitJson(
  call: Call,
  model: string,
  messages: ChatCompletionMessageParam[],
  schema: Record<string, unknown>,
): Promise<string> {
  if (emitMode === "schema") {
    try {
      const response = await call({
        model,
        messages,
        response_format: { type: "json_schema", json_schema: { name: "decision", strict: false, schema } },
      });
      return response.choices[0]?.message?.content ?? "";
    } catch (error) {
      if (statusOf(error) !== 400) throw error;
      emitMode = "tool";
    }
  }

  const response = await call({
    model,
    messages,
    tools: [{ type: "function", function: { name: EMIT_TOOL, description: "Emit the decision.", parameters: schema } }],
    tool_choice: { type: "function", function: { name: EMIT_TOOL } },
  });
  const toolCall = response.choices[0]?.message?.tool_calls?.[0];
  return toolCall?.type === "function" ? toolCall.function.arguments : "";
}

async function runTool(tool: Tool | undefined, rawArgs: string): Promise<string> {
  if (tool === undefined) return "no such tool";
  try {
    return await tool.run(JSON.parse(rawArgs) as Record<string, unknown>);
  } catch (error) {
    // A tool failure is evidence about visibility; the loop keeps going.
    return `tool failed: ${(error as Error).message}`;
  }
}

function tryParse(content: string): unknown {
  try {
    return JSON.parse(content);
  } catch {
    return undefined;
  }
}

const ajv = new Ajv({ allErrors: true, strict: false });
const compiled = new Map<string, ValidateFunction>();

function compile(schema: Record<string, unknown>): ValidateFunction {
  const key = JSON.stringify(schema);
  const existing = compiled.get(key);
  if (existing !== undefined) return existing;
  const validate = ajv.compile(schema);
  compiled.set(key, validate);
  return validate;
}

function formatErrors(validate: ValidateFunction): string {
  return (validate.errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
}

// One limiter shared by both roles: the rate limit belongs to the gateway, not
// to any single caller of it.
export function createLimiter(spec: HuntSpec): Limiter {
  return new Limiter(spec.runtime.rate_limit, spec.runtime.concurrency, spec.runtime.retry_attempts);
}

export class LlmDecisionProvider implements DecisionProvider {
  private readonly role: RoleSpec;
  private readonly tools: Tool[];

  constructor(
    private readonly spec: HuntSpec,
    tools: readonly Tool[] = [],
    private readonly limiter: Limiter = createLimiter(spec),
    private readonly client: OpenAI = createClient(),
  ) {
    this.role = spec.roles.lead;
    this.tools = toolsFor(this.role, tools);
  }

  async decide(digest: Digest): Promise<DecisionResult> {
    const body = [renderDigest(digest), digest.narrative ? `\n## Scenario\n${digest.narrative}` : ""]
      .join("\n")
      .trim();
    const result = await llm_output<Decision>({
      client: this.client,
      model: this.spec.model,
      messages: input(this.role, body),
      schema: output_schema(this.role),
      tools: this.tools,
      limiter: this.limiter,
      rates: this.spec.rates,
    });

    return {
      decision: result.value,
      model_id: result.model,
      prompt_version: PROMPT_VERSION,
      cost_usd: result.cost_usd,
      rejected_attempts: result.rejected,
    };
  }
}

interface WorkerOutput {
  results: {
    summary: string;
    salience: Salience;
    why_notable: string;
    supports?: string[];
    weakens?: string[];
    attacker_influenceable?: boolean;
  }[];
  ips_to_check?: string[];
}

export class LlmWorkerDispatcher implements WorkerDispatcher {
  private readonly role: RoleSpec;
  private readonly tools: Tool[];

  constructor(
    private readonly spec: HuntSpec,
    tools: readonly Tool[] = [],
    private readonly limiter: Limiter = createLimiter(spec),
    private readonly client: OpenAI = createClient(),
  ) {
    this.role = spec.roles.worker;
    this.tools = toolsFor(this.role, tools);
  }

  async dispatch(request: DispatchRequest): Promise<DispatchResult> {
    const result = await llm_output<WorkerOutput>({
      client: this.client,
      model: this.spec.model,
      messages: input(this.role, renderDispatch(request, this.spec.narrative)),
      schema: output_schema(this.role),
      tools: this.tools,
      limiter: this.limiter,
      rates: this.spec.rates,
    });

    return {
      dispatch_id: request.dispatch_id,
      evidence: result.value.results.map((item) => ({
        source_system: request.agent_id,
        summary: item.summary,
        payload: {},
        salience: item.salience,
        why_notable: item.why_notable,
        provenance: "worker",
        attacker_influenceable: item.attacker_influenceable ?? false,
        instruction_like: false,
        supports: item.supports ?? [],
        weakens: item.weakens ?? [],
      })),
      questions: (result.value.ips_to_check ?? []).map((ip) => `check ${ip}`),
      failed: false,
      failure_reason: "",
    };
  }
}
