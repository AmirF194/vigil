import { beforeEach, describe, expect, it } from "vitest";
import type OpenAI from "openai";
import { EMIT_TOOL, LlmError, llm_output, renderDispatch, resetEmitMode } from "../ai/llm.js";
import { Limiter } from "../ai/limiter.js";
import type { DispatchRequest } from "../ai/types.js";

type Body = OpenAI.Chat.ChatCompletionCreateParamsNonStreaming;

const SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["action"],
  properties: { action: { type: "string", enum: ["CONCLUDE"] } },
};

function limiter(): Limiter {
  return new Limiter({ rpm: 10_000, tpm: 10_000_000 }, 4, 1);
}

function completion(message: Record<string, unknown>): OpenAI.Chat.ChatCompletion {
  return {
    choices: [{ message, finish_reason: "stop", index: 0, logprobs: null }],
    usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
  } as unknown as OpenAI.Chat.ChatCompletion;
}

function clientOf(create: (body: Body) => Promise<OpenAI.Chat.ChatCompletion>): OpenAI {
  return { chat: { completions: { create } } } as unknown as OpenAI;
}

function badRequest(): Error {
  return Object.assign(new Error("response_format is not supported"), { status: 400 });
}

beforeEach(() => resetEmitMode());

describe("llm_output", () => {
  it("returns a schema-valid emission from response_format", async () => {
    const bodies: Body[] = [];
    const client = clientOf(async (body) => {
      bodies.push(body);
      return completion({ role: "assistant", content: '{"action":"CONCLUDE"}' });
    });

    const result = await llm_output<{ action: string }>({
      client,
      model: "openai/gpt-4o",
      messages: [{ role: "user", content: "go" }],
      schema: SCHEMA,
      limiter: limiter(),
    });

    expect(result.value.action).toBe("CONCLUDE");
    expect(result.rejected).toEqual([]);
    expect(bodies[0]!.response_format).toBeDefined();
    expect(result.cost_usd).toBeGreaterThan(0);
  });

  it("downgrades to a tool-shaped emit when the gateway rejects response_format", async () => {
    const bodies: Body[] = [];
    const client = clientOf(async (body) => {
      bodies.push(body);
      if (body.response_format !== undefined) throw badRequest();
      return completion({
        role: "assistant",
        tool_calls: [{ id: "1", type: "function", function: { name: EMIT_TOOL, arguments: '{"action":"CONCLUDE"}' } }],
      });
    });

    const options = {
      client,
      model: "openai/gpt-4o",
      messages: [{ role: "user" as const, content: "go" }],
      schema: SCHEMA,
      limiter: limiter(),
    };
    expect((await llm_output<{ action: string }>(options)).value.action).toBe("CONCLUDE");

    // The downgrade is remembered, so the second call never probes again.
    await llm_output<{ action: string }>(options);
    expect(bodies.filter((body) => body.response_format !== undefined)).toHaveLength(1);
    expect(bodies.at(-1)!.tool_choice).toEqual({ type: "function", function: { name: EMIT_TOOL } });
  });

  it("re-prompts once on a schema violation and records the rejection", async () => {
    let call = 0;
    const client = clientOf(async () => {
      call += 1;
      const content = call === 1 ? '{"action":"NOPE"}' : '{"action":"CONCLUDE"}';
      return completion({ role: "assistant", content });
    });

    const result = await llm_output<{ action: string }>({
      client,
      model: "openai/gpt-4o",
      messages: [{ role: "user", content: "go" }],
      schema: SCHEMA,
      limiter: limiter(),
    });

    expect(result.value.action).toBe("CONCLUDE");
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]).toContain("NOPE");
  });

  it("gives up rather than returning something off-schema", async () => {
    const client = clientOf(async () => completion({ role: "assistant", content: "not json at all" }));
    await expect(
      llm_output({
        client,
        model: "openai/gpt-4o",
        messages: [{ role: "user", content: "go" }],
        schema: SCHEMA,
        limiter: limiter(),
      }),
    ).rejects.toThrow(LlmError);
  });

  it("does not swallow a non-400 failure as a schema downgrade", async () => {
    const client = clientOf(async () => {
      throw Object.assign(new Error("nope"), { status: 401 });
    });
    await expect(
      llm_output({
        client,
        model: "openai/gpt-4o",
        messages: [{ role: "user", content: "go" }],
        schema: SCHEMA,
        limiter: limiter(),
      }),
    ).rejects.toThrow(/nope/);
  });
});

describe("renderDispatch", () => {
  it("gives a fanned-out worker its own focus", () => {
    const request: DispatchRequest = {
      dispatch_id: "dsp-1",
      hunt_id: "hunt-1",
      agent_id: "threat_hunter",
      query_intent: "characterise outbound traffic",
      focus: "check 10.0.0.1",
      target_hypothesis_id: "h-1",
      scope: { tenant: "acme" },
    };
    const rendered = renderDispatch(request, "scenario text");
    expect(rendered).toContain("characterise outbound traffic");
    expect(rendered).toContain("check 10.0.0.1");
    expect(rendered).toContain("h-1");
    expect(rendered).toContain("scenario text");
  });
});
