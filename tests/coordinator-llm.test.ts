import type OpenAI from "openai";
import { beforeEach, describe, expect, it } from "vitest";
import type { Alert } from "../ai/alert.js";
import type { CoordinatorInput } from "../ai/coordinator-ports.js";
import { LlmCoordinatorProvider, renderCoordinatorInput } from "../ai/coordinator-llm.js";
import { Limiter } from "../ai/limiter.js";
import { resetEmitMode } from "../ai/llm.js";

type Body = OpenAI.Chat.ChatCompletionCreateParamsNonStreaming;

function limiter(): Limiter {
  return new Limiter({ rpm: 10_000, tpm: 10_000_000 }, 4, 1);
}

// A schema-only call (no tools) goes straight to the response_format emit, so the
// model's reply is the content of one completion.
function completion(json: string): OpenAI.Chat.ChatCompletion {
  return {
    choices: [{ message: { role: "assistant", content: json }, finish_reason: "stop", index: 0, logprobs: null }],
    usage: { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 },
  } as unknown as OpenAI.Chat.ChatCompletion;
}

function clientOf(create: (body: Body) => Promise<OpenAI.Chat.ChatCompletion>): OpenAI {
  return { chat: { completions: { create } } } as unknown as OpenAI;
}

function provider(create: (body: Body) => Promise<OpenAI.Chat.ChatCompletion>): LlmCoordinatorProvider {
  return new LlmCoordinatorProvider("openai/gpt-4o", { input: 1, output: 1 }, limiter(), clientOf(create));
}

function alert(entity: string): Alert {
  return { alert_id: "a1", entity, rule_name: "beaconing", severity: "high", timestamp: "2026-08-21T00:00:00.000Z", raw: {} };
}

const input = (overrides: Partial<CoordinatorInput> = {}): CoordinatorInput => ({
  alert: alert("10.0.0.1"),
  hunts: [],
  exact_match: null,
  ...overrides,
});

beforeEach(() => resetEmitMode());

describe("LlmCoordinatorProvider", () => {
  it("parses a START decision from the model", async () => {
    const provider_ = provider(async () => completion('{"action":"START","reason":"novel entity"}'));
    const decision = await provider_.decide(input());
    expect(decision.action).toBe("START");
    expect(decision.reason).toBe("novel entity");
  });

  it("parses a STEER decision carrying hunt_ids and a directive", async () => {
    const provider_ = provider(async () =>
      completion('{"action":"STEER","reason":"duplicate","hunt_ids":["hunt-1"],"directive":"check DNS"}'),
    );
    const decision = await provider_.decide(input());
    expect(decision.action).toBe("STEER");
    expect(decision.hunt_ids).toEqual(["hunt-1"]);
    expect(decision.directive).toBe("check DNS");
  });

  it("sends the alert and the live hunts to the model", async () => {
    const bodies: Body[] = [];
    const provider_ = provider(async (body) => {
      bodies.push(body);
      return completion('{"action":"DROP","reason":"dup"}');
    });

    await provider_.decide(
      input({
        hunts: [{ hunt_id: "hunt-42", seed_entity: "ip:10.0.0.1", active_hypotheses: ["beaconing"], status: "active" }],
        exact_match: { hunt_id: "hunt-42", seed_entity: "ip:10.0.0.1", active_hypotheses: ["beaconing"], status: "active" },
      }),
    );

    const sent = JSON.stringify(bodies[0]?.messages);
    expect(sent).toContain("10.0.0.1");
    expect(sent).toContain("hunt-42");
  });

  it("rejects an action outside the closed vocabulary", async () => {
    // DEFER is coordinator-authored; the schema must not let the model emit it.
    // llm_output retries once, then throws when nothing valid comes back.
    const provider_ = provider(async () => completion('{"action":"DEFER","reason":"nope"}'));
    await expect(provider_.decide(input())).rejects.toThrow();
  });

  it("renders the input with a no-match line when nothing matches", () => {
    const text = renderCoordinatorInput(input());
    expect(text).toContain("# New alert");
    expect(text).toContain("none — no running hunt is seeded on this entity");
  });
});
