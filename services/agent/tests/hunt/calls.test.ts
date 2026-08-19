// The execution log: a summary is the worker's account of the data, a call is the
// query that produced it. Journaled empty on every dispatch until #0017, which made
// the "reproducible query set" unreachable rather than deferred.
import { describe, expect, it } from "vitest";
import type { Attempt } from "../../core/loop.js";
import { wrap, scannerFor } from "../../core/security.js";
import { callsOf, charged } from "../../workflows/hunt/adapters.js";
import { renderCaseFile } from "../../workflows/hunt/report.js";
import { newLedger, relate } from "../support/hunt.js";
import { newId } from "../../workflows/hunt/ids.js";

const attempt = (tool: string, args: string, rows: readonly unknown[]): Attempt => {
  const result = { ok: true as const, rows, rowCount: rows.length, capped: false, sourceSystem: "duckdb" };
  return { tool, args, result, wrapped: wrap(tool, result, scannerFor([]), 8_000) };
};

describe("the calls a dispatch ran", () => {
  it("journals the tool and the arguments an analyst would re-run", () => {
    const [call] = callsOf([attempt("telemetry_search", '{"query":"index=botsv3 dest_ip=45.77.53.176"}', [{ n: 1 }])]);

    expect(call!.tool).toBe("telemetry_search");
    expect(call!.arguments).toContain("index=botsv3");
    expect(call!.result).toContain("1 row(s) from duckdb");
  });

  it("shares one budget across the calls, so a large answer cannot crowd out the rest", () => {
    const big = Array.from({ length: 400 }, (_, n) => ({ n, filler: "x".repeat(200) }));
    const calls = callsOf([attempt("a", "{}", big), attempt("b", "{}", big), attempt("c", "{}", [{ n: 1 }])]);

    expect(calls).toHaveLength(3);
    expect(calls.every((call) => call.result.length <= 16_000 / 3 + 64)).toBe(true);
    // Truncation is marked, never silent -- output that just stops reads as short.
    expect(calls[0]!.result).toContain("[truncated");
    expect(calls[2]!.tool).toBe("c");
  });

  it("has nothing to say about a worker that ran no tools", () => {
    expect(callsOf([])).toEqual([]);
  });
});

describe("the case file a responder is handed", () => {
  it("carries the query behind the claim, not only the claim", async () => {
    const { ledger, hypothesisIds } = await newLedger();
    const hypothesisId = hypothesisIds[0]!;
    const dispatchId = newId("dsp");
    const evidenceId = newId("ev");

    ledger.append({
      kind: "dispatch",
      payload: {
        dispatch_id: dispatchId,
        iteration: 1,
        agent_id: "network_analyst",
        status: "complete",
        query_intent: "characterise the beaconing interval",
        target_hypothesis_id: hypothesisId,
        question_id: null,
        failure_reason: null,
        cost_usd: 0.2,
        calls: callsOf([attempt("telemetry_search", '{"query":"stats count by dest_ip"}', [{ dest_ip: "45.77.53.176" }])]),
      },
    } as never);
    ledger.append({
      kind: "evidence",
      payload: {
        evidence_id: evidenceId,
        dispatch_id: dispatchId,
        iteration: 1,
        source_system: "duckdb",
        summary: "412 connections every 300s +/- 4s",
        payload: { interval_s: 300 },
        salience: "anomalous",
        why_notable: "low-jitter periodicity",
        provenance: "worker",
        attacker_influenceable: false,
        instruction_like: false,
        entities: [],
        captured_at: new Date().toISOString(),
      },
    } as never);
    relate(ledger, evidenceId, hypothesisId, "supports");

    const rendered = renderCaseFile(ledger.projection, {
      case_id: "case-1",
      hypothesis_id: hypothesisId,
      iteration: 1,
      rationale: "proven and active",
      created_at: new Date().toISOString(),
    });

    expect(rendered).toContain("Queries behind it:");
    expect(rendered).toContain("stats count by dest_ip");
  });
});

// A call that throws has still been paid for. The harness journals the spend
// either way, but the controller reads what a failure cost off the error, and a
// provider error carries no cost field -- so the money landed on the ledger and
// never reached the budget or the report. One run journaled $0.7889 and reported
// $0.1110: nine worker calls died on a dropped upstream stream, every one paid
// for, none counted. A ceiling that cannot see failed work does not hold.
describe("what a failed call cost", () => {
  const harnessSpending = (spent: number) =>
    ({ budget: { spent: { cost_usd: spent } } }) as unknown as Parameters<typeof charged>[0];

  it("attaches the spend to an error that carries none", async () => {
    const failing = Promise.reject(new Error("Error reading stream: connection timed out"));

    const error = await charged(harnessSpending(0.6779), 0, failing).catch((e) => e);

    expect((error as { cost_usd?: number }).cost_usd).toBeCloseTo(0.6779, 6);
  });

  // Only what this call spent, not the pool's running total: the difference is
  // every earlier call in the run, and charging those again would compound.
  it("charges the delta since the call began, not the whole pool", async () => {
    const error = await charged(harnessSpending(1.0), 0.9, Promise.reject(new Error("dead"))).catch((e) => e);

    expect((error as { cost_usd?: number }).cost_usd).toBeCloseTo(0.1, 6);
  });

  // BudgetRefused already carries its own, and it is the authority on the call it
  // refused; overwriting it would report a refusal as though it had been paid for.
  it("leaves a cost the error already states", async () => {
    const stated = Object.assign(new Error("refused"), { cost_usd: 0.02 });

    const error = await charged(harnessSpending(5), 0, Promise.reject(stated)).catch((e) => e);

    expect((error as { cost_usd?: number }).cost_usd).toBe(0.02);
  });

  it("adds nothing to a call that failed before spending", async () => {
    const error = await charged(harnessSpending(0.5), 0.5, Promise.reject(new Error("refused early"))).catch((e) => e);

    expect((error as { cost_usd?: number }).cost_usd).toBeUndefined();
  });

  it("hands a successful call straight back", async () => {
    expect(await charged(harnessSpending(1), 0, Promise.resolve("answered"))).toBe("answered");
  });
});
