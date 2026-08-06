import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { buildDigest } from "../ai/digest.js";
import { Ledger, newId } from "../ai/ledger.js";
import { HuntController, InvalidDecision, startHunt, validateDecision } from "../ai/loop.js";
import { ScriptedDecisionProvider, ScriptedWorkerDispatcher } from "../ai/scripted.js";
import { buildSpec, parseSpec, SpecError } from "../ai/spec.js";
import type { Decision } from "../ai/types.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hunt-"));
});

function ledgerFor(hypotheses = ["a credential is used from new infrastructure"]): Ledger {
  const spec = buildSpec({ prompt: hypotheses[0] });
  return startHunt({ ...spec, hypotheses }, join(dir, "run.jsonl"));
}

const INVESTIGATE: Decision = {
  action: "INVESTIGATE",
  rationale: "open a baseline query",
  query_intent: "baseline",
};
const CONCLUDE: Decision = { action: "CONCLUDE", rationale: "done" };

describe("ledger", () => {
  it("folds appends into a projection and never rewrites the file", () => {
    const ledger = ledgerFor();
    const before = readFileSync(ledger.path, "utf8");
    ledger.append({
      kind: "question",
      question: { question_id: newId("q", 4), question: "which host?", status: "open", spawning_evidence_id: null },
    });
    const after = readFileSync(ledger.path, "utf8");

    expect(after.startsWith(before)).toBe(true);
    expect(ledger.projection.questions.size).toBe(1);
    expect(Ledger.open(ledger.path).projection).toEqual(ledger.projection);
  });

  it("applies patches to the projection", () => {
    const ledger = ledgerFor();
    const id = [...ledger.projection.hypotheses.keys()][0]!;
    ledger.patch("hypothesis", id, { status: "parked" });
    expect(ledger.projection.hypotheses.get(id)!.status).toBe("parked");
  });
});

describe("controller", () => {
  it("reaches a terminal state on CONCLUDE and snapshots every iteration", async () => {
    const ledger = ledgerFor();
    const controller = new HuntController(ledger, new ScriptedDecisionProvider([CONCLUDE], 0.25));
    const result = await controller.advanceIteration();

    expect(result.hunt_status).toBe("terminal");
    expect(result.hunt_outcome).toBe("completed");
    expect(ledger.projection.decisions).toHaveLength(1);
    expect(ledger.projection.decisions[0]!.digest_presented.iteration).toBe(1);
    expect(ledger.projection.hunt.cost_usd).toBe(0.25);
  });

  it("coerces unresolved hypotheses to inconclusive, never disproven", async () => {
    const ledger = ledgerFor(["h one", "h two"]);
    await new HuntController(ledger, new ScriptedDecisionProvider([CONCLUDE])).advanceIteration();
    const statuses = [...ledger.projection.hypotheses.values()].map((h) => h.status);
    expect(statuses).toEqual(["inconclusive", "inconclusive"]);
  });

  it("never downgrades an outcome already on the record", () => {
    const ledger = ledgerFor();
    const controller = new HuntController(ledger, new ScriptedDecisionProvider([]));
    controller.terminate("aborted");
    controller.terminate("completed");
    expect(ledger.projection.hunt.outcome).toBe("aborted");
  });

  it("records a worker failure as evidence and keeps going", async () => {
    const ledger = ledgerFor();
    const controller = new HuntController(
      ledger,
      new ScriptedDecisionProvider([INVESTIGATE, CONCLUDE]),
      new ScriptedWorkerDispatcher([], ["threat_hunter"]),
    );
    const first = await controller.advanceIteration();

    expect(first.hunt_status).toBe("active");
    const evidence = [...ledger.projection.evidence.values()];
    expect(evidence).toHaveLength(1);
    expect(evidence[0]!.provenance).toBe("tool_failure");
    expect([...ledger.projection.dispatches.values()][0]!.status).toBe("failed");

    const second = await controller.advanceIteration();
    expect(second.hunt_status).toBe("terminal");
  });

  it("terminates when the iteration budget runs out", async () => {
    const spec = buildSpec({ prompt: "h" });
    const ledger = startHunt(
      { ...spec, budgets: { max_iterations: 1, max_cost_usd: 10 } },
      join(dir, "run.jsonl"),
    );
    const result = await new HuntController(ledger, new ScriptedDecisionProvider([INVESTIGATE])).advanceIteration();
    expect(result.hunt_outcome).toBe("budget_terminated");
    expect(result.note).toBe("budget exhausted");
  });

  it("rejects an uncited ABANDON but accepts a cited one", () => {
    const ledger = ledgerFor();
    expect(() => validateDecision({ action: "ABANDON", rationale: "no" }, ledger.projection)).toThrow(InvalidDecision);
    expect(() =>
      validateDecision({ action: "ABANDON", rationale: "no", evidence_citations: ["ev-nope"] }, ledger.projection),
    ).toThrow(/unknown evidence/);
  });
});

describe("digest", () => {
  it("carries a weakens section and flags one-sidedness", () => {
    const ledger = ledgerFor();
    const hypothesisId = [...ledger.projection.hypotheses.keys()][0]!;
    const evidenceId = newId("ev");
    ledger.append({
      kind: "evidence",
      evidence: {
        evidence_id: evidenceId,
        dispatch_id: null,
        iteration: 1,
        source_system: "duckdb",
        summary: "the identity has logged in from this ASN before",
        payload: {},
        salience: "routine",
        why_notable: "",
        provenance: "worker",
        attacker_influenceable: false,
        instruction_like: false,
        captured_at: new Date().toISOString(),
      },
    });

    const oneSided = buildDigest(ledger.projection, 1);
    expect(oneSided.weakens[hypothesisId]).toEqual([]);
    expect(oneSided.notes.join(" ")).toMatch(/One-sided support/);

    ledger.append({ kind: "link", link: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation: "weakens" } });
    const balanced = buildDigest(ledger.projection, 1);
    expect(balanced.weakens[hypothesisId]).toHaveLength(1);
    // contradicting an active hypothesis promotes salience, and code may only raise
    expect(balanced.weakens[hypothesisId]![0]!.salience).toBe("notable");
  });
});

describe("spec", () => {
  it("rejects an unknown front-matter key", () => {
    expect(() => parseSpec("---\nname: x\nbudget: 5\n---\n")).toThrow(/unknown key/);
  });

  it("layers a prompt onto a spec file rather than replacing it", () => {
    const spec = parseSpec("---\nname: base\nhypotheses:\n  - one\n---\nnarrative here");
    expect(spec.hypotheses).toEqual(["one"]);
    expect(spec.narrative).toBe("narrative here");
  });

  it("refuses a hunt with nothing to test", () => {
    expect(() => buildSpec({ entity: "10.0.0.1" })).toThrow(SpecError);
  });

  it("types a seed entity", () => {
    expect(buildSpec({ prompt: "q", entity: "10.0.0.1" }).scope["entity"]).toEqual({ type: "ip", value: "10.0.0.1" });
    expect(buildSpec({ prompt: "q", entity: "host:web-01" }).scope["entity"]).toEqual({ type: "host", value: "web-01" });
  });
});
