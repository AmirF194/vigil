import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  AUTO_ACTOR,
  DEFAULT_CHECKPOINTS,
  pendingCheckpoints,
  resolutionOf,
  type Checkpoints,
} from "../ai/checkpoints.js";
import { buildDigest, scoredFrontier, suppressedEntities } from "../ai/digest.js";
import { steer } from "../ai/inbox.js";
import { Ledger, newId, type LedgerEvent } from "../ai/ledger.js";
import { HuntController, HuntParked, startHunt, validateDecision } from "../ai/loop.js";
import type { Enricher, WorkerDispatcher } from "../ai/ports.js";
import { caseFilePath, reportPath, type HuntReport } from "../ai/report.js";
import {
  ScriptedDecisionProvider,
  ScriptedDisconfirmationCritic,
  ScriptedWorkerDispatcher,
  type ScriptedDecision,
} from "../ai/scripted.js";
import { buildSpec, DEFAULT_VERDICTS } from "../ai/spec.js";
import { evidenceStrength, openGaps } from "../ai/strength.js";
import type { Decision, DispatchRequest, DispatchResult, Entity, LinkRelation } from "../ai/types.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "hunt-"));
});

// Every test states the policy it is about: the point of the class is that the
// same machinery either asks or answers itself, and which one is config.
function newLedger(
  checkpoints: Partial<Checkpoints> = {},
  overrides: { hypotheses?: string[]; scope?: Record<string, unknown> } = {},
): { ledger: Ledger; hypothesisIds: string[] } {
  const hypotheses = overrides.hypotheses ?? ["a credential is used from new infrastructure"];
  const spec = buildSpec({ prompt: hypotheses[0] });
  const ledger = startHunt(
    {
      ...spec,
      hypotheses,
      scope: overrides.scope ?? spec.scope,
      checkpoints: { ...DEFAULT_CHECKPOINTS, ...checkpoints },
    },
    join(dir, `${newId("run")}.jsonl`),
  );
  return { ledger, hypothesisIds: [...ledger.projection.hypotheses.keys()] };
}

function controllerFor(
  ledger: Ledger,
  decisions: ScriptedDecision[],
  options: { critic?: ScriptedDisconfirmationCritic; dispatcher?: WorkerDispatcher; enricher?: Enricher } = {},
): HuntController {
  return new HuntController(
    ledger,
    new ScriptedDecisionProvider(decisions),
    options.dispatcher,
    options.dispatcher === undefined ? undefined : { mode: "parallel", fan_out_over: "questions", max_workers: 3 },
    undefined,
    options.enricher,
    options.critic,
  );
}

function evidenceOn(ledger: Ledger, hypothesisId: string, source: string, relation: LinkRelation = "supports"): string {
  const evidenceId = newId("ev");
  ledger.append({
    kind: "evidence",
    evidence: {
      evidence_id: evidenceId,
      dispatch_id: null,
      iteration: 1,
      source_system: source,
      summary: `${source} saw the identity authenticate from 45.77.53.176`,
      payload: { rows: 3, src_ip: "45.77.53.176" },
      salience: "notable",
      why_notable: "first use of this ASN by the identity",
      provenance: "worker",
      attacker_influenceable: false,
      instruction_like: false,
      entities: [{ type: "ip", value: "45.77.53.176" }],
      captured_at: new Date().toISOString(),
    },
  });
  ledger.append({ kind: "link", link: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation } });
  return evidenceId;
}

// Enough support to clear every verdict predicate, so what a test is measuring
// is the checkpoint rather than the strength computation.
function provable(ledger: Ledger, hypothesisId: string): string[] {
  return [evidenceOn(ledger, hypothesisId, "cloudtrail"), evidenceOn(ledger, hypothesisId, "duckdb")];
}

function validate(hypothesisId: string, citations: string[]): Decision {
  return {
    action: "VALIDATE",
    rationale: "the support looks solid enough to put up for a verdict",
    target_hypothesis_id: hypothesisId,
    evidence_citations: citations,
  };
}

function question(ledger: Ledger, text: string, entityKey: string | null = null, spawnedIteration = 1): string {
  const questionId = newId("q", 4);
  ledger.append({
    kind: "question",
    question: {
      question_id: questionId,
      question: text,
      status: "open",
      entity_key: entityKey,
      spawning_evidence_id: null,
      spawning_dispatch_id: null,
      spawned_iteration: spawnedIteration,
      hypothesis_id: null,
    },
  });
  return questionId;
}

function events(ledger: Ledger): LedgerEvent[] {
  return readFileSync(ledger.path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as LedgerEvent);
}

function finalized(ledger: Ledger): HuntReport[] {
  return events(ledger)
    .filter((event): event is LedgerEvent & { kind: "finalize"; report: HuntReport } => event.kind === "finalize")
    .map((event) => event.report);
}

const CONCLUDE: Decision = { action: "CONCLUDE", rationale: "nothing further to run" };
const INVESTIGATE: Decision = { action: "INVESTIGATE", rationale: "look", query_intent: "baseline" };

describe("the ledger is the authority, the CLI is delivery", () => {
  it("journals an auto resolution rather than silently skipping the checkpoint", async () => {
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "auto" });
    const citations = provable(ledger, hypothesisIds[0]!);

    await controllerFor(ledger, [validate(hypothesisIds[0]!, citations)], {
      critic: new ScriptedDisconfirmationCritic(true),
    }).advanceIteration();

    // The verdict landed exactly as it does with no checkpoint machinery at all…
    expect(ledger.projection.hypotheses.get(hypothesisIds[0]!)!.status).toBe("proven");

    // …and the ledger says who approved it, which happens to be nobody.
    const [checkpoint] = [...ledger.projection.checkpoints.values()].filter((entry) => entry.class === "verdict_review");
    const resolution = resolutionOf(ledger.projection, checkpoint!.checkpoint_id)!;
    expect(resolution.verdict).toBe("approved");
    expect(resolution.actor).toBe(AUTO_ACTOR);
    expect(resolution.directive_id).toBeNull();
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(0);
  });

  it("keeps a pending checkpoint out of the operator directive stream", async () => {
    // Nothing the controller journals for itself may look like operator input:
    // the drain counts operator directives to know what it has already taken.
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "ask" });
    const citations = provable(ledger, hypothesisIds[0]!);

    await controllerFor(ledger, [validate(hypothesisIds[0]!, citations)], {
      critic: new ScriptedDisconfirmationCritic(true),
    }).advanceIteration();

    expect(ledger.projection.directives.filter((directive) => directive.origin !== "controller")).toHaveLength(0);
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(1);
  });
});

describe("verdict review", () => {
  async function parkedOnVerdict(): Promise<{ ledger: Ledger; hypothesisId: string; checkpointId: string }> {
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "ask" });
    const citations = provable(ledger, hypothesisIds[0]!);
    const result = await controllerFor(ledger, [validate(hypothesisIds[0]!, citations)], {
      critic: new ScriptedDisconfirmationCritic(true),
    }).advanceIteration();

    expect(result.hunt_status).toBe("parked");
    return {
      ledger,
      hypothesisId: hypothesisIds[0]!,
      checkpointId: pendingCheckpoints(ledger.projection)[0]!.checkpoint_id,
    };
  }

  it("parks instead of proving, and refuses to step until it is answered", async () => {
    const { ledger, hypothesisId } = await parkedOnVerdict();

    expect(ledger.projection.hypotheses.get(hypothesisId)!.status).toBe("active");
    expect(ledger.projection.hunt.outcome).toBeNull();

    await expect(controllerFor(ledger, [CONCLUDE]).advanceIteration()).rejects.toThrow(HuntParked);
    await expect(controllerFor(ledger, [CONCLUDE]).advanceIteration()).rejects.toThrow(/approve .*reject/s);
  });

  it("survives process death: a new controller from the JSONL alone still shows it pending", async () => {
    const { ledger, checkpointId } = await parkedOnVerdict();

    // Nothing of this process carries over — the file is the whole state.
    const reopened = Ledger.open(ledger.path);
    const pending = pendingCheckpoints(reopened.projection);
    expect(pending.map((checkpoint) => checkpoint.checkpoint_id)).toEqual([checkpointId]);
    expect(reopened.projection.hunt.status).toBe("parked");
    expect(reopened.projection.hunt.parked_reason).toContain(checkpointId);
  });

  it("applies the patch VALIDATE computed, with the strength snapshot from then", async () => {
    const { ledger, hypothesisId, checkpointId } = await parkedOnVerdict();
    const atValidateTime = (
      [...ledger.projection.checkpoints.values()][1]!.payload["evidence_strength"] as Record<string, unknown>
    );

    steer(ledger.path, "approve", "reviewed the payloads, this holds", { checkpoint_id: checkpointId });
    const resumed = Ledger.open(ledger.path);
    await controllerFor(resumed, [INVESTIGATE]).advanceIteration();

    // The snapshot is the one the reviewer was shown, never one recomputed on
    // approval: approving is the same verdict delivered late, not a second and
    // better-informed one.
    const hypothesis = resumed.projection.hypotheses.get(hypothesisId)!;
    expect(hypothesis.status).toBe("proven");
    expect(hypothesis.evidence_strength).toEqual(atValidateTime);
    expect(hypothesis.evidence_strength!.corroborating_sources).toBe(2);
  });

  it("refuses to land a verdict the argue-the-null pass no longer covers", async () => {
    const { ledger, hypothesisId, checkpointId } = await parkedOnVerdict();

    // Support the critic never argued against arrives while the review waits.
    // The stored patch still says the hypothesis survived disconfirmation, and
    // by the time it would land that sentence is no longer true.
    evidenceOn(ledger, hypothesisId, "okta");
    expect(evidenceStrength(ledger.projection, hypothesisId).survived_disconfirmation).toBe(false);

    steer(ledger.path, "approve", "reviewed the payloads, this holds", { checkpoint_id: checkpointId });
    const resumed = Ledger.open(ledger.path);
    await controllerFor(resumed, [INVESTIGATE]).advanceIteration();

    expect(resumed.projection.hypotheses.get(hypothesisId)!.status).toBe("active");
    expect(resumed.projection.directives.map((directive) => directive.text).join(" ")).toMatch(
      /no longer carries it.*VALIDATE it again/s,
    );
  });

  it("closes inconclusive when the operator declares a gap and then approves", async () => {
    const { ledger, hypothesisId, checkpointId } = await parkedOnVerdict();

    // The honest sequence this guards: a reviewer remembers the hunt is blind
    // somewhere, says so, and approves in the same breath. The gap they just
    // declared must not be the one thing the approval ignores.
    for (const blind of ["no EDR on that subnet", "no CloudTrail before August", "netflow sampled at 1:100"]) {
      steer(ledger.path, "gap", blind, { hypothesis_id: hypothesisId });
    }
    steer(ledger.path, "approve", "looks right to me", { checkpoint_id: checkpointId });

    const resumed = Ledger.open(ledger.path);
    await controllerFor(resumed, [INVESTIGATE]).advanceIteration();

    const hypothesis = resumed.projection.hypotheses.get(hypothesisId)!;
    expect(hypothesis.status).toBe("inconclusive");
    expect(hypothesis.resolution_reason).toMatch(/gap-locked before the approved verdict landed/);
    // The numbers on the record are the ones that closed it, not the ones the
    // reviewer was shown — a verdict nobody can re-read is not auditable.
    expect(hypothesis.evidence_strength!.open_gaps).toBe(3);
  });

  it("leaves the hypothesis active on a rejection, with the reason in the next digest", async () => {
    const { ledger, hypothesisId, checkpointId } = await parkedOnVerdict();
    steer(ledger.path, "reject", "the second source is the same collector under another name", {
      checkpoint_id: checkpointId,
    });

    const provider = new ScriptedDecisionProvider([INVESTIGATE]);
    await new HuntController(ledger, provider).advanceIteration();

    expect(ledger.projection.hypotheses.get(hypothesisId)!.status).toBe("active");
    expect(ledger.projection.hunt.status).toBe("active");
    expect(provider.seenDigests[0]!.directives.join(" ")).toMatch(/same collector under another name/);
  });

  it("answers a checkpoint by id, so a stale or duplicate answer changes nothing", async () => {
    const { ledger, hypothesisId, checkpointId } = await parkedOnVerdict();
    steer(ledger.path, "reject", "not yet", { checkpoint_id: checkpointId });
    steer(ledger.path, "approve", "changed my mind", { checkpoint_id: checkpointId });

    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    // The first answer stands, and the second is on the record as ignored.
    expect(ledger.projection.hypotheses.get(hypothesisId)!.status).toBe("active");
    expect(resolutionOf(ledger.projection, checkpointId)!.verdict).toBe("rejected");
    expect(ledger.projection.directives.map((directive) => directive.text).join(" ")).toMatch(/first answer stands/);
  });

  it("reviews the conclusion too, and terminates through the one funnel on approval", async () => {
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "ask" });
    ledger.patch("hypothesis", hypothesisIds[0]!, { status: "parked", resolution_reason: "dropped" });

    const parked = await controllerFor(ledger, [CONCLUDE]).advanceIteration();
    expect(parked.hunt_status).toBe("parked");
    expect(ledger.projection.hunt.outcome).toBeNull();

    const checkpointId = pendingCheckpoints(ledger.projection)[0]!.checkpoint_id;
    steer(ledger.path, "approve", "agreed, we are done", { checkpoint_id: checkpointId });
    const result = await controllerFor(ledger, []).advanceIteration();

    expect(result.hunt_outcome).toBe("completed");
    // Finalize sits on terminate(), so an approval that ends a hunt still
    // produces the deliverable.
    expect(finalized(ledger)).toHaveLength(1);
    expect(existsSync(reportPath(ledger.path))).toBe(true);
  });

  it("keeps the hunt running when the conclusion is refused", async () => {
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "ask" });
    ledger.patch("hypothesis", hypothesisIds[0]!, { status: "parked", resolution_reason: "dropped" });
    await controllerFor(ledger, [CONCLUDE]).advanceIteration();

    const checkpointId = pendingCheckpoints(ledger.projection)[0]!.checkpoint_id;
    steer(ledger.path, "reject", "check the second host first", { checkpoint_id: checkpointId });
    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect(ledger.projection.hunt.outcome).toBeNull();
    expect(finalized(ledger)).toHaveLength(0);
  });
});

describe("the start approval", () => {
  it("holds the hunt at pending_approval until it is journaled", async () => {
    const { ledger } = newLedger({ hypothesis_approval: "ask" });

    expect(ledger.projection.hunt.status).toBe("pending_approval");
    expect(pendingCheckpoints(ledger.projection)[0]!.class).toBe("hypothesis_approval");
    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(HuntParked);

    const checkpointId = pendingCheckpoints(ledger.projection)[0]!.checkpoint_id;
    steer(ledger.path, "approve", "reviewed the hypotheses", { checkpoint_id: checkpointId });
    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect(resolutionOf(ledger.projection, checkpointId)!.actor).not.toBe(AUTO_ACTOR);
  });

  it("aborts a rejected start through terminate(), so it still finalizes", async () => {
    const { ledger, hypothesisIds } = newLedger({ hypothesis_approval: "ask" });
    const checkpointId = pendingCheckpoints(ledger.projection)[0]!.checkpoint_id;
    steer(ledger.path, "reject", "wrong scope, start again", { checkpoint_id: checkpointId });

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(result.hunt_outcome).toBe("aborted");
    expect(ledger.projection.hunt.termination_reason).toMatch(/rejected the hypotheses/);
    // Never disproven: nobody looked.
    expect(ledger.projection.hypotheses.get(hypothesisIds[0]!)!.status).toBe("inconclusive");
    expect(finalized(ledger)).toHaveLength(1);
    expect(readFileSync(reportPath(ledger.path), "utf8")).toMatch(/\*\*Outcome:\*\* aborted/);
  });

  it("starts active under the auto policy, with the approval on the record", () => {
    const { ledger } = newLedger({ hypothesis_approval: "auto" });

    expect(ledger.projection.hunt.status).toBe("active");
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(0);
    expect(ledger.projection.resolutions[0]!.actor).toBe(AUTO_ACTOR);
    // The default, so a headless run has nothing pending and no TTY to prompt on.
    expect(DEFAULT_CHECKPOINTS.hypothesis_approval).toBe("auto");
  });
});

describe("the soft directive set", () => {
  it("binds the Hunt Lead rather than only the digest", async () => {
    const { ledger, hypothesisIds } = newLedger();
    evidenceOn(ledger, hypothesisIds[0]!, "duckdb");
    steer(ledger.path, "benign", "our own scanner", { entity_key: "ip:45.77.53.176" });
    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    // Dropping it from pivot candidates only makes the lead less likely to name
    // it. An authorization the lead can decline to notice is a suggestion.
    const citations = [...ledger.projection.evidence.keys()];
    for (const action of ["INVESTIGATE", "DEEPEN", "PIVOT"] as const) {
      expect(() =>
        validateDecision(
          { action, rationale: "chase it anyway", target_entity: "ip:45.77.53.176", evidence_citations: citations },
          ledger.projection,
        ),
      ).toThrow(/known-benign/);
    }

    // ABANDON is the exception: closing work on a suppressed entity is the
    // point of suppressing it.
    expect(() =>
      validateDecision(
        {
          action: "ABANDON",
          rationale: "the operator cleared it",
          target_entity: "ip:45.77.53.176",
          evidence_citations: citations,
        },
        ledger.projection,
      ),
    ).not.toThrow();
  });

  it("suppresses an entity without touching a single record, and lets a revoke lift it", async () => {
    const { ledger, hypothesisIds } = newLedger();
    const evidenceId = evidenceOn(ledger, hypothesisIds[0]!, "duckdb");
    const before = ledger.projection.evidence.get(evidenceId)!;

    steer(ledger.path, "benign", "our own scanner", { entity_key: "ip:45.77.53.176" });
    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect([...suppressedEntities(ledger.projection).keys()]).toEqual(["ip:45.77.53.176"]);
    // The evidence is exactly what it was: a suppression is an authorization,
    // not a deletion.
    expect(ledger.projection.evidence.get(evidenceId)).toEqual(before);

    const digest = buildDigest(ledger.projection, 2);
    expect(digest.entities.find((entity) => entity.value === "45.77.53.176")!.suppressed).toBe(true);
    expect(digest.notes.join(" ")).toMatch(/known-benign/);

    steer(ledger.path, "benign", "put it back in play", { entity_key: "ip:45.77.53.176", revoke: true });
    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(suppressedEntities(ledger.projection).size).toBe(0);
    expect(buildDigest(ledger.projection, 3).entities.find((entity) => entity.value === "45.77.53.176")!.suppressed)
      .toBeUndefined();
  });

  it("keeps a suppressed entity out of enrichment and out of the pivot candidates", async () => {
    const { ledger } = newLedger();
    const enriched: string[] = [];
    const enricher: Enricher = async (entity: Entity) => {
      enriched.push(`${entity.type}:${entity.value}`);
      return [];
    };

    steer(ledger.path, "benign", "our own scanner", { entity_key: "ip:45.77.53.176" });
    await controllerFor(ledger, [INVESTIGATE], {
      enricher,
      dispatcher: new ScriptedWorkerDispatcher([
        {
          source_system: "duckdb",
          summary: "10.0.0.5 talked to 45.77.53.176",
          payload: { src_ip: "10.0.0.5", dest_ip: "45.77.53.176" },
          salience: "routine",
          why_notable: "",
          provenance: "worker",
          attacker_influenceable: false,
          instruction_like: false,
        },
      ]),
    }).advanceIteration();

    expect(enriched).toContain("ip:10.0.0.5");
    expect(enriched).not.toContain("ip:45.77.53.176");

    // And it is not offered as somewhere to pivot to, having been cleared once.
    const digest = buildDigest(ledger.projection, 2);
    expect(digest.pivot_candidates.map((entity) => entity.value)).not.toContain("45.77.53.176");
  });

  it("counts an operator-declared gap like a tool failure, up to gap-lock", async () => {
    const { ledger, hypothesisIds } = newLedger();
    const hypothesisId = hypothesisIds[0]!;
    const citations = provable(ledger, hypothesisId);

    for (const text of ["no EDR on the 10.30.0.0/16 subnet", "no DNS logging before 03:00", "no proxy logs at all"]) {
      steer(ledger.path, "gap", text, { hypothesis_id: hypothesisId });
    }
    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(openGaps(ledger.projection, hypothesisId)).toBe(DEFAULT_VERDICTS.gap_lock_threshold);

    // Enough blindness that the verdict closes inconclusive: the hunt could not
    // look, which is never the same as having cleared it.
    const result = await controllerFor(ledger, [validate(hypothesisId, citations)], {
      critic: new ScriptedDisconfirmationCritic(true),
    }).advanceIteration();

    expect(ledger.projection.hypotheses.get(hypothesisId)!.status).toBe("inconclusive");
    expect(result.note).toMatch(/gap-locked/);
  });

  it("pins a boosted question to the top of the frontier", async () => {
    const { ledger } = newLedger();
    question(ledger, "the obvious next thread", "ip:10.0.0.1");
    // Stale enough to rank below it on recency, so the pin is doing the work
    // rather than a tie-break.
    const buried = question(ledger, "a thread nobody ranked", null, -5);

    expect(scoredFrontier(ledger.projection, 1)[0]!.question.question_id).not.toBe(buried);

    steer(ledger.path, "boost", "look at this one next", { question_id: buried });
    await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    const [top] = scoredFrontier(ledger.projection, 2);
    expect(top!.question.question_id).toBe(buried);
    expect(top!.boosted).toBe(true);
    // Pinned, not rescored: the floor termination measures against still means
    // what it meant.
    expect(top!.score).toBeLessThan(scoredFrontier(ledger.projection, 2)[1]!.score);
  });

  it("records a premise correction as the note it already is", async () => {
    const { ledger } = newLedger();
    steer(ledger.path, "note", "the 03:00 spike is our backup window, not exfil");

    const provider = new ScriptedDecisionProvider([INVESTIGATE]);
    await new HuntController(ledger, provider).advanceIteration();

    expect(provider.seenDigests[0]!.directives.join(" ")).toMatch(/backup window/);
  });
});

describe("a hard abort preempts the work in flight", () => {
  // Queues the halt while the first worker is running, which is what an
  // operator hitting abort mid-iteration actually looks like.
  class AbortingDispatcher implements WorkerDispatcher {
    readonly seen: string[] = [];
    constructor(private readonly ledgerPath: string) {}

    async dispatch(request: DispatchRequest): Promise<DispatchResult> {
      this.seen.push(request.focus);
      if (this.seen.length === 1) steer(this.ledgerPath, "abort", "operator halted the hunt");
      return {
        dispatch_id: request.dispatch_id,
        evidence: [],
        failed: false,
        failure_reason: "",
        cost_usd: 0,
      };
    }
  }

  it("skips the workers that had not started, journals why, and aborts through terminate()", async () => {
    const { ledger } = newLedger();
    for (const text of ["check 10.0.0.1", "check 10.0.0.2", "check 10.0.0.3"]) question(ledger, text, null);

    const dispatcher = new AbortingDispatcher(ledger.path);
    await controllerFor(ledger, [INVESTIGATE, INVESTIGATE], { dispatcher }).advanceIteration();

    // One worker ran; the other two never did, and the ledger says so rather
    // than leaving two dispatches that look like they chose not to look.
    expect(dispatcher.seen).toHaveLength(1);
    const skipped = [...ledger.projection.dispatches.values()].filter(
      (dispatch) => dispatch.failure_reason?.includes("abort") === true,
    );
    expect(skipped).toHaveLength(2);
    expect(skipped.every((dispatch) => dispatch.status === "failed")).toBe(true);

    // The boundary still owns the ending: aborted, coerced, finalized.
    const result = await controllerFor(ledger, []).advanceIteration();
    expect(result.hunt_outcome).toBe("aborted");
    expect([...ledger.projection.hypotheses.values()].every((h) => h.status === "inconclusive")).toBe(true);
    expect(finalized(ledger)).toHaveLength(1);
  });
});

describe("scope", () => {
  it("refuses a cross-tenant lead outright rather than raising a checkpoint", async () => {
    const { ledger } = newLedger({ scope_extension: "ask" }, { scope: { tenant: "frothly" } });
    steer(ledger.path, "lead", "check tenant:acme for the same key");

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    // No checkpoint: a tenant boundary is not one an operator may waive from
    // inside the hunt, so there is nothing to approve.
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(0);
    expect(result.hunt_status).toBe("active");
    expect([...ledger.projection.questions.values()]).toHaveLength(0);
    expect(ledger.projection.directives.map((directive) => directive.text).join(" ")).toMatch(
      /names tenant acme.*Refused outright/s,
    );
  });

  it("asks before growing past the declared scope, and grows on approval", async () => {
    const { ledger } = newLedger(
      { scope_extension: "ask" },
      { scope: { tenant: "frothly", entities: ["ip:10.0.0.5"] } },
    );
    steer(ledger.path, "lead", "pull on 45.77.53.176 as well");

    await expect(controllerFor(ledger, [INVESTIGATE]).advanceIteration()).rejects.toThrow(HuntParked);
    const checkpoint = pendingCheckpoints(ledger.projection)[0]!;
    expect(checkpoint.class).toBe("scope_extension");
    expect(checkpoint.question).toMatch(/ip:45.77.53.176/);
    expect([...ledger.projection.questions.values()]).toHaveLength(0);

    steer(ledger.path, "approve", "yes, it is ours", { checkpoint_id: checkpoint.checkpoint_id });
    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect([...ledger.projection.questions.values()].map((entry) => entry.question)).toEqual([
      "pull on 45.77.53.176 as well",
    ]);
    expect(ledger.projection.hunt.scope["entities"]).toEqual(["ip:10.0.0.5", "ip:45.77.53.176"]);
  });

  it("leaves a hunt that declared no scope free of scope checkpoints", async () => {
    const { ledger } = newLedger({ scope_extension: "ask" });
    steer(ledger.path, "lead", "check 45.77.53.176");

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(0);
    expect([...ledger.projection.questions.values()].map((entry) => entry.question)).toEqual(["check 45.77.53.176"]);
  });

  it("does not treat the seed entity as a boundary", async () => {
    // A hunt seeded with --id is *about* that entity, not fenced to it:
    // following the trail somewhere new is the job, not a scope extension.
    const { ledger } = newLedger({ scope_extension: "ask" }, { scope: { entity: { type: "ip", value: "10.0.0.5" } } });
    steer(ledger.path, "lead", "check what else 45.77.53.176 talked to");

    const result = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();

    expect(result.hunt_status).toBe("active");
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(0);
  });
});

describe("HANDOFF_IR", () => {
  const handoff = (hypothesisId: string | null): Decision => ({
    action: "HANDOFF_IR",
    rationale: "the key is being used right now; IR should rotate it",
    target_hypothesis_id: hypothesisId,
  });

  it("escalates a proven hypothesis, writes the case file, and keeps hunting", async () => {
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "auto" }, { hypotheses: ["h one", "h two"] });
    const citations = provable(ledger, hypothesisIds[0]!);

    const controller = controllerFor(
      ledger,
      [validate(hypothesisIds[0]!, citations), handoff(hypothesisIds[0]!), CONCLUDE],
      { critic: new ScriptedDisconfirmationCritic(true) },
    );
    await controller.advanceIteration();
    const escalated = await controller.advanceIteration();

    const hypothesis = ledger.projection.hypotheses.get(hypothesisIds[0]!)!;
    expect(hypothesis.status).toBe("handed_off");
    expect(hypothesis.spawned_case_id).toBeTruthy();
    expect(escalated.hunt_status).toBe("active");

    const record = ledger.projection.handoffs[0]!;
    expect(record.hypothesis_id).toBe(hypothesisIds[0]!);
    expect(record.case_file).toBe(caseFilePath(ledger.path, hypothesis.spawned_case_id!));

    // What an IR responder is handed: the claim, the numbers, the records, and
    // what the hunt could not see.
    const caseFile = readFileSync(record.case_file, "utf8");
    expect(caseFile).toMatch(/# IR case/);
    expect(caseFile).toMatch(/h one/);
    expect(caseFile).toMatch(/2 corroborating source system\(s\)/);
    expect(caseFile).toContain(citations[0]!);
    expect(caseFile).toMatch(/## What the hunt could not see/);

    // The hunt carries on for its other hypothesis, and a handed-off one is
    // terminal, so it concludes normally once that one resolves.
    ledger.patch("hypothesis", hypothesisIds[1]!, { status: "parked", resolution_reason: "dropped" });
    const ended = await controller.advanceIteration();
    expect(ended.hunt_outcome).toBe("completed");
    expect(readFileSync(reportPath(ledger.path), "utf8")).toMatch(/## Escalated to incident response/);
  });

  it("refuses to escalate a hunch, and burns no re-prompt doing it", async () => {
    const { ledger, hypothesisIds } = newLedger();
    const provider = new ScriptedDecisionProvider([handoff(hypothesisIds[0]!)]);
    const result = await new HuntController(ledger, provider).advanceIteration();

    expect(result.note).toMatch(/HANDOFF_IR refused: .* is active, not proven/);
    expect(ledger.projection.hypotheses.get(hypothesisIds[0]!)!.status).toBe("active");
    expect(ledger.projection.handoffs).toHaveLength(0);

    // Schema- and citation-valid, so it stands on the record and cost exactly
    // one call — the refusal is a controller judgement, not a bad emission.
    expect(provider.seenDigests).toHaveLength(1);
    expect(ledger.projection.decisions).toHaveLength(1);
    expect(ledger.projection.decisions[0]!.rejected_attempts).toBeUndefined();
  });
});

describe("the CHECKPOINT verb", () => {
  const raise: Decision = {
    action: "CHECKPOINT",
    rationale: "the evidence contradicts the premise of this hunt; I need a human",
  };

  it("parks the hunt under the ask policy", async () => {
    const { ledger } = newLedger({ budget_anomaly: "ask" });
    const result = await controllerFor(ledger, [raise]).advanceIteration();

    expect(result.hunt_status).toBe("parked");
    const checkpoint = pendingCheckpoints(ledger.projection)[0]!;
    expect(checkpoint.class).toBe("budget_anomaly");
    expect(checkpoint.question).toMatch(/contradicts the premise/);
    expect(checkpoint.payload["raised_by"]).toBe("hunt_lead");

    steer(ledger.path, "approve", "noted, keep going", { checkpoint_id: checkpoint.checkpoint_id });
    const resumed = await controllerFor(ledger, [INVESTIGATE]).advanceIteration();
    expect(resumed.hunt_status).toBe("active");
  });

  it("journals it and carries on under the auto policy", async () => {
    const { ledger } = newLedger({ budget_anomaly: "auto" });
    const provider = new ScriptedDecisionProvider([raise, INVESTIGATE]);
    const controller = new HuntController(ledger, provider);

    const result = await controller.advanceIteration();
    expect(result.hunt_status).toBe("active");
    expect(pendingCheckpoints(ledger.projection)).toHaveLength(0);
    expect(ledger.projection.resolutions.some((entry) => entry.actor === AUTO_ACTOR)).toBe(true);

    // The concern is not lost: the Hunt Lead is told nobody was asked, so it
    // acts on it rather than raising the same checkpoint every turn.
    await controller.advanceIteration();
    expect(provider.seenDigests[1]!.notes.join(" ") + provider.seenDigests[1]!.directives.join(" ")).toMatch(
      /nobody was asked/,
    );
  });
});

describe("the report carries the supervision", () => {
  it("names every checkpoint, who answered it, and what is still suppressed", async () => {
    const { ledger, hypothesisIds } = newLedger({ verdict_review: "auto" });
    steer(ledger.path, "benign", "our own scanner", { entity_key: "ip:45.77.53.176" });
    ledger.patch("hypothesis", hypothesisIds[0]!, { status: "parked", resolution_reason: "dropped" });
    await controllerFor(ledger, [CONCLUDE]).advanceIteration();

    const report = finalized(ledger)[0]!;
    expect(report.checkpoints.map((checkpoint) => checkpoint.class)).toEqual([
      "hypothesis_approval",
      "verdict_review",
    ]);
    expect(report.checkpoints.every((checkpoint) => checkpoint.resolution?.actor === AUTO_ACTOR)).toBe(true);
    expect(report.suppressions).toEqual([{ entity_key: "ip:45.77.53.176", actor: expect.any(String) }]);

    const rendered = readFileSync(reportPath(ledger.path), "utf8");
    expect(rendered).toMatch(/## Checkpoints/);
    expect(rendered).toMatch(/## Operator suppressions/);
  });
});

// The whole ticket in one walk, driven through the ports with nothing scripted
// but the decisions: start approval, a verdict a human holds, the escalation,
// and an ending the same human signs off.
describe("a supervised hunt end to end", () => {
  it("runs start approval → parked verdict → approve → proven → handoff → conclude", async () => {
    const { ledger, hypothesisIds } = newLedger({ hypothesis_approval: "ask", verdict_review: "ask" });
    const hypothesisId = hypothesisIds[0]!;
    const citations = provable(ledger, hypothesisId);

    const start = pendingCheckpoints(ledger.projection)[0]!;
    steer(ledger.path, "approve", "hypotheses look right", { checkpoint_id: start.checkpoint_id });

    const decisions: ScriptedDecision[] = [
      validate(hypothesisId, citations),
      { action: "HANDOFF_IR", rationale: "escalate", target_hypothesis_id: hypothesisId },
      CONCLUDE,
    ];
    const critic = new ScriptedDisconfirmationCritic(true);

    // Each leg reopens the ledger from disk, because that is what an operator
    // answering a checkpoint hours later actually does.
    let parked = await controllerFor(Ledger.open(ledger.path), decisions, { critic }).advanceIteration();
    expect(parked.hunt_status).toBe("parked");

    const review = pendingCheckpoints(Ledger.open(ledger.path).projection)[0]!;
    expect(review.class).toBe("verdict_review");
    steer(ledger.path, "approve", "checked the payloads", { checkpoint_id: review.checkpoint_id });

    const escalated = await controllerFor(Ledger.open(ledger.path), decisions.slice(1), { critic }).advanceIteration();
    expect(escalated.note).toMatch(/handed off to incident response/);

    const conclusion = await controllerFor(Ledger.open(ledger.path), decisions.slice(2), { critic }).advanceIteration();
    expect(conclusion.hunt_status).toBe("parked");

    const final = pendingCheckpoints(Ledger.open(ledger.path).projection)[0]!;
    steer(ledger.path, "approve", "ship it", { checkpoint_id: final.checkpoint_id });
    const ended = await controllerFor(Ledger.open(ledger.path), [], { critic }).advanceIteration();

    expect(ended.hunt_outcome).toBe("completed");
    const replayed = Ledger.open(ledger.path).projection;
    expect(replayed.hypotheses.get(hypothesisId)!.status).toBe("handed_off");
    expect(replayed.resolutions).toHaveLength(3);
    expect(replayed.resolutions.every((resolution) => resolution.actor !== AUTO_ACTOR)).toBe(true);
    expect(existsSync(replayed.handoffs[0]!.case_file)).toBe(true);
  });
});
