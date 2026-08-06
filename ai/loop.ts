import { join } from "node:path";
import { buildDigest } from "./digest.js";
import { drain } from "./inbox.js";
import { Ledger, newId, type Projection } from "./ledger.js";
import type { DecisionProvider, DisconfirmationCritic, WorkerDispatcher } from "./ports.js";
import {
  DEFAULT_DIGEST,
  DEFAULT_DISPATCH,
  DEFAULT_VERDICTS,
  type DigestPolicy,
  type DispatchPolicy,
  type HuntSpec,
  type Verdicts,
} from "./spec.js";
import {
  CRITIC_SOURCE_SYSTEM,
  evidenceStrength,
  isGap,
  NULL_CHECK_PROVENANCE,
  UNDECLARED_SOURCE,
  unmetPredicates,
} from "./strength.js";
import {
  ACTIONS_REQUIRING_CITATION,
  DECISION_ACTIONS,
  OUTCOME_PRECEDENCE,
  type Decision,
  type DecisionResult,
  type Digest,
  type DispatchRequest,
  type DispatchResult,
  type EvidenceRecord,
  type HuntOutcome,
  type Hypothesis,
  type IterationResult,
  type NullCheckEvidence,
  type NullCheckInput,
  type NullCheckResult,
  type WorkerEvidence,
} from "./types.js";

export const DEFAULT_WORKER_AGENT_ID = "threat_hunter";

// One emission plus two re-asks. Bounded because a Hunt Lead that cannot obey
// the vocabulary will not learn to on the tenth try, and every ask costs money.
export const MAX_DECISION_ATTEMPTS = 3;

export class HuntAlreadyTerminal extends Error {}
export class InvalidDecision extends Error {}

interface FanOutTarget {
  focus: string;
  hypothesisId: string | null;
  questionId: string | null;
}

// Either the critic ran, or it did not and the hunt is owed the reason: silence
// must never read the same as a hypothesis that withstood the argument. The cost
// stands apart from the result because a critic that failed still spent.
interface NullCheckAttempt {
  result: NullCheckResult | null;
  blocked: string;
  cost_usd: number;
  // Exactly what the critic was shown. A later verdict must not rest on an
  // argument that never saw half the evidence now on the record.
  argued: string[];
}

const NO_NULL_CHECK: NullCheckAttempt = { result: null, blocked: "", cost_usd: 0, argued: [] };

// A call that died mid-way still spent. Duck-typed rather than reaching into the
// LLM module, so the controller stays free of it.
function spentBefore(error: unknown): number {
  const cost = (error as { cost_usd?: unknown }).cost_usd;
  return typeof cost === "number" ? cost : 0;
}

// The controller rejects anything outside the closed vocabulary, so the Hunt
// Lead cannot widen its own action space by emitting a new verb.
export function validateDecision(decision: Decision, projection: Projection): void {
  if (!DECISION_ACTIONS.includes(decision.action)) {
    throw new InvalidDecision(`unknown action ${String(decision.action)}`);
  }
  if (!ACTIONS_REQUIRING_CITATION.has(decision.action)) return;

  const citations = decision.evidence_citations ?? [];
  if (citations.length === 0) {
    throw new InvalidDecision(`${decision.action} must cite the evidence it rests on`);
  }
  const unknown = citations.filter((id) => !projection.evidence.has(id));
  if (unknown.length > 0) {
    throw new InvalidDecision(`${decision.action} cites unknown evidence: ${unknown.join(", ")}`);
  }

  // A verdict is about one claim. Without the target there is nothing to argue
  // the null against, so this is as much a violation as an uncited citation.
  if (decision.action === "VALIDATE") {
    const target = decision.target_hypothesis_id;
    if (!target) throw new InvalidDecision("VALIDATE must name the target_hypothesis_id it puts up for a verdict");
    if (!projection.hypotheses.has(target)) {
      throw new InvalidDecision(`VALIDATE names unknown hypothesis: ${target}`);
    }
  }
}

// Raw payloads, not digest summaries: the critic argues against what was
// actually collected rather than against the Hunt Lead's compression of it.
function nullCheckInput(projection: Projection, hypothesis: Hypothesis): NullCheckInput {
  const evidence = projection.links
    .filter((link) => link.hypothesis_id === hypothesis.hypothesis_id)
    .map((link) => ({ relation: link.relation, record: projection.evidence.get(link.evidence_id) }))
    .filter((linked): linked is NullCheckEvidence => linked.record !== undefined);

  return {
    hypothesis_id: hypothesis.hypothesis_id,
    statement: hypothesis.statement,
    narrative: projection.hunt.narrative,
    evidence,
  };
}

// The violation goes back to the Hunt Lead as a digest note, which is where the
// digest already carries controller-side observations, so the re-ask needs no
// change to the DecisionProvider port.
function withRejection(digest: Digest, reason: string): Digest {
  return {
    ...digest,
    notes: [
      ...digest.notes,
      `Your previous emission was rejected: ${reason}. Emit one decision from the closed vocabulary, citing only evidence ids present in this digest.`,
    ],
  };
}

export function startHunt(spec: HuntSpec, dir: string): Ledger {
  const now = new Date().toISOString();
  const huntId = newId("hunt");
  const ledger = Ledger.create(join(dir, `${huntId}.jsonl`), {
    hunt_id: huntId,
    name: spec.name,
    spec,
    status: "active",
    outcome: null,
    iteration: 0,
    cost_usd: 0,
    budgets: spec.budgets,
    scope: spec.scope,
    narrative: spec.narrative,
    created_at: now,
    terminated_at: null,
  });

  for (const [index, statement] of spec.hypotheses.entries()) {
    ledger.append({
      kind: "hypothesis",
      hypothesis: {
        hypothesis_id: newId("h", 4),
        statement,
        status: "active",
        attack_technique: spec.attack_techniques[index] ?? null,
        provenance: "hunt_spec",
        resolution_reason: null,
        evidence_strength: null,
      },
    });
  }
  return ledger;
}

// The ledger is the resume point: the spec came with it, so nothing is re-read
// from disk and a mid-run edit to an arch file cannot change a hunt in flight.
export function resumeHunt(path: string): { ledger: Ledger; spec: HuntSpec } {
  const ledger = Ledger.open(path);
  const { hunt } = ledger.projection;
  if (hunt.status === "terminal") throw new HuntAlreadyTerminal(`${hunt.hunt_id} already ended as ${hunt.outcome}`);
  return { ledger, spec: hunt.spec };
}

export class HuntController {
  constructor(
    private readonly ledger: Ledger,
    private readonly provider: DecisionProvider,
    private readonly dispatcher?: WorkerDispatcher | undefined,
    private readonly policy: DispatchPolicy = DEFAULT_DISPATCH,
    private readonly digestPolicy: DigestPolicy = DEFAULT_DIGEST,
    // Optional: a hunt with no critic runs to a legible end, it just cannot
    // prove anything, and says so rather than transitioning quietly.
    private readonly critic?: DisconfirmationCritic | undefined,
    private readonly verdicts: Verdicts = DEFAULT_VERDICTS,
  ) {}

  async advanceIteration(): Promise<IterationResult> {
    if (this.ledger.projection.hunt.status === "terminal") {
      const hunt = this.ledger.projection.hunt;
      throw new HuntAlreadyTerminal(`${hunt.hunt_id} already ended as ${hunt.outcome}`);
    }

    // Human input is integrated at the boundary, before anything is decided on it.
    if (this.applyDirectives()) return this.aborted();

    const projection = this.ledger.projection;
    const iteration = projection.hunt.iteration + 1;
    const digest = buildDigest(projection, iteration, this.digestPolicy.evidence_window);

    const { presented, result } = await this.decide(digest, projection);

    const dispatchResults = await this.runDispatches(iteration, result.decision);
    const nullCheck = await this.runNullCheck(result.decision);
    return this.write(iteration, presented, result, dispatchResults, nullCheck);
  }

  // A rejection is a correctable mistake, not a lost iteration: the Hunt Lead is
  // told what was wrong and asked again, boundedly. The digest returned is the
  // one that produced the accepted decision, rejection notes included, so
  // digest_presented stays honest by construction.
  private async decide(
    digest: Digest,
    projection: Projection,
  ): Promise<{ presented: Digest; result: DecisionResult }> {
    // Schema-level rejections from inside the provider and controller-level ones
    // from here are the same audit fact, so they merge into one list in order.
    const rejected: string[] = [];
    // A rejected emission was still paid for. Charging only the accepted one
    // would under-report spend by up to the attempt bound, which both hides
    // cost-per-verdict and lets a hunt overrun max_cost_usd.
    let spent = 0;
    let presented = digest;

    for (let attempt = 0; attempt < MAX_DECISION_ATTEMPTS; attempt += 1) {
      const result = await this.provider.decide(presented);
      rejected.push(...(result.rejected_attempts ?? []));
      spent += result.cost_usd;

      try {
        validateDecision(result.decision, projection);
      } catch (error) {
        if (!(error instanceof InvalidDecision)) throw error;
        rejected.push(error.message);
        presented = withRejection(presented, error.message);
        continue;
      }

      // Left absent rather than empty when nothing was rejected, so a clean
      // iteration journals exactly what it did before.
      return {
        presented,
        result: {
          ...result,
          cost_usd: spent,
          ...(rejected.length > 0 ? { rejected_attempts: rejected } : {}),
        },
      };
    }

    // Known simplification for Phase 1: a wholly-failed iteration writes nothing
    // to the ledger and surfaces to the operator, who can retry the still-active
    // hunt. The rejected emissions live in this error rather than in an event,
    // and their cost goes unrecorded with them.
    throw new InvalidDecision(
      `the Hunt Lead emitted nothing valid in ${MAX_DECISION_ATTEMPTS} attempts ` +
        `($${spent.toFixed(4)} spent): ${rejected.join(" | ")}`,
    );
  }

  // Returns true when a directive ended the hunt. A lead becomes a real lead; a
  // note only reaches the digest, so it steers without mutating anything.
  private applyDirectives(): boolean {
    let abort = false;
    for (const directive of drain(this.ledger)) {
      if (directive.kind === "abort") abort = true;
      if (directive.kind !== "lead") continue;
      this.ledger.append({
        kind: "question",
        question: {
          question_id: newId("q", 4),
          question: directive.text,
          status: "open",
          spawning_evidence_id: null,
          // An operator lead names no hypothesis; whatever it turns up links
          // through the worker, not through the lead it arrived on.
          hypothesis_id: null,
        },
      });
    }
    if (abort) this.terminate("aborted");
    return abort;
  }

  private aborted(): IterationResult {
    const hunt = this.ledger.projection.hunt;
    return {
      hunt_id: hunt.hunt_id,
      iteration: hunt.iteration,
      action: "CONCLUDE",
      decision_id: "",
      cost_usd: 0,
      evidence_appended: 0,
      hunt_status: hunt.status,
      hunt_outcome: hunt.outcome,
      note: "aborted by operator directive",
    };
  }

  // A crash between journaling a dispatch and recording its result leaves a lead
  // closed but unanswered. Reaping hands it back and records the gap.
  reap(): number {
    const stale = [...this.ledger.projection.dispatches.values()].filter(
      (dispatch) => dispatch.status === "pending",
    );
    for (const dispatch of stale) {
      this.persistDispatch(dispatch.iteration, {
        dispatch_id: dispatch.dispatch_id,
        evidence: [],
        failed: true,
        failure_reason: "interrupted before the worker returned",
        // Whatever the interrupted worker spent went with it; nothing is known.
        cost_usd: 0,
      });
      if (dispatch.question_id !== null) {
        this.ledger.patch("question", dispatch.question_id, { status: "open" });
      }
    }
    return stale.length;
  }

  // One worker per open lead, capped. Serial is simply max_workers of 1, so
  // there is no second code path for it.
  private fanOut(decision: Decision): FanOutTarget[] {
    const fallback: FanOutTarget[] = [
      { focus: "", hypothesisId: decision.target_hypothesis_id ?? null, questionId: null },
    ];
    if (this.policy.max_workers === 1) return fallback;

    const projection = this.ledger.projection;
    const targets: FanOutTarget[] =
      this.policy.fan_out_over === "questions"
        ? [...projection.questions.values()]
            .filter((question) => question.status === "open")
            .map((question) => ({
              focus: question.question,
              // The lead carries its hypothesis, so a fanned-out worker that
              // fails leaves a gap attributed to what it was serving.
              hypothesisId: question.hypothesis_id,
              questionId: question.question_id,
            }))
        : [...projection.hypotheses.values()]
            .filter((hypothesis) => hypothesis.status === "active")
            .map((hypothesis) => ({
              focus: hypothesis.statement,
              hypothesisId: hypothesis.hypothesis_id,
              questionId: null,
            }));

    return targets.length === 0 ? fallback : targets.slice(0, this.policy.max_workers);
  }

  private async runDispatches(iteration: number, decision: Decision): Promise<DispatchResult[]> {
    if (decision.action !== "INVESTIGATE" || this.dispatcher === undefined) return [];
    const dispatcher = this.dispatcher;

    const targets = this.fanOut(decision);
    const requests = targets.map(({ focus, hypothesisId }) => ({
      dispatch_id: newId("dsp"),
      hunt_id: this.ledger.projection.hunt.hunt_id,
      agent_id: decision.worker_agent_id ?? DEFAULT_WORKER_AGENT_ID,
      query_intent: decision.query_intent || decision.rationale,
      focus,
      target_hypothesis_id: hypothesisId,
      scope: this.ledger.projection.hunt.scope,
    })) satisfies DispatchRequest[];

    // Closed once taken, not once answered: a lead left open would be re-issued
    // every iteration, and a failed one is already recorded as a visibility gap.
    // Written before the workers run, so an interrupted dispatch leaves a pending
    // row that reap() can hand its lead back from.
    for (const [index, request] of requests.entries()) {
      const questionId = targets[index]?.questionId ?? null;
      if (questionId !== null) this.ledger.patch("question", questionId, { status: "closed" });
      this.ledger.append({
        kind: "dispatch",
        dispatch: {
          dispatch_id: request.dispatch_id,
          iteration,
          agent_id: request.agent_id,
          status: "pending",
          query_intent: request.focus ? `${request.query_intent} — ${request.focus}` : request.query_intent,
          target_hypothesis_id: request.target_hypothesis_id,
          question_id: questionId,
          failure_reason: null,
          cost_usd: 0,
          calls: [],
        },
      });
    }

    // Promise.all resolves in request order regardless of completion order, so
    // two runs over the same inputs produce the same ledger.
    return Promise.all(
      requests.map(async (request) => {
        try {
          return await dispatcher.dispatch(request);
        } catch (error) {
          return {
            dispatch_id: request.dispatch_id,
            evidence: [],
            failed: true,
            failure_reason: (error as Error).message,
            cost_usd: spentBefore(error),
          };
        }
      }),
    );
  }

  // The only call that can lead to proven. Runs before anything is written, so
  // an iteration that pays the critic records the charge with its decision.
  private async runNullCheck(decision: Decision): Promise<NullCheckAttempt> {
    if (decision.action !== "VALIDATE") return NO_NULL_CHECK;
    if (this.critic === undefined) {
      return { ...NO_NULL_CHECK, blocked: "no disconfirmation critic is configured, so it stays active" };
    }

    // validateDecision has already required a target the ledger knows.
    const hypothesis = this.ledger.projection.hypotheses.get(decision.target_hypothesis_id ?? "");
    if (hypothesis === undefined) return NO_NULL_CHECK;
    if (hypothesis.status !== "active") {
      return { ...NO_NULL_CHECK, blocked: `already ${hypothesis.status}; no second verdict was run` };
    }

    const input = nullCheckInput(this.ledger.projection, hypothesis);
    const argued = input.evidence.map((linked) => linked.record.evidence_id);
    try {
      const result = await this.critic.argueNull(input);
      return { result, blocked: "", cost_usd: result.cost_usd, argued };
    } catch (error) {
      // A critic that cannot run fails closed. An unavailable argument is not a
      // won one, and the hunt keeps going with the hypothesis still open — but
      // whatever it spent before dying is still charged.
      return {
        result: null,
        blocked: `the disconfirmation critic failed (${(error as Error).message}), so it stays active`,
        cost_usd: spentBefore(error),
        argued: [],
      };
    }
  }

  // The one writer of proven, and kept off write() because termination reads
  // hypothesis terminality. Returns what to tell the operator.
  private applyVerdict(iteration: number, decision: Decision, attempt: NullCheckAttempt): string {
    const hypothesisId = decision.target_hypothesis_id ?? "";
    if (attempt.result === null) return `${hypothesisId}: ${attempt.blocked}`;
    const nullCheck = attempt.result;

    const evidenceId = newId("ev");
    this.ledger.append({
      kind: "evidence",
      evidence: {
        evidence_id: evidenceId,
        dispatch_id: null,
        iteration,
        source_system: CRITIC_SOURCE_SYSTEM,
        summary: `strongest benign explanation: ${nullCheck.strongest_benign_explanation}`,
        payload: {
          hypothesis_id: hypothesisId,
          survives: nullCheck.survives,
          // What the argument was made against, so a later verdict can tell a
          // current survival from one that predates half the evidence.
          argued_evidence_ids: attempt.argued,
          strongest_benign_explanation: nullCheck.strongest_benign_explanation,
          rationale: nullCheck.rationale,
          model_id: nullCheck.model_id,
          prompt_version: nullCheck.prompt_version,
          cost_usd: nullCheck.cost_usd,
        },
        salience: "notable",
        why_notable: nullCheck.rationale,
        provenance: NULL_CHECK_PROVENANCE,
        attacker_influenceable: false,
        instruction_like: false,
        captured_at: new Date().toISOString(),
      },
    });

    // A benign explanation that stands is counter-evidence like any other: it
    // enters the record, reaches the next digest, and is never a verdict itself.
    if (!nullCheck.survives) {
      this.ledger.append({
        kind: "link",
        link: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation: "weakens" },
      });
    }

    const strength = evidenceStrength(this.ledger.projection, hypothesisId);

    // Checked whichever way the critic argued: not having been able to look is
    // never the same as having cleared it, so this closes inconclusive.
    if (strength.open_gaps >= this.verdicts.gap_lock_threshold) {
      this.ledger.patch("hypothesis", hypothesisId, {
        status: "inconclusive",
        resolution_reason:
          `gap-locked: ${strength.open_gaps} open visibility gap(s) bear on this hypothesis, ` +
          "so the hunt could not look rather than having cleared it",
        evidence_strength: strength,
      });
      return `${hypothesisId} inconclusive (gap-locked)`;
    }

    const unmet = unmetPredicates(strength, this.verdicts);
    if (unmet.length > 0) return `${hypothesisId} stays active: ${unmet.join("; ")}`;

    this.ledger.patch("hypothesis", hypothesisId, {
      status: "proven",
      resolution_reason:
        `survived the argue-the-null pass against "${nullCheck.strongest_benign_explanation}" ` +
        `on ${strength.corroborating_sources} corroborating source system(s)`,
      evidence_strength: strength,
    });
    return `${hypothesisId} proven`;
  }

  private write(
    iteration: number,
    digest: Digest,
    result: DecisionResult,
    dispatchResults: readonly DispatchResult[],
    nullCheck: NullCheckAttempt,
  ): IterationResult {
    const decisionId = newId("dec");
    this.ledger.append({
      kind: "decision",
      decision: {
        ...result,
        decision_id: decisionId,
        iteration,
        digest_presented: digest,
        created_at: new Date().toISOString(),
      },
    });

    // Every paid call in the iteration lands in the budget counter: the workers
    // are the largest share of a real hunt's spend, and a max_cost_usd that only
    // sees the Hunt Lead is not a budget.
    const workers = dispatchResults.reduce((total, dispatchResult) => total + dispatchResult.cost_usd, 0);
    const spent = Number((result.cost_usd + workers + nullCheck.cost_usd).toFixed(6));
    const hunt = this.ledger.projection.hunt;
    this.ledger.patch("hunt", hunt.hunt_id, {
      iteration,
      cost_usd: Number((hunt.cost_usd + spent).toFixed(6)),
    });

    const appended = dispatchResults.reduce(
      (total, dispatchResult) => total + this.persistDispatch(iteration, dispatchResult),
      0,
    );

    // Before termination: a verdict reached this iteration must be on the record
    // when the terminal path coerces whatever is still active.
    const notes: string[] = [];
    if (result.decision.action === "VALIDATE") {
      notes.push(this.applyVerdict(iteration, result.decision, nullCheck));
    }

    if (result.decision.action === "CONCLUDE") {
      this.terminate("completed");
    } else if (this.budgetExhausted()) {
      this.terminate("budget_terminated");
      notes.push("budget exhausted");
    }

    const final = this.ledger.projection.hunt;
    return {
      hunt_id: final.hunt_id,
      iteration,
      action: result.decision.action,
      decision_id: decisionId,
      cost_usd: spent,
      evidence_appended: appended,
      hunt_status: final.status,
      hunt_outcome: final.outcome,
      note: notes.filter((entry) => entry !== "").join("; "),
    };
  }

  // Corroboration is counted over source systems, so a label the hunt never
  // declared earns no independence credit: it collapses into one bucket rather
  // than letting two invented names read as two systems agreeing. The worker's
  // claim stays on the record.
  private attributeSource(record: WorkerEvidence): Pick<EvidenceRecord, "source_system" | "payload"> {
    const declared = this.ledger.projection.hunt.spec.data_domains;
    if (record.provenance !== "worker" || declared.length === 0 || declared.includes(record.source_system)) {
      return { source_system: record.source_system, payload: record.payload };
    }
    return {
      source_system: UNDECLARED_SOURCE,
      payload: { ...record.payload, claimed_source_system: record.source_system },
    };
  }

  private persistDispatch(iteration: number, result: DispatchResult): number {
    // Idempotency on dispatch_id: a retried dispatch re-delivers the same
    // evidence, and appending it twice would inflate corroboration counts. A gap
    // record does not count as delivery, or a retry of a dispatch that failed
    // could never bring anything back.
    const already = [...this.ledger.projection.evidence.values()].some(
      (record) => record.dispatch_id === result.dispatch_id && !isGap(record),
    );
    if (already) {
      this.ledger.patch("dispatch", result.dispatch_id, { status: "complete" });
      return 0;
    }

    // A failed worker is evidence about visibility, not a lost turn.
    const records = result.failed
      ? [
          {
            source_system: "dispatcher",
            summary: `worker failed: ${result.failure_reason}`,
            payload: {},
            salience: "routine" as const,
            why_notable: "a query the hunt wanted could not be run",
            provenance: "tool_failure",
            attacker_influenceable: false,
            instruction_like: false,
          },
        ]
      : result.evidence;

    const known = this.ledger.projection.hypotheses;
    const dispatch = this.ledger.projection.dispatches.get(result.dispatch_id);
    for (const { supports, weakens, ...record } of records) {
      const evidenceId = newId("ev");
      this.ledger.append({
        kind: "evidence",
        evidence: {
          ...record,
          ...this.attributeSource(record),
          evidence_id: evidenceId,
          dispatch_id: result.dispatch_id,
          iteration,
          captured_at: new Date().toISOString(),
        },
      });

      // A link to a hypothesis the worker invented would corrupt the contrarian
      // quota, so only ids the ledger already knows are linked.
      for (const [relation, ids] of [["supports", supports], ["weakens", weakens]] as const) {
        for (const hypothesisId of ids ?? []) {
          if (!known.has(hypothesisId)) continue;
          this.ledger.append({
            kind: "link",
            link: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation },
          });
        }
      }
    }

    for (const question of result.questions ?? []) {
      this.ledger.append({
        kind: "question",
        question: {
          question_id: newId("q", 4),
          question,
          status: "open",
          spawning_evidence_id: null,
          // Inherited from the work that opened it, so the lead stays attached to
          // the hypothesis it serves however far it travels down the frontier.
          hypothesis_id: dispatch?.target_hypothesis_id ?? null,
        },
      });
    }

    this.ledger.patch("dispatch", result.dispatch_id, {
      status: result.failed ? "failed" : "complete",
      failure_reason: result.failed ? result.failure_reason : null,
      cost_usd: result.cost_usd,
      calls: result.calls ?? [],
    });
    return records.length;
  }

  // Unresolved hypotheses become inconclusive, never disproven: the hunt
  // stopped looking, which is not the same as having cleared them.
  terminate(outcome: HuntOutcome): void {
    const hunt = this.ledger.projection.hunt;
    if (hunt.outcome !== null && OUTCOME_PRECEDENCE[hunt.outcome] >= OUTCOME_PRECEDENCE[outcome]) return;

    for (const hypothesis of this.ledger.projection.hypotheses.values()) {
      if (hypothesis.status !== "active") continue;
      this.ledger.patch("hypothesis", hypothesis.hypothesis_id, {
        status: "inconclusive",
        resolution_reason: `hunt ended (${outcome}) with the hypothesis unresolved`,
      });
    }

    this.ledger.patch("hunt", hunt.hunt_id, {
      status: "terminal",
      outcome,
      terminated_at: new Date().toISOString(),
    });
  }

  private budgetExhausted(): boolean {
    const hunt = this.ledger.projection.hunt;
    return (
      hunt.iteration >= hunt.budgets.max_iterations || hunt.cost_usd >= hunt.budgets.max_cost_usd
    );
  }
}
