import { join } from "node:path";
import { buildDigest } from "./digest.js";
import { drain } from "./inbox.js";
import { Ledger, newId, type Projection } from "./ledger.js";
import type { DecisionProvider, WorkerDispatcher } from "./ports.js";
import { sanitize, sanitizeQuestion } from "./sanitize.js";
import { DEFAULT_DIGEST, DEFAULT_DISPATCH, type DigestPolicy, type DispatchPolicy, type HuntSpec } from "./spec.js";
import {
  ACTIONS_REQUIRING_CITATION,
  DECISION_ACTIONS,
  OUTCOME_PRECEDENCE,
  type Decision,
  type DecisionResult,
  type Digest,
  type DispatchRequest,
  type DispatchResult,
  type HuntOutcome,
  type IterationResult,
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

// The controller rejects anything outside the closed vocabulary, so the Hunt
// Lead cannot widen its own action space by emitting a new verb or a worker
// the registry never declared.
export function validateDecision(decision: Decision, projection: Projection): void {
  if (!DECISION_ACTIONS.includes(decision.action)) {
    throw new InvalidDecision(`unknown action ${String(decision.action)}`);
  }

  const workers = projection.hunt.spec.roles.workers;
  const agentId = decision.worker_agent_id;
  if (agentId !== undefined && agentId !== null && !(agentId in workers)) {
    throw new InvalidDecision(`no such worker ${agentId}; the registry declares ${Object.keys(workers).sort().join(", ")}`);
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
    return this.write(iteration, presented, result, dispatchResults);
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
              hypothesisId: null,
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
          };
        }
      }),
    );
  }

  private write(
    iteration: number,
    digest: Digest,
    result: DecisionResult,
    dispatchResults: readonly DispatchResult[],
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

    const hunt = this.ledger.projection.hunt;
    this.ledger.patch("hunt", hunt.hunt_id, {
      iteration,
      cost_usd: Number((hunt.cost_usd + result.cost_usd).toFixed(6)),
    });

    const appended = dispatchResults.reduce(
      (total, dispatchResult) => total + this.persistDispatch(iteration, dispatchResult),
      0,
    );

    let note = "";
    if (result.decision.action === "CONCLUDE") {
      this.terminate("completed");
    } else if (this.budgetExhausted()) {
      this.terminate("budget_terminated");
      note = "budget exhausted";
    }

    const final = this.ledger.projection.hunt;
    return {
      hunt_id: final.hunt_id,
      iteration,
      action: result.decision.action,
      decision_id: decisionId,
      cost_usd: result.cost_usd,
      evidence_appended: appended,
      hunt_status: final.status,
      hunt_outcome: final.outcome,
      note,
    };
  }

  // A link to a hypothesis the worker invented would corrupt the contrarian
  // quota, so only ids the ledger already knows are linked.
  private link(evidenceId: string, supports?: string[], weakens?: string[]): void {
    const known = this.ledger.projection.hypotheses;
    for (const [relation, ids] of [["supports", supports], ["weakens", weakens]] as const) {
      for (const hypothesisId of ids ?? []) {
        if (!known.has(hypothesisId)) continue;
        this.ledger.append({ kind: "link", link: { evidence_id: evidenceId, hypothesis_id: hypothesisId, relation } });
      }
    }
  }

  private persistDispatch(iteration: number, result: DispatchResult): number {
    // Idempotency on dispatch_id: a retried dispatch re-delivers the same
    // evidence, and appending it twice would inflate corroboration counts. Keyed
    // on the dispatch row rather than a scan for its evidence, so a dispatch that
    // legitimately found nothing is still settled exactly once.
    if (this.ledger.projection.dispatches.get(result.dispatch_id)?.status !== "pending") return 0;

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

    // Sanitized here rather than in the dispatcher, so no WorkerDispatcher can
    // put unescaped text into the digest by omitting the step.
    for (const { supports, weakens, ...record } of records.map(sanitize)) {
      const evidenceId = newId("ev");
      this.ledger.append({
        kind: "evidence",
        evidence: {
          ...record,
          evidence_id: evidenceId,
          dispatch_id: result.dispatch_id,
          iteration,
          captured_at: new Date().toISOString(),
        },
      });

      this.link(evidenceId, supports, weakens);
    }

    for (const question of result.questions ?? []) {
      this.ledger.append({
        kind: "question",
        question: {
          question_id: newId("q", 4),
          question: sanitizeQuestion(question),
          status: "open",
          spawning_evidence_id: null,
        },
      });
    }

    this.ledger.patch("dispatch", result.dispatch_id, {
      status: result.failed ? "failed" : "complete",
      failure_reason: result.failed ? result.failure_reason : null,
    });
    return result.failed ? 0 : records.length;
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
