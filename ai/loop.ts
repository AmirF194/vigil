import { join } from "node:path";
import { buildDigest, focusOf, rankFrontier } from "./digest.js";
import { buildEntityGraph, entitiesOf, key } from "./entities.js";
import { drain } from "./inbox.js";
import { Ledger, newId, type Projection } from "./ledger.js";
import type { DecisionProvider, Enricher, WorkerDispatcher } from "./ports.js";
import { sanitize, sanitizeQuestion } from "./sanitize.js";
import {
  DEFAULT_DIGEST,
  DEFAULT_DISPATCH,
  DEFAULT_ENRICHMENT,
  type DigestPolicy,
  type DispatchPolicy,
  type HuntSpec,
} from "./spec.js";
import {
  ACTIONS_REQUIRING_CITATION,
  DECISION_ACTIONS,
  OUTCOME_PRECEDENCE,
  type Decision,
  type DecisionResult,
  type Digest,
  type DispatchRequest,
  type DispatchResult,
  type Entity,
  type EvidenceRecord,
  type Expansion,
  type HuntOutcome,
  type IterationResult,
  type OpenQuestion,
  type WorkerEvidence,
} from "./types.js";

export const DEFAULT_WORKER_AGENT_ID = "threat_hunter";

// One emission plus two re-asks. Bounded because a Hunt Lead that cannot obey
// the vocabulary will not learn to on the tenth try, and every ask costs money.
export const MAX_DECISION_ATTEMPTS = 3;

// EXPAND does not advance the iteration, so only this stops a lead reading forever.
export const MAX_EXPANSIONS = 3;

// Total characters of raw payload one expansion may add. Rounds are bounded
// already; without this the context is bounded only by how many ids are named.
const EXPANSION_BUDGET = 12_000;

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

  const hypothesisId = decision.target_hypothesis_id;
  if (hypothesisId !== undefined && hypothesisId !== null && !projection.hypotheses.has(hypothesisId)) {
    throw new InvalidDecision(`no such hypothesis ${hypothesisId}`);
  }

  // Citations before focus: a decision resting on evidence that does not exist
  // is wrong about the data, which is worth saying before it is wrong about a verb.
  if (ACTIONS_REQUIRING_CITATION.has(decision.action)) {
    const citations = decision.evidence_citations ?? [];
    if (citations.length === 0) {
      throw new InvalidDecision(`${decision.action} must cite the evidence it rests on`);
    }
    const unknown = citations.filter((id) => !projection.evidence.has(id));
    if (unknown.length > 0) {
      throw new InvalidDecision(`${decision.action} cites unknown evidence: ${unknown.join(", ")}`);
    }
  }
  validateFocus(decision, projection);
  if (decision.action === "ABANDON") validateAbandon(decision, projection);
}

// Dropping a branch is the one decision an adversary most wants the hunt to make,
// and the evidence it would rest on is exactly what an adversary can write. So a
// branch may not be abandoned on attacker-authored grounds alone.
function validateAbandon(decision: Decision, projection: Projection): void {
  if (!decision.target_hypothesis_id && !decision.target_entity) {
    throw new InvalidDecision("ABANDON must name the hypothesis or entity it is dropping");
  }

  const cited = (decision.evidence_citations ?? [])
    .map((id) => projection.evidence.get(id))
    .filter((record): record is EvidenceRecord => record !== undefined);

  if (!cited.some((record) => !record.attacker_influenceable && !record.instruction_like)) {
    throw new InvalidDecision(
      "every record ABANDON cites is attacker-influenceable; cite at least one whose content an adversary could not have authored",
    );
  }
}

// DEEPEN keeps the current entity and hypothesis; PIVOT changes at least one.
// Without the graph the rule is unenforceable, and the two verbs collapse into
// a preference the lead states and nothing checks.
function validateFocus(decision: Decision, projection: Projection): void {
  const graph = buildEntityGraph([...projection.evidence.values()], projection.hunt.scope["entity"] as Entity);
  const target = decision.target_entity;

  if (target !== undefined && target !== null && graph.node(target) === undefined) {
    const known = graph.nodes().map((node) => key(node.entity)).sort();
    throw new InvalidDecision(
      `no evidence mentions ${target}; the graph knows ${known.slice(0, 8).join(", ") || "nothing yet"}`,
    );
  }
  if (decision.action !== "DEEPEN" && decision.action !== "PIVOT") return;

  const focus = focusOf(projection);
  const held =
    (target ?? focus.entity) === focus.entity &&
    (decision.target_hypothesis_id ?? focus.hypothesis) === focus.hypothesis;

  if (decision.action === "DEEPEN" && !held) {
    throw new InvalidDecision("DEEPEN must keep the current entity and hypothesis; changing one is a PIVOT");
  }
  if (decision.action === "PIVOT" && held) {
    throw new InvalidDecision("PIVOT must change the entity or the hypothesis; keeping both is a DEEPEN");
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
    seed: newId("seed", 8),
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
    private readonly enricher?: Enricher | undefined,
  ) {}

  // Read from the journaled spec rather than passed in: the chains a hunt runs
  // were fixed when it started, and resume must not pick up an edited config.
  private get enrichment() {
    return this.ledger.projection.hunt.spec.enrichment ?? DEFAULT_ENRICHMENT;
  }

  async advanceIteration(): Promise<IterationResult> {
    if (this.ledger.projection.hunt.status === "terminal") {
      const hunt = this.ledger.projection.hunt;
      throw new HuntAlreadyTerminal(`${hunt.hunt_id} already ended as ${hunt.outcome}`);
    }

    // Human input is integrated at the boundary, before anything is decided on it.
    if (this.applyDirectives()) return this.aborted();

    const projection = this.ledger.projection;
    const iteration = projection.hunt.iteration + 1;
    const digest = buildDigest(projection, iteration, this.digestPolicy);

    const { presented, result } = await this.decide(digest, projection);

    const dispatchResults = await this.runDispatches(iteration, result.decision);
    return await this.write(iteration, presented, result, dispatchResults);
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
    let attempts = 0;
    let expansions = 0;

    while (attempts < MAX_DECISION_ATTEMPTS) {
      const result = await this.provider.decide(presented);
      rejected.push(...(result.rejected_attempts ?? []));
      spent += result.cost_usd;

      try {
        validateDecision(result.decision, projection);
      } catch (error) {
        if (!(error instanceof InvalidDecision)) throw error;
        attempts += 1;
        rejected.push(error.message);
        presented = withRejection(presented, error.message);
        continue;
      }

      // EXPAND is a read, not a move: it buys raw payloads and asks again without
      // advancing the iteration. Cost still accrues, so it is not free, only
      // free of the iteration budget.
      if (result.decision.action === "EXPAND") {
        if (expansions < MAX_EXPANSIONS) {
          expansions += 1;
          presented = this.expand(presented, result.decision.evidence_citations ?? []);
          continue;
        }
        attempts += 1;
        const exhausted = `all ${MAX_EXPANSIONS} expansions are used; decide on what you have`;
        rejected.push(exhausted);
        presented = withRejection(presented, exhausted);
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

  // Whole records are dropped at the budget rather than one being cut mid-JSON,
  // and what was dropped is named so the lead can ask for less next time.
  private expand(digest: Digest, ids: readonly string[]): Digest {
    const expansions: Expansion[] = [];
    const dropped: string[] = [];
    let budget = EXPANSION_BUDGET;

    for (const evidenceId of ids) {
      const record = this.ledger.projection.evidence.get(evidenceId);
      if (record === undefined) continue;
      const payload = JSON.stringify(record.payload, null, 2);
      if (payload.length > budget) {
        dropped.push(evidenceId);
        continue;
      }
      budget -= payload.length;
      expansions.push({ evidence_id: evidenceId, payload });
    }

    const notes = dropped.length === 0 ? digest.notes : [...digest.notes, `Too large to expand: ${dropped.join(", ")}.`];
    return { ...digest, expansions: [...digest.expansions, ...expansions], notes };
  }

  // Returns true when a directive ended the hunt. A lead becomes a real lead; a
  // note only reaches the digest, so it steers without mutating anything.
  private applyDirectives(): boolean {
    let abort = false;
    for (const directive of drain(this.ledger)) {
      if (directive.kind === "abort") abort = true;
      if (directive.kind !== "lead") continue;
      this.raise(directive.text, { spawned_iteration: this.ledger.projection.hunt.iteration + 1 });
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
      enriched: 0,
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
    const held = decision.target_entity ?? focusOf(this.ledger.projection).entity;
    const scoped = (text: string, entityKey: string | null) =>
      entityKey === null ? text : `${text} [entity ${entityKey}]`;

    const fallback: FanOutTarget[] = [
      {
        focus: scoped("", held ?? null).trim(),
        hypothesisId: decision.target_hypothesis_id ?? null,
        questionId: null,
      },
    ];
    if (this.policy.max_workers === 1) return fallback;

    const projection = this.ledger.projection;
    const targets: FanOutTarget[] =
      this.policy.fan_out_over === "questions"
        ? rankFrontier(projection, projection.hunt.iteration + 1)
            .map((question) => ({
              // A lead carries the entity it is about, so the worker is told what
              // to look at rather than inferring it from prose.
              focus: scoped(question.question, question.entity_key),
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

  // One appender for every lead, so the priority features are always populated:
  // a lead with no provenance is a lead the frontier cannot rank.
  private raise(question: string, provenance: Partial<Omit<OpenQuestion, "question_id" | "question" | "status">>): void {
    this.ledger.append({
      kind: "question",
      question: {
        question_id: newId("q", 4),
        question,
        status: "open",
        entity_key: null,
        spawning_evidence_id: null,
        spawning_dispatch_id: null,
        spawned_iteration: 0,
        ...provenance,
      },
    });
  }

  // PIVOT is a move of attention, not a query: it puts its new target on the
  // frontier and lets the next INVESTIGATE pick it up from there.
  private pivot(iteration: number, decision: Decision): void {
    const target = decision.target_entity ?? decision.target_hypothesis_id ?? "";
    this.raise(decision.query_intent || `pursue ${target}: ${decision.rationale}`, {
      entity_key: decision.target_entity ?? null,
      spawning_evidence_id: decision.evidence_citations?.[0] ?? null,
      spawned_iteration: iteration,
    });
  }

  // Parked rather than disproven: the hunt stopped looking, which is not the same
  // as having cleared the branch. validateAbandon has already established that
  // the grounds are not attacker-authored alone.
  private abandon(decision: Decision): void {
    const reason = `abandoned at the Hunt Lead's decision: ${decision.rationale} [${(decision.evidence_citations ?? []).join(", ")}]`;
    if (decision.target_hypothesis_id) {
      this.ledger.patch("hypothesis", decision.target_hypothesis_id, { status: "parked", resolution_reason: reason });
    }

    for (const question of this.ledger.projection.questions.values()) {
      if (question.status === "open" && question.entity_key !== null && question.entity_key === decision.target_entity) {
        this.ledger.patch("question", question.question_id, { status: "closed" });
      }
    }
  }

  // DEEPEN dispatches like INVESTIGATE; validateFocus has already established
  // that it kept the focus, so the only difference is what the worker is told.
  private async runDispatches(iteration: number, decision: Decision): Promise<DispatchResult[]> {
    if (decision.action === "PIVOT") {
      this.pivot(iteration, decision);
      return [];
    }
    if (decision.action === "ABANDON") {
      this.abandon(decision);
      return [];
    }
    const dispatches = decision.action === "INVESTIGATE" || decision.action === "DEEPEN";
    if (!dispatches || this.dispatcher === undefined) return [];
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

  private async write(
    iteration: number,
    digest: Digest,
    result: DecisionResult,
    dispatchResults: readonly DispatchResult[],
  ): Promise<IterationResult> {
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

    const appended = dispatchResults.flatMap((dispatchResult) => this.persistDispatch(iteration, dispatchResult));
    const enriched = await this.enrich(iteration, appended.flatMap((record) => record.entities));

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
      evidence_appended: appended.length,
      enriched,
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

  // Shared by workers and by enrichment, so no evidence source can reach the
  // ledger without sanitize() and entity extraction.
  private appendEvidence(
    records: readonly WorkerEvidence[],
    iteration: number,
    dispatchId: string | null,
  ): EvidenceRecord[] {
    return records.map(sanitize).map(({ supports, weakens, ...record }) => {
      const evidenceId = newId("ev");
      const stored: EvidenceRecord = {
        ...record,
        evidence_id: evidenceId,
        dispatch_id: dispatchId,
        iteration,
        entities: entitiesOf(record),
        captured_at: new Date().toISOString(),
      };
      this.ledger.append({ kind: "evidence", evidence: stored });
      this.link(evidenceId, supports, weakens);
      return stored;
    });
  }

  // Read-only follow-up on the entities this iteration introduced. Deterministic,
  // so it costs no decision — only rounds, breadth and the once-per-entity rule
  // bound it. Dedup is on the entity alone because the enricher runs every chain
  // that applies to one, so an enriched entity has had all of its chains run.
  private async enrich(iteration: number, seed: readonly Entity[]): Promise<number> {
    const enricher = this.enricher;
    if (enricher === undefined) return 0;
    const { max_depth, max_entities } = this.enrichment;

    let frontier = seed;
    let total = 0;

    for (let depth = 0; depth < max_depth && frontier.length > 0; depth += 1) {
      const done = this.enrichedEntities();
      const fresh = new Map(frontier.map((entity) => [key(entity), entity] as const));
      const pending = [...fresh].filter(([id]) => !done.has(id)).slice(0, max_entities);
      if (pending.length === 0) break;

      const records = (await Promise.all(pending.map(([, entity]) => enricher(entity)))).flat();
      const appended = this.appendEvidence(records, iteration, null);
      total += appended.length;
      frontier = appended.flatMap((record) => record.entities);
    }
    return total;
  }

  private enrichedEntities(): Set<string> {
    const done = new Set<string>();
    for (const record of this.ledger.projection.evidence.values()) {
      if (record.provenance.startsWith("enrichment:")) done.add(String(record.payload["entity"] ?? ""));
    }
    return done;
  }

  private persistDispatch(iteration: number, result: DispatchResult): EvidenceRecord[] {
    // Idempotency on dispatch_id: a retried dispatch re-delivers the same
    // evidence, and appending it twice would inflate corroboration counts. Keyed
    // on the dispatch row rather than a scan for its evidence, so a dispatch that
    // legitimately found nothing is still settled exactly once.
    if (this.ledger.projection.dispatches.get(result.dispatch_id)?.status !== "pending") return [];

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

    const appended = this.appendEvidence(records, iteration, result.dispatch_id);

    for (const question of result.questions ?? []) {
      this.raise(sanitizeQuestion(question), {
        spawning_dispatch_id: result.dispatch_id,
        spawned_iteration: iteration,
      });
    }

    this.ledger.patch("dispatch", result.dispatch_id, {
      status: result.failed ? "failed" : "complete",
      failure_reason: result.failed ? result.failure_reason : null,
    });
    // A gap record is a fact about visibility, not a finding, so it counts as
    // neither evidence appended nor something worth enriching.
    return result.failed ? [] : appended;
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
