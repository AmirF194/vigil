import { drain, streamTurn } from "../../core/stream.js";
import type { Attempt, Harness } from "../../core/loop.js";
import { clamp } from "../../core/security.js";
import type { RoleSpec, RunSpec } from "../../core/spec.js";
import { SpecError } from "../../core/spec.js";
import { narrativeOf, renderDigest, renderDispatch, renderNullCheck } from "./render.js";
import type { HuntKinds } from "./ledger.js";
import type { DecisionProvider, DisconfirmationCritic, WorkerDispatcher } from "./ports.js";
import type {
  Decision,
  DecisionResult,
  Digest,
  DispatchRequest,
  DispatchResult,
  NullCheckInput,
  NullCheckResult,
  ToolCall,
  WorkerEvidence,
} from "./types.js";

// The hunt's four ports over the harness. The controller decides; these only
// carry a question to a model and an answer back, and never touch the ledger.
export interface AdapterOptions {
  harness: Harness<HuntKinds>;
  spec: RunSpec;
  run_id: string;
  actions: readonly string[];
  signal?: AbortSignal;
}

function role(spec: RunSpec, name: "lead" | "critic"): RoleSpec {
  const held = spec.roles[name];
  if (held === undefined) throw new SpecError(`arch ${spec.arch} declares no ${name}, which the hunt requires`);
  return held;
}

// The lease signal and the operator's abort both end the call, and either alone
// leaves the other unheard.
//
// Composed by hand rather than with AbortSignal.any, for the reason core/remote.ts
// documents: any() attaches to both sources and lets go only when the composite is
// collected, so composing one per turn piled a listener per iteration onto the
// run-long lease signal until Node warned about a leak. release() is what any()
// gives no way to call.
interface Linked {
  signal: AbortSignal | undefined;
  release(): void;
}

export function link(held?: AbortSignal, asked?: AbortSignal): Linked {
  // Only one to honour: pass it straight through, attaching nothing to release.
  if (held === undefined || asked === undefined) return { signal: held ?? asked, release: () => {} };

  const halt = new AbortController();
  const relay = (source: AbortSignal) => () => halt.abort(source.reason);
  const onHeld = relay(held);
  const onAsked = relay(asked);
  if (held.aborted) halt.abort(held.reason);
  else if (asked.aborted) halt.abort(asked.reason);
  held.addEventListener("abort", onHeld, { once: true });
  asked.addEventListener("abort", onAsked, { once: true });

  return {
    signal: halt.signal,
    release: () => {
      held.removeEventListener("abort", onHeld);
      asked.removeEventListener("abort", onAsked);
    },
  };
}

function turnFor(options: AdapterOptions, id: string, spec: RoleSpec, task: string, signal?: AbortSignal) {
  const held = signal ?? options.signal;
  const { runtime } = options.spec;
  return {
    run_id: options.run_id,
    run_kind: "hunt" as const,
    role: id,
    system: spec.prompt,
    task,
    schema: spec.output_schema,
    max_turns: runtime.max_turns,
    approvals: new Set(options.spec.approvals),
    verbs: options.actions,
    result_cap: runtime.result_cap,
    recall_limit: runtime.recall_limit,
    ...(held === undefined ? {} : { signal: held }),
  };
}

// What a turn cost, from what the harness journaled rather than a second tally:
// the pool is the authority on money and this is reading it, not keeping books.
function spentOn(harness: Harness<HuntKinds>, before: number): number {
  return Math.max(0, harness.budget.spent.cost_usd - before);
}

// A call that throws has still been paid for. The harness journals the spend
// either way, but the caller reads what a failure cost off the error --
// spentBefore() in the controller expects error.cost_usd -- and a provider error
// carries no such field, so the money vanished between the ledger and the budget.
// One run journaled $0.79 of spend and reported $0.11: nine worker calls failed on
// a dropped upstream stream, every one of them paid for, none of them counted.
// A ceiling that cannot see failed work is a ceiling a failing run walks straight
// through.
export async function charged<T>(harness: Harness<HuntKinds>, before: number, call: Promise<T>): Promise<T> {
  try {
    return await call;
  } catch (error) {
    const spent = spentOn(harness, before);
    if (spent > 0 && typeof error === "object" && error !== null && !("cost_usd" in error)) {
      Object.defineProperty(error, "cost_usd", { value: spent, enumerable: false });
    }
    throw error;
  }
}

// One digest in, one decision out. The digest is rendered rather than handed
// over as an object, because what the lead reasons about is what it can read.
export function decisionProvider(options: AdapterOptions): DecisionProvider {
  const lead = role(options.spec, "lead");

  return {
    decide: async (digest: Digest, signal?: AbortSignal): Promise<DecisionResult> => {
      const before = options.harness.budget.spent.cost_usd;
      const linked = link(options.signal, signal);
      let outcome;
      try {
        outcome = await charged(
          options.harness,
          before,
          drain(streamTurn<Decision, HuntKinds>(turnFor(options, "lead", lead, renderDigest(digest), linked.signal), options.harness)),
        );
      } finally {
        linked.release();
      }
      if (outcome.value === null) {
        if (outcome.refusal !== null) throw new BudgetRefused(outcome.reason);
        throw new SpecError(`the lead emitted no decision: ${outcome.reason}`);
      }

      return {
        decision: outcome.value,
        model_id: options.harness.provider.model,
        prompt_version: options.spec.arch,
        cost_usd: spentOn(options.harness, before),
        ...(outcome.rejected.length === 0 ? {} : { rejected_attempts: outcome.rejected }),
      };
    },
  };
}

export interface WorkerAnswer {
  results?: unknown[];
  ips_to_check?: string[];
}

// What a worker reported, having characterised it. The strength layer counts
// corroboration and confirmation drift over exactly this provenance.
export const WORKER = "worker";

// Rows a dispatch gathered and then died before writing up. Real telemetry the run
// has already paid for, at a provenance of its own: no role has said what they mean,
// so they must not read as a finding somebody vouched for.
export const UNSUMMARISED = "unsummarised";

// A dispatch whose write-up call failed still ran its queries. Discarding those
// rows made one flaky call cost the whole iteration -- eight successful Splunk
// searches thrown away because the ninth call died. Kept as evidence instead, with
// the query beside the rows so an analyst can re-run it.
// Characters of gathered output one salvage record may carry. The digest caps a
// payload at 8000 and replaces an over-long one with a flat string, which would cost
// the entities -- the addresses in these rows are the point -- so this trims first.
const SALVAGE_BUDGET = 6_000;

// One record for the whole dispatch, not one per call: a worker that ran twenty-nine
// queries produced twenty-nine near-identical records, every one promoted to notable
// by the attacker_influenceable floor, which buried the real findings in a digest that
// holds twenty-five. What the lead needs to know is that this dispatch gathered
// something nobody wrote up, once, with the queries beside it.
export function salvaged(attempts: readonly Attempt[]): WorkerEvidence[] {
  const kept = attempts.filter(({ result }) => result.ok && result.rowCount > 0);
  if (kept.length === 0) return [];

  const systems = [...new Set(kept.map(({ result }) => (result.ok ? result.sourceSystem : "")))].filter((one) => one);
  let spent = 0;
  const gathered = kept.map(({ tool, args, result }) => {
    const rows = result.ok ? result.rows : [];
    const text = JSON.stringify(rows);
    // Queries are never dropped: they are what an analyst re-runs. Rows are, past
    // the budget, and the record says so rather than appearing to be all of them.
    const room = spent < SALVAGE_BUDGET;
    spent += text.length;
    return { tool, query: args, ...(room ? { rows } : { rows_dropped: rows.length }) };
  });

  return [
    {
      // Several tools can answer one dispatch, and corroboration is counted over
      // this: naming one of them would credit it with the others' independence.
      source_system: systems.length === 1 ? systems[0]! : "several",
      summary: `${kept.length} quer${kept.length === 1 ? "y" : "ies"} returned data that no role summarised: the dispatch failed before its write-up`,
      salience: "routine" as const,
      why_notable: "gathered before the dispatch failed, and never characterised",
      payload: { gathered },
      provenance: UNSUMMARISED,
      // Nothing has vouched for these rows, so they cannot clear a branch on
      // their own -- the same rule that holds for an auto-enriched record.
      attacker_influenceable: true,
      instruction_like: false,
    },
  ];
}

// A worker's emission, as evidence records. Anything the schema did not require
// is dropped rather than guessed at: the controller stamps identity and time.
export function evidenceFrom(answer: WorkerAnswer): WorkerEvidence[] {
  if (!Array.isArray(answer.results)) return [];
  return answer.results.map((row) => {
    const record = row as Record<string, unknown>;
    return {
      // Stamped here or nowhere: unclassified(), unruledObservations() and
      // attributeSource() all filter on it, so an unset provenance silently
      // switched off the confirmation-drift guard rather than failing anything.
      provenance: WORKER,
      instruction_like: false,
      attacker_influenceable: false,
      source_system: String(record["source_system"] ?? ""),
      summary: String(record["summary"] ?? ""),
      salience: (record["salience"] ?? "routine") as WorkerEvidence["salience"],
      why_notable: String(record["why_notable"] ?? ""),
      payload: (record["payload"] ?? {}) as Record<string, unknown>,
      ...(Array.isArray(record["supports"]) ? { supports: record["supports"] as string[] } : {}),
      ...(Array.isArray(record["weakens"]) ? { weakens: record["weakens"] as string[] } : {}),
      ...(typeof record["attacker_influenceable"] === "boolean"
        ? { attacker_influenceable: record["attacker_influenceable"] }
        : {}),
      ...(typeof record["attack_technique"] === "string" && record["attack_technique"] !== ""
        ? { attack_technique: record["attack_technique"] }
        : {}),
    };
  });
}

// The pool refused another call, which is nothing like a lead that emitted badly:
// the run spent what it was given and is over. Its own error because the hunt loop
// ends on it, the way compose, lead and tally all end on outcome.refusal.
export class BudgetRefused extends Error {}

// A failure is a result, not a throw: a worker that burned tokens and then died
// still spent them, and the controller records the gap either way.
export function workerDispatcher(options: AdapterOptions): WorkerDispatcher {
  return {
    dispatch: async (request: DispatchRequest): Promise<DispatchResult> => {
      const worker = options.spec.roles.workers[request.agent_id];
      if (worker === undefined) {
        return {
          dispatch_id: request.dispatch_id,
          evidence: [],
          failed: true,
          failure_reason: `no worker ${request.agent_id} in this arch`,
          cost_usd: 0,
        };
      }

      const before = options.harness.budget.spent.cost_usd;
      // The dispatch's own signal wins where it has one: an operator halting the
      // hunt mid-query is a narrower stop than the run losing its lease.
      const scoped = { ...options, ...(request.signal === undefined ? {} : { signal: request.signal }) };
      const task = renderDispatch(request, narrativeOf(options.spec));
      const outcome = await charged(
        options.harness,
        before,
        drain(streamTurn<WorkerAnswer, HuntKinds>(turnFor(scoped, request.agent_id, worker, task), options.harness)),
      );

      const cost_usd = spentOn(options.harness, before);
      if (outcome.value === null) {
        return {
          dispatch_id: request.dispatch_id,
          evidence: salvaged(outcome.calls),
          calls: callsOf(outcome.calls),
          failed: true,
          failure_reason: outcome.reason,
          cost_usd,
        };
      }
      const questions = Array.isArray(outcome.value.ips_to_check) ? outcome.value.ips_to_check : [];
      return {
        dispatch_id: request.dispatch_id,
        evidence: evidenceFrom(outcome.value),
        calls: callsOf(outcome.calls),
        ...(questions.length === 0 ? {} : { questions }),
        failed: false,
        failure_reason: "",
        cost_usd,
      };
    },
  };
}

// Total characters of tool output one dispatch may journal. Shared rather than
// per-call: one 500-row answer must not crowd the record of the calls after it.
const CALL_BUDGET = 16_000;

// The execution log the audit trail needs. wrapped.text is what the worker was
// actually shown -- already scrubbed, delimiter-safe and capped at result_cap by
// wrap() -- so journaling it cannot drift from what the model read. Arguments are
// the query itself, so they are what an analyst re-runs and are never dropped.
export function callsOf(attempts: readonly Attempt[]): ToolCall[] {
  if (attempts.length === 0) return [];
  const share = Math.max(1, Math.floor(CALL_BUDGET / attempts.length));
  return attempts.map(({ tool, args, wrapped }) => ({
    tool,
    arguments: clamp(args, share),
    result: clamp(wrapped.text, share),
  }));
}

interface CriticAnswer {
  benign_explanation?: string;
  benign_explanation_stands?: boolean;
  rationale?: string;
}

// The critic argues the benign case against the raw evidence. Its answer is
// inverted here: the hypothesis survives exactly when the benign case does not.
export function disconfirmationCritic(options: AdapterOptions): DisconfirmationCritic {
  const critic = role(options.spec, "critic");

  return {
    argueNull: async (check: NullCheckInput): Promise<NullCheckResult> => {
      const before = options.harness.budget.spent.cost_usd;
      const task = renderNullCheck(check);
      const outcome = await charged(
        options.harness,
        before,
        drain(streamTurn<CriticAnswer, HuntKinds>(turnFor(options, "critic", critic, task), options.harness)),
      );

      const cost_usd = spentOn(options.harness, before);
      // A critic that could not answer leaves the hypothesis standing rather than
      // proving it: an unargued null is not a null that failed.
      if (outcome.value === null) {
        return {
          survives: true,
          strongest_benign_explanation: "",
          rationale: `the critic did not answer: ${outcome.reason}`,
          cost_usd,
          model_id: options.harness.provider.model,
          prompt_version: options.spec.arch,
        };
      }

      return {
        survives: outcome.value.benign_explanation_stands !== true,
        strongest_benign_explanation: String(outcome.value.benign_explanation ?? ""),
        rationale: String(outcome.value.rationale ?? ""),
        cost_usd,
        model_id: options.harness.provider.model,
        prompt_version: options.spec.arch,
      };
    },
  };
}
