// Type-only, so the cycle with spec.ts is erased at compile time.
import type { HuntSpec } from "./spec.js";

export const SCHEMA_VERSION = 1;

export type DecisionAction =
  | "INVESTIGATE"
  | "EXPAND"
  | "PIVOT"
  | "DEEPEN"
  | "ABANDON"
  | "VALIDATE"
  | "CHECKPOINT"
  | "CONCLUDE"
  | "HANDOFF_IR";

export const DECISION_ACTIONS = [
  "INVESTIGATE",
  "EXPAND",
  "PIVOT",
  "DEEPEN",
  "ABANDON",
  "VALIDATE",
  "CHECKPOINT",
  "CONCLUDE",
  "HANDOFF_IR",
] as const satisfies readonly DecisionAction[];

// These rest on a judgement about existing evidence, so an uncited one is unauditable.
export const ACTIONS_REQUIRING_CITATION: ReadonlySet<DecisionAction> = new Set([
  "ABANDON",
  "VALIDATE",
  "PIVOT",
]);

// What the controller actually does something about. An arch may only declare
// these: a verb that is merely in the vocabulary would burn an iteration and
// change nothing, and the Hunt Lead would keep choosing it. Grows as the
// controller learns a verb, which is the only place this list may change.
export const EXECUTABLE_ACTIONS = ["INVESTIGATE", "VALIDATE", "CONCLUDE"] as const satisfies readonly DecisionAction[];

export type HuntStatus = "pending_approval" | "active" | "terminal";

export type HuntOutcome =
  | "completed"
  | "budget_terminated"
  | "data_starved"
  | "aborted";

// Higher wins. An outcome on the record is never downgraded, so a late
// "completed" cannot relabel a hunt that was aborted or ran out of budget.
export const OUTCOME_PRECEDENCE: Record<HuntOutcome, number> = {
  completed: 0,
  budget_terminated: 1,
  data_starved: 2,
  aborted: 3,
};

export type HypothesisStatus =
  | "active"
  | "proven"
  | "disproven"
  | "inconclusive"
  | "parked";

export type Salience = "routine" | "notable" | "anomalous";
export type LinkRelation = "supports" | "weakens";

export interface Budgets {
  max_iterations: number;
  max_cost_usd: number;
}

export const DEFAULT_BUDGETS: Budgets = { max_iterations: 20, max_cost_usd: 25.0 };

export interface Entity {
  type: string;
  value: string;
}

// Human input, and the one thing in the ledger that is direction rather than
// data. Applied by the controller at an iteration boundary, never written as state.
export type DirectiveKind = "note" | "lead" | "abort";

export interface Directive {
  directive_id: string;
  actor: string;
  kind: DirectiveKind;
  text: string;
  created_at: string;
}

export interface HuntState {
  hunt_id: string;
  name: string;
  // Resolved once at hunt start: resume needs no YAML, and editing an arch file
  // mid-run cannot silently change what a hunt in flight was told.
  spec: HuntSpec;
  status: HuntStatus;
  outcome: HuntOutcome | null;
  iteration: number;
  cost_usd: number;
  budgets: Budgets;
  scope: Record<string, unknown>;
  narrative: string;
  created_at: string;
  terminated_at: string | null;
}

export interface Hypothesis {
  hypothesis_id: string;
  statement: string;
  status: HypothesisStatus;
  attack_technique: string | null;
  provenance: string;
  resolution_reason: string | null;
  // What the numbers were at verdict time. Absent while the hypothesis is
  // active; a verdict that cannot be re-read is not auditable.
  evidence_strength?: EvidenceStrength | null;
}

// Controller-computed from deterministic features of the ledger, never a model
// self-report, and the only thing a verdict is allowed to gate on.
export interface EvidenceStrength {
  corroborating_sources: number;
  contradicting_records: number;
  open_gaps: number;
  attacker_influenceable_only: boolean;
  survived_disconfirmation: boolean;
}

export interface OpenQuestion {
  question_id: string;
  question: string;
  status: "open" | "closed";
  spawning_evidence_id: string | null;
  // The hypothesis this lead was opened in service of. Without it a lead that
  // fails is a gap belonging to nothing, and no hypothesis is ever gap-locked.
  hypothesis_id: string | null;
}

export interface EvidenceRecord {
  evidence_id: string;
  dispatch_id: string | null;
  iteration: number;
  source_system: string;
  summary: string;
  payload: Record<string, unknown>;
  salience: Salience;
  why_notable: string;
  provenance: string;
  // Set when an adversary could have written the value; an ABANDON must not rest on it alone.
  attacker_influenceable: boolean;
  instruction_like: boolean;
  captured_at: string;
}

export interface EvidenceLink {
  evidence_id: string;
  hypothesis_id: string;
  relation: LinkRelation;
}

// One tool invocation and what came back, capped. The execution log the audit
// trail needs: a summary is the worker's account of the data, this is the data.
export interface ToolCall {
  tool: string;
  arguments: string;
  result: string;
}

export interface DispatchRecord {
  dispatch_id: string;
  iteration: number;
  agent_id: string;
  status: "pending" | "complete" | "failed";
  query_intent: string;
  target_hypothesis_id: string | null;
  // The lead this dispatch took, so an interrupted one can hand it back.
  question_id: string | null;
  failure_reason: string | null;
  // What the worker spent and what it ran. Both land on the completion patch,
  // since the row is journaled before the worker starts.
  cost_usd: number;
  calls: ToolCall[];
}

export interface Decision {
  action: DecisionAction;
  rationale: string;
  // Recorded for calibration only. Nothing gates on it.
  stated_confidence?: number | null;
  evidence_citations?: string[];
  target_hypothesis_id?: string | null;
  worker_agent_id?: string | null;
  query_intent?: string;
}

export interface DecisionResult {
  decision: Decision;
  model_id: string;
  prompt_version: string;
  cost_usd: number;
  // Emissions the controller rejected before accepting one, kept so re-prompts stay visible.
  rejected_attempts?: string[];
}

export interface DecisionRecord extends DecisionResult {
  decision_id: string;
  iteration: number;
  digest_presented: Digest;
  created_at: string;
}

export interface HypothesisView {
  hypothesis_id: string;
  statement: string;
  status: HypothesisStatus;
}

export interface EvidenceView {
  evidence_id: string;
  source_system: string;
  summary: string;
  salience: Salience;
  why_notable: string;
  instruction_like: boolean;
}

export interface Digest {
  hunt_id: string;
  hunt_name: string;
  iteration: number;
  narrative: string;
  hypotheses: HypothesisView[];
  recent_evidence: EvidenceView[];
  // Strongest counter-evidence per active hypothesis; one-sidedness is itself a finding.
  weakens: Record<string, EvidenceView[]>;
  open_questions: string[];
  budget_remaining: { iterations: number; cost_usd: number };
  // Operator instructions. Unlike evidence, these are direction.
  directives: string[];
  notes: string[];
}

export interface DispatchRequest {
  dispatch_id: string;
  hunt_id: string;
  agent_id: string;
  query_intent: string;
  // The one lead or hypothesis this worker owns when an iteration fans out.
  focus: string;
  target_hypothesis_id: string | null;
  scope: Record<string, unknown>;
}

// supports/weakens name the hypotheses this record bears on; the controller
// turns them into links, so a worker still never writes state itself.
export type WorkerEvidence = Omit<
  EvidenceRecord,
  "evidence_id" | "dispatch_id" | "iteration" | "captured_at"
> & { supports?: string[]; weakens?: string[] };

export interface DispatchResult {
  dispatch_id: string;
  evidence: WorkerEvidence[];
  // New threads the work opened up — the frontier of the search.
  questions?: string[];
  failed: boolean;
  failure_reason: string;
  // Required, including on the failure path: a worker that burned tokens and
  // then died still spent them, and hunt.cost_usd is the budget counter.
  cost_usd: number;
  calls?: ToolCall[];
}

export interface NullCheckEvidence {
  relation: LinkRelation;
  record: EvidenceRecord;
}

// What the disconfirmation critic is given: the claim and the raw payloads
// behind it. Deliberately not the digest — the digest is the Hunt Lead's own
// compression of its own case, and an argument built inside it is not independent.
export interface NullCheckInput {
  hypothesis_id: string;
  statement: string;
  narrative: string;
  evidence: NullCheckEvidence[];
}

export interface NullCheckResult {
  // Whether the hypothesis is left standing. false means the benign explanation
  // accounts for the evidence, so nothing here has been shown.
  survives: boolean;
  strongest_benign_explanation: string;
  rationale: string;
  cost_usd: number;
  model_id: string;
  prompt_version: string;
}

export interface IterationResult {
  hunt_id: string;
  iteration: number;
  action: DecisionAction;
  decision_id: string;
  cost_usd: number;
  evidence_appended: number;
  hunt_status: HuntStatus;
  hunt_outcome: HuntOutcome | null;
  note: string;
}
