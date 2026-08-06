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

export interface HuntState {
  hunt_id: string;
  name: string;
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
}

export interface OpenQuestion {
  question_id: string;
  question: string;
  status: "open" | "closed";
  spawning_evidence_id: string | null;
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

export interface DispatchRecord {
  dispatch_id: string;
  iteration: number;
  agent_id: string;
  status: "pending" | "complete" | "failed";
  query_intent: string;
  target_hypothesis_id: string | null;
  failure_reason: string | null;
}

export interface Decision {
  action: DecisionAction;
  rationale: string;
  // Recorded for calibration only. Nothing gates on it.
  stated_confidence?: number | null;
  evidence_citations?: string[];
  target_hypothesis_id?: string | null;
  target_question?: string | null;
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
