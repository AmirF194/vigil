import type {
  Digest,
  DecisionResult,
  DispatchRequest,
  DispatchResult,
  NullCheckInput,
  NullCheckResult,
} from "./types.js";

// The Hunt Lead: one digest in, exactly one typed decision out. Implementations
// never touch the ledger — the controller applies, validates, and persists.
export interface DecisionProvider {
  decide(digest: Digest): Promise<DecisionResult>;
}

// The evidence source. Returns records rather than appending them, so a worker
// can never mutate hypothesis or budget state. Must be idempotent on dispatch_id.
export interface WorkerDispatcher {
  dispatch(request: DispatchRequest): Promise<DispatchResult>;
}

// Argues the strongest benign explanation against a hypothesis before it may be
// proven. Like a worker it returns a finding the controller appends as Hunt
// Evidence — it is a restoring force on the record, not a second decision-maker.
export interface DisconfirmationCritic {
  argueNull(check: NullCheckInput): Promise<NullCheckResult>;
}
