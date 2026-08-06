import type { Digest, DecisionResult, DispatchRequest, DispatchResult, Entity, WorkerEvidence } from "./types.js";

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

// Every chain that applies to one entity, run without a model. A function rather
// than an interface because depth, dedup and the per-round cap are ledger facts
// and stay with the controller.
export type Enricher = (entity: Entity) => Promise<WorkerEvidence[]>;
