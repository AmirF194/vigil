import { newId, type Ledger, type Projection } from "./ledger.js";
import type { Directive } from "./types.js";

// The four moments a hunt is allowed to stop and ask. Closed, because a class
// the controller has no policy for would raise a checkpoint nobody can answer.
export const CHECKPOINT_CLASSES = [
  // At hunt start, before any query runs.
  "hypothesis_approval",
  // Growth inside the declared tenant. A crossing of the tenant itself is
  // refused outright rather than asked about — see refuseCrossTenant in loop.ts.
  "scope_extension",
  // Before a hypothesis is marked proven, and before the hunt concludes.
  "verdict_review",
  // The Hunt Lead's own CHECKPOINT: it is asking for an adult, not emitting a verdict.
  "budget_anomaly",
] as const;

export type CheckpointClass = (typeof CHECKPOINT_CLASSES)[number];

// ask suspends the hunt until a human answers; auto answers it on the spot and
// journals that it did. Both leave the same record — an approval that is not on
// the ledger never happened.
export type CheckpointPolicy = "ask" | "auto";
export type Checkpoints = Record<CheckpointClass, CheckpointPolicy>;

// hypothesis_approval and verdict_review default to auto so a headless run — CI,
// --scripted, any programmatic startHunt — advances with no TTY and no pending
// prompt. The demo config flips them to ask, which is the same machinery with a
// human in it. The two that default to ask cannot fire unless something asks for
// them: scope_extension needs a declared scope to grow past, and budget_anomaly
// needs the Hunt Lead to emit CHECKPOINT.
export const DEFAULT_CHECKPOINTS: Checkpoints = {
  hypothesis_approval: "auto",
  scope_extension: "ask",
  verdict_review: "auto",
  budget_anomaly: "ask",
};

// The actor on a resolution nobody was asked for. Named rather than blank so a
// reader can tell policy from a person at a glance, and so grepping the ledger
// for what a human actually decided is one filter.
export const AUTO_ACTOR = "policy:auto";

export interface Checkpoint {
  checkpoint_id: string;
  class: CheckpointClass;
  raised_iteration: number;
  // What the operator is being asked, in their words not the controller's.
  question: string;
  // Everything the resolution needs to act without recomputing anything — for a
  // verdict review, the exact patch applyVerdict computed at VALIDATE time.
  payload: Record<string, unknown>;
  raised_at: string;
}

export interface Resolution {
  checkpoint_id: string;
  verdict: "approved" | "rejected";
  actor: string;
  reason: string;
  // The operator directive that carried it, when a human answered. Null on an
  // auto resolution: there was no input, only a policy.
  directive_id: string | null;
  resolved_at: string;
}

// Resolution is a separate event rather than a field on the checkpoint, because
// nothing on this ledger is ever rewritten — and separate from the directive
// stream because a policy resolution has no operator input behind it, and
// inventing a directive for one would put words in a human's mouth.
export function raiseCheckpoint(
  ledger: Ledger,
  checkpointClass: CheckpointClass,
  raisedIteration: number,
  question: string,
  payload: Record<string, unknown> = {},
): Checkpoint {
  const checkpoint: Checkpoint = {
    checkpoint_id: newId("cp", 4),
    class: checkpointClass,
    raised_iteration: raisedIteration,
    question,
    payload,
    raised_at: new Date().toISOString(),
  };
  ledger.append({ kind: "checkpoint", checkpoint });
  return checkpoint;
}

export function resolveCheckpoint(
  ledger: Ledger,
  checkpoint: Checkpoint,
  verdict: Resolution["verdict"],
  actor: string,
  reason: string,
  directive: Directive | null = null,
): Resolution {
  const resolution: Resolution = {
    checkpoint_id: checkpoint.checkpoint_id,
    verdict,
    actor,
    reason,
    directive_id: directive?.directive_id ?? null,
    resolved_at: new Date().toISOString(),
  };
  ledger.append({ kind: "resolution", resolution });
  return resolution;
}

export function resolutionOf(projection: Projection, checkpointId: string): Resolution | undefined {
  // First wins: a second answer to a settled question is a duplicate, not a
  // change of mind, and reversing a decision is its own directive.
  return projection.resolutions.find((resolution) => resolution.checkpoint_id === checkpointId);
}

// Raised minus resolved, folded like everything else — which is what makes a
// pending checkpoint survive process death and come back from the JSONL alone.
export function pendingCheckpoints(projection: Projection): Checkpoint[] {
  return [...projection.checkpoints.values()].filter(
    (checkpoint) => resolutionOf(projection, checkpoint.checkpoint_id) === undefined,
  );
}

export function pendingOfClass(projection: Projection, checkpointClass: CheckpointClass): Checkpoint | undefined {
  return pendingCheckpoints(projection).find((checkpoint) => checkpoint.class === checkpointClass);
}
