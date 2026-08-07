import { scoredFrontier } from "./digest.js";
import type { Projection } from "./ledger.js";
import { DEFAULT_VERDICTS, type Termination, type Verdicts } from "./spec.js";
import type { Hypothesis, OpenQuestion } from "./types.js";

// Sub-floor leads ride along on a passing verdict so the caller can close them as
// backlog in one place. data_starved carries them for the same reason completed
// does: a hunt that could not see still owes the operator the threads it left.
export type TerminationVerdict =
  | { outcome: "completed"; park: OpenQuestion[] }
  | { outcome: "data_starved"; park: OpenQuestion[] }
  // Why the hunt must continue. A CONCLUDE that lands here is refused, not rejected.
  | { outcome: null; blocked_by: string };

// A hypothesis the hunt closed because it could not look, rather than because it
// looked and found nothing. Read off the strength snapshot the verdict wrote, not
// off the resolution_reason prose: the numbers are the record, the sentence is
// how it was said.
function gapLocked(hypothesis: Hypothesis, verdicts: Verdicts): boolean {
  const strength = hypothesis.evidence_strength;
  return (
    hypothesis.status === "inconclusive" &&
    strength !== undefined &&
    strength !== null &&
    strength.open_gaps >= verdicts.gap_lock_threshold
  );
}

// The controller's own answer to "may this hunt stop?", computed from the
// projection exactly like evidence_strength — never from anything the Hunt Lead
// said about being finished. CONCLUDE is a recommendation; this is the judge.
export function terminationVerdict(
  projection: Projection,
  iteration: number,
  config: Termination,
  verdicts: Verdicts = DEFAULT_VERDICTS,
): TerminationVerdict {
  const hypotheses = [...projection.hypotheses.values()];

  const active = hypotheses.find((hypothesis) => hypothesis.status === "active");
  if (active !== undefined) {
    return {
      outcome: null,
      blocked_by: `${active.hypothesis_id} is still active: ${active.statement}`,
    };
  }

  const frontier = scoredFrontier(projection, iteration);
  const above = frontier.find((entry) => entry.score >= config.priority_floor);
  if (above !== undefined) {
    return {
      outcome: null,
      blocked_by:
        `open question ${above.question.question_id} scores ${above.score}, at or above the priority ` +
        `floor of ${config.priority_floor}: ${above.question.question}`,
    };
  }

  // Everything left on the frontier is below the floor, so the hunt is done
  // spending on it and it becomes the backlog deliverable.
  const park = frontier.map((entry) => entry.question);

  // Outranks completed when both match: a hunt that could not see is not a hunt
  // that finished, and reporting it as finished is how a blind spot becomes a
  // clean bill of health.
  const starved =
    hypotheses.some((hypothesis) => gapLocked(hypothesis, verdicts)) &&
    !hypotheses.some((hypothesis) => hypothesis.status === "proven");

  return starved ? { outcome: "data_starved", park } : { outcome: "completed", park };
}
