import type { Projection } from "./ledger.js";
import type { Verdicts } from "./spec.js";
import type { DispatchRecord, EvidenceRecord, EvidenceStrength, LinkRelation } from "./types.js";

export const NULL_CHECK_PROVENANCE = "null_check";
export const CRITIC_SOURCE_SYSTEM = "critic";
export const UNDECLARED_SOURCE = "undeclared";

// The one gap reader over evidence. Gap *counting* is off the dispatch log
// below; this is for the operator-facing view of what could not be run.
export function isGap(record: EvidenceRecord): boolean {
  return record.provenance === "tool_failure";
}

// What went unanswered, not how many times it failed: three retries of one query
// are one blind spot. The intent is the key when no lead owns the dispatch.
function gapKey(dispatch: DispatchRecord): string {
  return dispatch.question_id ?? dispatch.query_intent;
}

// A gap belongs to the hypothesis the dispatch was serving, and stops being a
// gap once the same question is answered — being unable to look once is not a
// permanent blind spot.
export function openGaps(projection: Projection, hypothesisId: string): number {
  const answered = new Set<string>();
  const unanswered = new Set<string>();

  for (const dispatch of projection.dispatches.values()) {
    if (dispatch.target_hypothesis_id !== hypothesisId) continue;
    if (dispatch.status === "complete") answered.add(gapKey(dispatch));
    if (dispatch.status === "failed") unanswered.add(gapKey(dispatch));
  }

  return [...unanswered].filter((key) => !answered.has(key)).length;
}

// Read off the appended record rather than the critic's return value, so a
// verdict rests on the ledger and replays to the same answer.
function nullChecksFor(projection: Projection, hypothesisId: string): EvidenceRecord[] {
  return [...projection.evidence.values()].filter(
    (record) => record.provenance === NULL_CHECK_PROVENANCE && record.payload["hypothesis_id"] === hypothesisId,
  );
}

// A verdict rests on a *current* argument. The latest null check must have
// stood, and it must have been argued against everything now linked: an earlier
// survival says nothing about evidence that arrived after it, and a hypothesis
// whose benign story has since been re-argued and won must not coast on it.
function survivedDisconfirmation(projection: Projection, hypothesisId: string, linked: readonly string[]): boolean {
  const checks = nullChecksFor(projection, hypothesisId);
  const latest = checks[checks.length - 1];
  if (latest === undefined || latest.payload["survives"] !== true) return false;

  const argued = new Set((latest.payload["argued_evidence_ids"] as string[] | undefined) ?? []);
  return linked.every((evidenceId) => argued.has(evidenceId));
}

export function evidenceStrength(projection: Projection, hypothesisId: string): EvidenceStrength {
  const linked = (relation: LinkRelation): EvidenceRecord[] =>
    projection.links
      .filter((link) => link.hypothesis_id === hypothesisId && link.relation === relation)
      .map((link) => projection.evidence.get(link.evidence_id))
      .filter((record): record is EvidenceRecord => record !== undefined);

  const supporting = linked("supports");
  const contradicting = linked("weakens");
  const allLinked = [...supporting, ...contradicting].map((record) => record.evidence_id);

  return {
    // Distinct systems: ten records out of one tool are one system agreeing with
    // itself, which is not corroboration.
    corroborating_sources: new Set(supporting.map((record) => record.source_system)).size,
    contradicting_records: contradicting.length,
    open_gaps: openGaps(projection, hypothesisId),
    // Vacuously true with no support at all, which is the fail-closed answer.
    attacker_influenceable_only: supporting.every((record) => record.attacker_influenceable),
    survived_disconfirmation: survivedDisconfirmation(projection, hypothesisId, allLinked),
  };
}

// Every predicate a verdict fails, so "not proven" is never a bare no.
export function unmetPredicates(strength: EvidenceStrength, verdicts: Verdicts): string[] {
  const unmet: string[] = [];
  if (!strength.survived_disconfirmation) {
    unmet.push("the strongest benign explanation was not ruled out against everything now linked to it");
  }
  if (strength.corroborating_sources < verdicts.min_corroborating_sources) {
    unmet.push(
      `${strength.corroborating_sources} corroborating source system(s), ${verdicts.min_corroborating_sources} required`,
    );
  }
  if (strength.attacker_influenceable_only) {
    unmet.push("every supporting record sits in a field an adversary could have written");
  }
  if (strength.open_gaps >= verdicts.gap_lock_threshold) {
    unmet.push(`${strength.open_gaps} open visibility gap(s) bear on it`);
  }
  return unmet;
}
