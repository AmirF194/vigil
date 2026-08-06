import type { Projection } from "./ledger.js";
import type { Verdicts } from "./spec.js";
import type { EvidenceRecord, EvidenceStrength, LinkRelation } from "./types.js";

export const NULL_CHECK_PROVENANCE = "null_check";
export const CRITIC_SOURCE_SYSTEM = "critic";

// The one gap reader. Richer gap recording lands later; when it does, this is
// the only function that has to learn about it.
export function isGap(record: EvidenceRecord): boolean {
  return record.provenance === "tool_failure";
}

// Read off the appended record rather than the critic's return value, so a
// verdict rests on the ledger and replays to the same answer.
function survivedNullCheck(record: EvidenceRecord, hypothesisId: string): boolean {
  return (
    record.provenance === NULL_CHECK_PROVENANCE &&
    record.payload["hypothesis_id"] === hypothesisId &&
    record.payload["survives"] === true
  );
}

// A gap belongs to the hypothesis whose question went unanswered — the dispatch
// that failed knows which one that was.
function gapTarget(projection: Projection, record: EvidenceRecord): string | null {
  if (record.dispatch_id === null) return null;
  return projection.dispatches.get(record.dispatch_id)?.target_hypothesis_id ?? null;
}

export function evidenceStrength(projection: Projection, hypothesisId: string): EvidenceStrength {
  const linked = (relation: LinkRelation): EvidenceRecord[] =>
    projection.links
      .filter((link) => link.hypothesis_id === hypothesisId && link.relation === relation)
      .map((link) => projection.evidence.get(link.evidence_id))
      .filter((record): record is EvidenceRecord => record !== undefined);

  const supporting = linked("supports");
  const records = [...projection.evidence.values()];

  return {
    // Distinct systems: ten records out of one tool are one system agreeing with
    // itself, which is not corroboration.
    corroborating_sources: new Set(supporting.map((record) => record.source_system)).size,
    contradicting_records: linked("weakens").length,
    open_gaps: records.filter((record) => isGap(record) && gapTarget(projection, record) === hypothesisId).length,
    // Vacuously true with no support at all, which is the fail-closed answer.
    attacker_influenceable_only: supporting.every((record) => record.attacker_influenceable),
    survived_disconfirmation: records.some((record) => survivedNullCheck(record, hypothesisId)),
  };
}

// Every predicate a verdict fails, so "not proven" is never a bare no.
export function unmetPredicates(strength: EvidenceStrength, verdicts: Verdicts): string[] {
  const unmet: string[] = [];
  if (!strength.survived_disconfirmation) {
    unmet.push("the strongest benign explanation was not ruled out");
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

export function isProven(strength: EvidenceStrength, verdicts: Verdicts): boolean {
  return unmetPredicates(strength, verdicts).length === 0;
}
