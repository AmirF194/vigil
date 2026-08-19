import { openCheckpoint, type OpenCheckpoint } from "../../contracts/events.js";
import { fold, type HuntEvent, type Projection } from "./ledger.js";
import { citedTechniques, isGap } from "./strength.js";
import { renderReport, type HuntReport } from "./report.js";
import type {
  Budgets,
  EvidenceRecord,
  Handoff,
  HuntOutcome,
  HuntState,
  HuntStatus,
  Hypothesis,
  HypothesisStatus,
  LinkRelation,
  Salience,
} from "./types.js";

// What a reader outside this process is told about a hunt. A hunt has no steps to
// report progress against, so what it has tested and how each belief stands is it.
export interface HuntProjection {
  run_id: string;
  status: HuntStatus;
  outcome: HuntOutcome | null;
  reason: string;
  iteration: number;
  cost_usd: number;
  // What this run was actually granted, extensions included -- so a reader can
  // say how far through its budget the hunt is rather than only where it stands.
  budgets: Budgets;
  hypotheses: HypothesisStanding[];
  evidence_count: number;
  // The records themselves, newest first, not only how many there are. A reader
  // given a count has to wait for the finalized report to learn what a hunt found,
  // which is the whole of the run for as long as it is running. Capped, and
  // evidence_count above is the untruncated total so a reader can say so.
  evidence: EvidenceView[];
  open_checkpoint: OpenCheckpoint | null;
  // The deliverable, null until the hunt writes one. Rendered here because the
  // renderer is this side's: a reader that formatted the report itself would be a
  // second opinion about what a hunt found.
  report: HuntReport | null;
  report_markdown: string | null;
  // What the hunt asked someone else to take on, each carrying its own case file.
  handoffs: Handoff[];
}

// What a piece of evidence is, to somebody watching. The payload is left out: it
// is the worker's raw answer, sized for a model rather than a table, and salience
// plus why_notable are the parts a person reads.
export interface EvidenceView {
  evidence_id: string;
  iteration: number;
  source_system: string;
  summary: string;
  why_notable: string;
  salience: Salience;
  attack_technique: string | null;
  // Both flags matter to a reader for the same reason they matter to the gate: a
  // record an adversary could have written cannot carry a verdict alone.
  attacker_influenceable: boolean;
  instruction_like: boolean;
  provenance: string;
  // A blind spot rather than a finding. "We looked and it was not there" and "we
  // could not look" read identically until something separates them.
  is_gap: boolean;
  // Why the hunt could not look, for the operator only. It is kept off the summary
  // because that text reaches the lead as its most salient record, and a transport
  // error names this deployment's own plumbing rather than the estate.
  gap_detail: string | null;
  captured_at: string;
  // Which beliefs it bears on and how. Evidence attached to nothing is the case
  // worth seeing: it was gathered and then nobody linked it.
  bears_on: { hypothesis_id: string; relation: LinkRelation }[];
}

export interface HypothesisStanding {
  hypothesis_id: string;
  statement: string;
  status: HypothesisStatus;
  // What a belief was declared to test, which nothing declares any more: the
  // vocabulary gates a citation, it does not label a hypothesis. Kept because the
  // ledger's own record carries it, and a historical run has one.
  attack_technique: string | null;
  // What evidence bearing on this belief actually cited -- earned rather than
  // asserted, and the only technique claim on a hypothesis that anything checked.
  techniques_cited: string[];
  resolution_reason: string | null;
  // Where the belief came from: the definition, the caller, or the base rate.
  // A console that cannot say which is which cannot show an operator that the
  // thing they asked about is the thing being tested.
  provenance: string;
}

export function huntProjection(runId: string, events: readonly HuntEvent[]): HuntProjection {
  const view = fold(events);
  const answered = new Set(view.resolutions.map((resolution) => resolution.checkpoint_id));
  const open = [...view.checkpoints.values()].find((checkpoint) => !answered.has(checkpoint.checkpoint_id));
  const report = reportIn(events);

  return {
    run_id: runId,
    status: view.hunt.status,
    outcome: view.hunt.outcome,
    reason: why(view.hunt),
    iteration: view.hunt.iteration,
    cost_usd: view.hunt.cost_usd,
    budgets: view.hunt.budgets,
    hypotheses: [...view.hypotheses.values()].map((hypothesis) => standing(hypothesis, view)),
    evidence_count: view.evidence.size,
    // Ledger order reversed rather than sorted on captured_at: two records written
    // in the same millisecond carry the same timestamp, and the order they were
    // journaled in is the order they happened in.
    evidence: [...view.evidence.values()]
      .reverse()
      .slice(0, EVIDENCE_SHOWN)
      .map((record) => evidenceView(record, view.links)),
    open_checkpoint: open === undefined ? null : openCheckpoint(open),
    report,
    report_markdown: report === null ? null : renderReport(report, view),
    handoffs: events.filter((event) => event.kind === "handoff").map((event) => event.payload as Handoff),
  };
}

// The last one written. A run that resumed past its own terminal wrote a second,
// and the later one is the report of the hunt that actually happened.
function reportIn(events: readonly HuntEvent[]): HuntReport | null {
  const finalized = events.filter((event) => event.kind === "finalize");
  const last = finalized.at(-1);
  return last === undefined ? null : (last.payload as HuntReport);
}

// A parked hunt is asked why it stopped, a terminal one why it ended, and the two
// are different fields: a hunt that resumed and later ended still holds both.
function why(hunt: HuntState): string {
  return (hunt.status === "terminal" ? hunt.termination_reason : hunt.parked_reason) ?? "";
}

// Enough for a reader to see what a hunt has been doing without shipping a whole
// run's transcript on a five-second poll.
export const EVIDENCE_SHOWN = 50;

function evidenceView(
  record: EvidenceRecord,
  links: readonly { evidence_id: string; hypothesis_id: string; relation: LinkRelation }[],
): EvidenceView {
  return {
    evidence_id: record.evidence_id,
    iteration: record.iteration,
    source_system: record.source_system,
    summary: record.summary,
    why_notable: record.why_notable,
    salience: record.salience,
    attack_technique: record.attack_technique ?? null,
    attacker_influenceable: record.attacker_influenceable,
    instruction_like: record.instruction_like,
    provenance: record.provenance,
    is_gap: isGap(record),
    gap_detail: typeof record.payload["failure_reason"] === "string" ? record.payload["failure_reason"] : null,
    captured_at: record.captured_at,
    bears_on: links
      .filter((link) => link.evidence_id === record.evidence_id)
      .map((link) => ({ hypothesis_id: link.hypothesis_id, relation: link.relation })),
  };
}

function standing(hypothesis: Hypothesis, view: Projection): HypothesisStanding {
  const { hypothesis_id, statement, status, attack_technique, resolution_reason, provenance } = hypothesis;
  return {
    hypothesis_id,
    statement,
    status,
    attack_technique,
    techniques_cited: citedTechniques(view, hypothesis_id),
    resolution_reason,
    provenance,
  };
}
