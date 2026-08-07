import type { Projection } from "./ledger.js";
import { isGap } from "./strength.js";
import type { Budgets, EvidenceStrength, HuntOutcome, HypothesisStatus } from "./types.js";

// The deliverable, derived. A hunt that ends without one is a hunt that never
// happened — and "we found nothing, here is what we could not see" is an answer,
// not a failure. Built from the projection alone, so it replays identically and
// can be rebuilt from the JSONL long after the process that ran the hunt is gone.

export interface HypothesisVerdict {
  hypothesis_id: string;
  statement: string;
  status: HypothesisStatus;
  resolution_reason: string | null;
  evidence_strength: EvidenceStrength | null;
}

export interface VisibilityGap {
  evidence_id: string;
  iteration: number;
  summary: string;
  // What went unanswered and for which claim, so a gap reads as a question the
  // hunt could not put, rather than as a tool that misbehaved.
  query_intent: string;
  hypothesis_id: string | null;
}

export interface BacklogQuestion {
  question_id: string;
  question: string;
  reason: string;
}

export interface HuntReport {
  hunt_id: string;
  name: string;
  outcome: HuntOutcome | null;
  reason: string;
  iterations: number;
  cost_usd: number;
  budgets: Budgets;
  created_at: string;
  terminated_at: string | null;
  hypotheses: HypothesisVerdict[];
  gaps: VisibilityGap[];
  // Parked hypotheses and the leads nobody pulled: the work this hunt did not do,
  // named so the next one can pick it up.
  parked_hypotheses: HypothesisVerdict[];
  backlog: BacklogQuestion[];
}

export function reportPath(ledgerPath: string): string {
  return `${ledgerPath.replace(/\.jsonl$/, "")}.report.md`;
}

function verdictOf(hypothesis: {
  hypothesis_id: string;
  statement: string;
  status: HypothesisStatus;
  resolution_reason: string | null;
  evidence_strength?: EvidenceStrength | null;
}): HypothesisVerdict {
  return {
    hypothesis_id: hypothesis.hypothesis_id,
    statement: hypothesis.statement,
    status: hypothesis.status,
    resolution_reason: hypothesis.resolution_reason,
    evidence_strength: hypothesis.evidence_strength ?? null,
  };
}

export function buildReport(projection: Projection): HuntReport {
  const { hunt } = projection;
  const hypotheses = [...projection.hypotheses.values()].map(verdictOf);

  const gaps = [...projection.evidence.values()]
    .filter(isGap)
    .map((record) => {
      const dispatch = projection.dispatches.get(record.dispatch_id ?? "");
      return {
        evidence_id: record.evidence_id,
        iteration: record.iteration,
        summary: record.summary,
        query_intent: dispatch?.query_intent ?? "",
        hypothesis_id: dispatch?.target_hypothesis_id ?? null,
      };
    })
    .sort((a, b) => (a.iteration === b.iteration ? a.evidence_id.localeCompare(b.evidence_id) : a.iteration - b.iteration));

  return {
    hunt_id: hunt.hunt_id,
    name: hunt.name,
    outcome: hunt.outcome,
    reason: hunt.termination_reason ?? "",
    iterations: hunt.iteration,
    cost_usd: hunt.cost_usd,
    budgets: hunt.budgets,
    created_at: hunt.created_at,
    terminated_at: hunt.terminated_at,
    hypotheses,
    gaps,
    parked_hypotheses: hypotheses.filter((hypothesis) => hypothesis.status === "parked"),
    backlog: [...projection.questions.values()]
      .filter((question) => question.status === "parked")
      .map((question) => ({
        question_id: question.question_id,
        question: question.question,
        reason: question.closed_reason ?? "",
      })),
  };
}

const STATUS_ORDER: Record<HypothesisStatus, number> = {
  proven: 0,
  disproven: 1,
  inconclusive: 2,
  parked: 3,
  active: 4,
};

function strengthLine(strength: EvidenceStrength): string {
  return [
    `${strength.corroborating_sources} corroborating source system(s)`,
    `${strength.contradicting_records} contradicting record(s)`,
    `${strength.open_gaps} open gap(s)`,
    strength.attacker_influenceable_only ? "support is attacker-influenceable only" : "support is not attacker-authored alone",
    strength.survived_disconfirmation ? "survived disconfirmation" : "did not survive disconfirmation",
  ].join(", ");
}

// The one line an operator reads first. A hunt that proved nothing says so
// plainly and says why — an unread report is the same as no report.
function headline(report: HuntReport): string {
  const proven = report.hypotheses.filter((hypothesis) => hypothesis.status === "proven");
  if (proven.length > 0) {
    return `${proven.length} hypothesis(es) reached a verdict of proven; each survived the argue-the-null pass.`;
  }
  if (report.outcome === "data_starved") {
    return (
      `Nothing was proven, and the hunt could not see well enough to say so honestly: ` +
      `${report.gaps.length} visibility gap(s) closed hypotheses that were never cleared.`
    );
  }
  if (report.outcome === "completed") {
    return "Nothing was proven. The hunt reached the end of its frontier without finding support that cleared the bar.";
  }
  return `Nothing was proven; the hunt ended ${report.outcome ?? "without an outcome"} with its hypotheses unresolved.`;
}

export function renderReport(report: HuntReport): string {
  const lines: string[] = [
    `# Hunt report — ${report.name}`,
    "",
    `- **Outcome:** ${report.outcome ?? "not terminated"}`,
    `- **Hunt:** ${report.hunt_id}`,
    `- **Iterations:** ${report.iterations} of ${report.budgets.max_iterations}`,
    `- **Cost:** $${report.cost_usd.toFixed(4)} of $${report.budgets.max_cost_usd.toFixed(2)}`,
    `- **Started:** ${report.created_at}`,
    `- **Ended:** ${report.terminated_at ?? "still running"}`,
  ];
  if (report.reason) lines.push(`- **Why it ended:** ${report.reason}`);
  lines.push("", headline(report), "", "## Verdicts", "");

  const ordered = [...report.hypotheses].sort(
    (a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.hypothesis_id.localeCompare(b.hypothesis_id),
  );
  for (const hypothesis of ordered) {
    lines.push(`### ${hypothesis.hypothesis_id} — ${hypothesis.status}`, "", hypothesis.statement, "");
    if (hypothesis.resolution_reason) lines.push(`_${hypothesis.resolution_reason}_`, "");
    if (hypothesis.evidence_strength !== null) {
      lines.push(`Evidence strength at verdict: ${strengthLine(hypothesis.evidence_strength)}.`, "");
    }
  }

  lines.push(`## Visibility gaps (${report.gaps.length})`, "");
  if (report.gaps.length === 0) {
    lines.push("None: every query the hunt wanted to run came back.", "");
  } else {
    lines.push("Questions the hunt could not answer. Each is a blind spot, not a finding.", "");
    for (const gap of report.gaps) {
      const bearing = gap.hypothesis_id === null ? "unattributed" : gap.hypothesis_id;
      lines.push(`- iteration ${gap.iteration} (${bearing}): ${gap.query_intent || gap.summary} — ${gap.summary}`);
    }
    lines.push("");
  }

  lines.push("## Parked backlog", "");
  if (report.parked_hypotheses.length === 0 && report.backlog.length === 0) {
    lines.push("Nothing parked: no hypothesis was abandoned and no lead was left on the frontier.", "");
  }
  if (report.parked_hypotheses.length > 0) {
    lines.push("### Hypotheses", "");
    for (const hypothesis of report.parked_hypotheses) {
      lines.push(`- ${hypothesis.statement} — ${hypothesis.resolution_reason ?? "parked"}`);
    }
    lines.push("");
  }
  if (report.backlog.length > 0) {
    lines.push("### Open questions", "");
    for (const question of report.backlog) {
      lines.push(`- ${question.question}${question.reason ? ` — ${question.reason}` : ""}`);
    }
    lines.push("");
  }

  return `${lines.join("\n").trimEnd()}\n`;
}
