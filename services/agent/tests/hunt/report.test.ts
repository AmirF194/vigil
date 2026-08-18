// How a report reads, as opposed to what it contains. buildReport's gaps array is
// frozen by the ADR 0012 goldens, so everything here is presentation over the
// same records.
import { describe, expect, it } from "vitest";
import { groupedGaps, renderReport, type HuntReport, type VisibilityGap } from "../../workflows/hunt/report.js";
import { DEFAULT_BUDGETS } from "../../workflows/hunt/types.js";

// A fan-out hands every worker the same query_intent, so four failed workers
// printed one 300-character intent four times over and buried the reasons that
// actually differed.
const INTENT = "Determine reputation, ownership and ASN for 45.77.53.176";

const gap = (over: Partial<VisibilityGap> = {}): VisibilityGap => ({
  evidence_id: "ev-1",
  iteration: 2,
  summary: "worker failed: calls_exhausted",
  query_intent: INTENT,
  hypothesis_id: "h-cacab566",
  ...over,
});

const fannedOut: VisibilityGap[] = [
  gap({ evidence_id: "ev-1" }),
  gap({ evidence_id: "ev-2" }),
  gap({ evidence_id: "ev-3", summary: "worker failed: timeout" }),
  gap({ evidence_id: "ev-4" }),
];

describe("one row per question, not per worker", () => {
  it("collapses the workers that were asked the same thing", () => {
    const asked = groupedGaps(fannedOut);

    expect(asked).toHaveLength(1);
    expect(asked[0]!.workers).toBe(4);
  });

  it("keeps every distinct reason and drops the repeats", () => {
    expect(groupedGaps(fannedOut)[0]!.reasons).toEqual([
      "worker failed: calls_exhausted",
      "worker failed: timeout",
    ]);
  });

  it("keeps questions apart when they differ", () => {
    const other = gap({ evidence_id: "ev-9", query_intent: "something else" });
    expect(groupedGaps([...fannedOut, other])).toHaveLength(2);
  });

  it("keeps the same question apart across iterations", () => {
    const later = gap({ evidence_id: "ev-9", iteration: 3 });
    expect(groupedGaps([...fannedOut, later])).toHaveLength(2);
  });

  it("does not merge a gap that bears on no hypothesis into one that does", () => {
    const unattributed = gap({ evidence_id: "ev-9", hypothesis_id: null, query_intent: "" });
    expect(groupedGaps([unattributed, gap()])).toHaveLength(2);
  });
});

describe("the rendered visibility gaps", () => {
  const report = (gaps: VisibilityGap[]): HuntReport => ({
    hunt_id: "hunt-1",
    name: "threat-hunt",
    outcome: "budget_terminated",
    reason: "the budget refused another iteration",
    iterations: 2,
    cost_usd: 1.31,
    budgets: DEFAULT_BUDGETS,
    created_at: "2026-08-18T00:00:00.000Z",
    terminated_at: "2026-08-18T00:10:00.000Z",
    hypotheses: [],
    gaps,
    parked_hypotheses: [],
    backlog: [],
    checkpoints: [],
    suppressions: [],
    handoffs: [],
  });

  it("states the intent once however many workers failed on it", () => {
    const rendered = renderReport(report(fannedOut));
    expect(rendered.split(INTENT)).toHaveLength(2);
  });

  it("says how many workers were asked, so the count is not lost", () => {
    expect(renderReport(report(fannedOut))).toMatch(/\(4 workers\)/);
  });

  it("lists the reasons underneath rather than beside the intent", () => {
    const rendered = renderReport(report(fannedOut));
    expect(rendered).toMatch(/ {2}- worker failed: calls_exhausted/);
    expect(rendered).toMatch(/ {2}- worker failed: timeout/);
  });

  it("still says plainly when every query came back", () => {
    expect(renderReport(report([]))).toMatch(/None: every query the hunt wanted to run came back/);
  });
});
