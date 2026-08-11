import { describe, expect, it } from "vitest";
import { InProcessState } from "../../core/state.js";
import { asHarnessEvents, gunzipped, historicalRuns } from "../support/historical.js";
import { fold, LedgerError, projectionOf, type HuntKinds } from "../../workflows/hunt/ledger.js";

const RUNS = historicalRuns();

// Maps do not survive JSON, and the goldens were written from the file ledger's
// fold. Ordering is preserved: a Map keeps insertion order and so does this.
function comparable(projection: ReturnType<typeof fold>): unknown {
  return JSON.parse(
    JSON.stringify({
      ...projection,
      hypotheses: Object.fromEntries(projection.hypotheses),
      questions: Object.fromEntries(projection.questions),
      evidence: Object.fromEntries(projection.evidence),
      dispatches: Object.fromEntries(projection.dispatches),
      checkpoints: Object.fromEntries(projection.checkpoints),
    }),
  );
}

// Written by running the file ledger's own fold over the same fixture, with the
// same Map conversion applied, so this compares implementations and not shapes.
function golden(name: string): unknown {
  return JSON.parse(gunzipped(`${name}.projection.json.gz`));
}

describe("the fold survives the move to the harness ledger", () => {
  it("has ten historical ledgers to replay", () => {
    expect(RUNS).toHaveLength(10);
  });

  it.each(RUNS)("%s folds to the projection the file ledger produced", (name) => {
    const events = asHarnessEvents(gunzipped(`${name}.jsonl.gz`), name);
    expect(comparable(fold(events))).toEqual(golden(name));
  });

  it.each(RUNS)("%s folds identically when read back through the State seam", async (name) => {
    const events = asHarnessEvents(gunzipped(`${name}.jsonl.gz`), name);
    const state = new InProcessState<HuntKinds>();
    await state.append(name, 0, events.map(({ seq, ts, schema_version, ...rest }) => rest));

    expect(comparable(await projectionOf(state, name))).toEqual(comparable(fold(events)));
  });
});

describe("a ledger that is not one", () => {
  it("refuses a torn write rather than folding what it could parse", () => {
    const torn = gunzipped("torn.jsonl.corrupt.gz");
    expect(() => asHarnessEvents(torn, "torn")).toThrow(SyntaxError);
  });

  it("refuses a ledger that does not open with a run event", () => {
    const events = asHarnessEvents(gunzipped(`${RUNS[0]}.jsonl.gz`), RUNS[0]!).slice(1);
    expect(() => fold(events)).toThrow(LedgerError);
  });

  it("refuses a patch against a record the ledger never opened", () => {
    const events = asHarnessEvents(gunzipped(`${RUNS[0]}.jsonl.gz`), RUNS[0]!);
    events.push({
      ...events[0]!,
      seq: 999,
      kind: "patch",
      payload: { target: "hypothesis", id: "h-never", fields: { status: "proven" } },
    } as (typeof events)[number]);

    expect(() => fold(events)).toThrow(/unknown hypothesis h-never/);
  });
});
