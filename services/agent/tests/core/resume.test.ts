import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { RunJob } from "../../contracts/job.js";
import { InProcessLeases } from "../../core/leases.js";
import { InProcessState } from "../../core/state.js";
import { advance, resolveSpec, specOf } from "../../worker.js";
import { scriptedHarness } from "../support/scripted-harness.js";
import type { ScriptedTurn } from "../support/scripted-provider.js";

const CONCLUDE: ScriptedTurn[] = [{ calls: [] }, { emit: { action: "CONCLUDE", rationale: "done", evidence_citations: [] } }];

const FIXTURES = join(import.meta.dirname, "..", "fixtures");
const RUN = "7d3c2d3e-0000-4000-8000-000000000619";

let config: string;
let leases: InProcessLeases;
beforeEach(() => {
  leases = new InProcessLeases();
  config = join(mkdtempSync(join(tmpdir(), "vigil-resume-")), "vigil.config.yaml");
  copyFileSync(join(FIXTURES, "hunt.config.yaml"), config);
});

// The registry resolves the arch, so the request names only the two layers an
// operator supplies per run.
function startJob(run_kind: RunJob["run_kind"] = "hunt", overrides?: Record<string, unknown>): Extract<RunJob, { reason: "start" }> {
  const tighten = overrides === undefined ? {} : { overrides };
  return {
    schema_version: 1,
    run_id: RUN,
    run_kind,
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "test",
    reason: "start",
    request: { arch: "", playbook: join(FIXTURES, "hunt.playbook.yaml"), config, prompt: "go", ...tighten },
  };
}

function resumeJob(): RunJob {
  return {
    schema_version: 1,
    run_id: RUN,
    run_kind: "hunt",
    tenant_id: null,
    enqueued_at: new Date().toISOString(),
    enqueued_by: "watchdog",
    reason: "resume",
  };
}

function rewriteBudget(iterations: number): void {
  writeFileSync(config, readFileSync(config, "utf8").replace("max_calls: 12", `max_calls: ${iterations}`), "utf8");
}

describe("resolving a run", () => {
  it("routes the run kind through the registry to its arch file", async () => {
    expect((await resolveSpec(startJob())).arch).toBe("threathunt");
  });

  // Startup, not runtime: the kind is resolved before the ledger opens.
  it("refuses a run kind no arch is registered for", async () => {
    await expect(resolveSpec(startJob("tally"))).rejects.toThrow(/no architecture is registered for run_kind tally/);
  });

  it("lets an explicit arch path override the registry's default", async () => {
    const job = startJob();
    job.request.arch = join(import.meta.dirname, "..", "..", "arch", "threathunt.yaml");
    expect((await resolveSpec(job)).dispatch.max_workers).toBe(4);
  });

  // Per-run, so it rides the job rather than the playbook the reference names --
  // which is a definition every run of it shares.
  it("carries what this run asked about into the sections the workflow reads", async () => {
    const job = startJob();
    job.request.hypotheses = ["lateral movement over SMB"];

    expect((await resolveSpec(job)).sections["operator_hypotheses"]).toEqual(["lateral movement over SMB"]);
  });

  it("leaves the sections alone when the run asked about nothing", async () => {
    expect((await resolveSpec(startJob())).sections["operator_hypotheses"]).toBeUndefined();
  });
});

describe("the arch a run started under is journaled", () => {
  it("writes the resolved spec into the run event", async () => {
    const state = new InProcessState();
    await advance(state, leases, startJob(), scriptedHarness(CONCLUDE));

    const opened = await specOf(state, RUN);
    expect(opened?.arch).toBe("threathunt");
    // The turn count is the one that binds; max_calls is a backstop the hunt
    // raises off it, so this asserts the relationship rather than the arithmetic
    // -- the multiplier is a property of this arch's fan-out, not of the budget.
    // Cast because the harness's budget type has no turn count -- that is the
    // whole point of the split, and the journaled spec carries the hunt's.
    const budgets = opened?.budgets as unknown as { max_iterations: number; max_calls: number; max_cost_usd: number };
    expect(budgets.max_iterations).toBe(8);
    expect(budgets.max_calls).toBeGreaterThan(budgets.max_iterations);
    expect(budgets.max_cost_usd).toBe(5);
  });

  // The whole point of journaling it: the file moved, the run did not.
  it("keeps a resumed run on the spec it opened with after the config is edited", async () => {
    const state = new InProcessState();
    await advance(state, leases, startJob(), scriptedHarness(CONCLUDE));

    const opened = (await specOf(state, RUN))?.budgets.max_calls;

    rewriteBudget(99);
    expect((await resolveSpec(startJob())).budgets.max_calls).toBe(99);

    // Not 99: the run keeps the ceiling it opened with, whatever the file says now.
    await advance(state, leases, resumeJob(), scriptedHarness(CONCLUDE));
    expect((await specOf(state, RUN))?.budgets.max_calls).toBe(opened);
  });

  it("refuses to resume a run that has no ledger", async () => {
    await expect(advance(new InProcessState(), leases, resumeJob(), scriptedHarness(CONCLUDE))).rejects.toThrow(/has no ledger/);
  });
});

describe("what the caller enqueuing a run may tighten", () => {
  it("lowers a ceiling the config set", async () => {
    const spec = await resolveSpec(startJob("hunt", { budgets: { max_cost_usd: 0.5 } }));
    expect(spec.budgets.max_cost_usd).toBe(0.5);
  });

  it("leaves the ceilings it did not name", async () => {
    const plain = await resolveSpec(startJob());
    const tightened = await resolveSpec(startJob("hunt", { budgets: { max_cost_usd: 0.5 } }));
    expect(tightened.budgets.max_calls).toBe(plain.budgets.max_calls);
  });

  it("refuses a ceiling of zero, which is a run that cannot start rather than one that cannot overspend", async () => {
    await expect(resolveSpec(startJob("hunt", { budgets: { max_cost_usd: 0 } }))).rejects.toThrow(/must be a positive number/);
  });

  it("refuses an unknown budget key rather than accepting a knob nothing reads", async () => {
    await expect(resolveSpec(startJob("hunt", { budgets: { max_dollars: 5 } }))).rejects.toThrow(/unknown overrides.budgets key/);
  });

  it("refuses to override anything but budgets and runtime", async () => {
    // The deployment's ceilings are the deployment's; the arch is not negotiable.
    await expect(resolveSpec(startJob("hunt", { roles: {} }))).rejects.toThrow(/may name budgets or runtime/);
  });
});
