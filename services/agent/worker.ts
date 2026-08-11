import { Worker } from "bullmq";
import pg from "pg";
import { archFor } from "./arch/registry.js";
import { RUN_QUEUE, type RunJob } from "./contracts/job.js";
import type { NewEvent, RunPayload } from "./contracts/events.js";
import type { State } from "./core/seams.js";
import { buildSpec, type RunSpec } from "./core/spec.js";
import { LedgerRepository } from "./ledger/repository.js";

type StartJob = Extract<RunJob, { reason: "start" }>;

// The registry is the only resolver, and it runs before the ledger opens: an
// unregistered run kind fails at startup rather than seven iterations in.
export function resolveSpec(job: StartJob): RunSpec {
  const entry = archFor(job.run_kind);
  const arch = job.request.arch === "" ? entry.arch : job.request.arch;
  return buildSpec({ arch, playbook: job.request.playbook, config: job.request.config }, entry.actions);
}

// The spec a run started under, read off the ledger. A resume re-reads no file,
// so an edited arch or config cannot reach a run already in flight.
export async function specOf(state: State, runId: string): Promise<RunSpec | null> {
  const opened = (await state.read(runId)).find((event) => event.kind === "run");
  return opened === undefined ? null : ((opened.payload as RunPayload).spec as RunSpec);
}

// Resolves the three layers, journals what it resolved, and ends. The loop that
// spends the budget it just wrote down is the next slice.
export async function advance(state: State, job: RunJob): Promise<void> {
  const latest = await state.latestSeq(job.run_id);
  const events: NewEvent<Record<never, never>>[] = [];

  if (latest === null) {
    if (job.reason !== "start") throw new Error(`cannot resume ${job.run_id}: it has no ledger`);
    const spec = resolveSpec(job);
    events.push({
      run_id: job.run_id,
      run_kind: job.run_kind,
      kind: "run",
      payload: {
        run_kind: job.run_kind,
        spec,
        budgets: spec.budgets,
        seed: job.run_id,
        tenant_id: job.tenant_id,
        started_by: job.enqueued_by,
      },
    });
  }

  // Re-entrant: a crash between the two appends resumes here rather than
  // colliding on seq 0. The lease and the watchdog are a later slice.
  if ((await state.terminal(job.run_id)) === null) {
    events.push({
      run_id: job.run_id,
      run_kind: job.run_kind,
      kind: "terminal",
      payload: { outcome: "completed", reason: "the spec resolved; nothing consumes it yet" },
    });
  }

  await state.append(job.run_id, latest === null ? 0 : latest + 1, events);
}

function connectionUrl(): string {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url === "") throw new Error("DATABASE_URL is not set");
  return url;
}

function redisUrl(): URL {
  return new URL(process.env["REDIS_URL"] ?? "redis://localhost:6379/0");
}

export function startWorker(): Worker<RunJob> {
  const pool = new pg.Pool({ connectionString: connectionUrl() });
  const ledger = new LedgerRepository(pool);
  const url = redisUrl();
  const worker = new Worker<RunJob>(RUN_QUEUE, (job) => advance(ledger, job.data), {
    connection: {
      host: url.hostname,
      port: Number(url.port || 6379),
      db: Number(url.pathname.slice(1) || 0),
      ...(url.password === "" ? {} : { password: url.password }),
    },
  });
  worker.on("closed", () => void pool.end());
  return worker;
}

if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "")) {
  const worker = startWorker();
  process.on("SIGTERM", () => void worker.close());
  process.on("SIGINT", () => void worker.close());
}
