#!/usr/bin/env -S npx tsx
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import type { Alert } from "../ai/alert.js";
import { enqueueAlert, FileAlertQueue } from "../ai/alert-queue.js";
import { Coordinator, type CoordinatorConfig } from "../ai/coordinator.js";
import { SpawnHuntLauncher } from "../ai/coordinator-launcher.js";
import { CoordinatorLog } from "../ai/coordinator-log.js";
import { LlmCoordinatorProvider } from "../ai/coordinator-llm.js";
import type { CoordinatorDecisionProvider } from "../ai/coordinator-ports.js";
import { heuristicDecision, ScriptedCoordinatorProvider } from "../ai/coordinator-scripted.js";
import { buildSpec } from "../ai/spec.js";

const USAGE = `vigil-coordinator run  --queue <dir> [--runs <dir>] [options]
  Consume alerts and start/steer/relate/drop hunts. Long-running by default.

  --queue <dir>     directory the feeder drops alert JSON into (required)
  --runs <dir>      where hunt ledgers live (default runs)
  --scripted        decide with the no-LLM heuristic instead of a model
  --config <path>   model and rates for the LLM decider (default vigil.config.yaml)
  --max <n>         cap on concurrent active hunts (default 5)
  --recent-ms <ms>  how long a finished hunt stays in scope for dedup (default 24h)
  --iterations <n>  iterations each started hunt is launched with (default 6)
  --poll <ms>       how often to re-check the queue (default 3000)
  --once            drain the queue once and exit, rather than polling
  --dry             create hunts but do not launch a runner for them

vigil-coordinator feed --queue <dir> <alert.json> [<alert.json> ...]
  Drop one or more alert files onto the queue.`;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function providerFor(scripted: boolean, configPath?: string): CoordinatorDecisionProvider {
  if (scripted) return new ScriptedCoordinatorProvider(heuristicDecision);
  // Model and rates come from the same config the hunts use, so the coordinator
  // bills against the configured rates rather than a number of its own.
  const spec = buildSpec({ prompt: "coordinator", ...(configPath ? { configPath } : {}) });
  return new LlmCoordinatorProvider(spec.model, spec.rates);
}

async function runDaemon(values: Values): Promise<number> {
  const queueDir = values.queue;
  if (queueDir === undefined) {
    console.error(`error: run needs --queue <dir>\n\n${USAGE}`);
    return 2;
  }

  const runsDir = values.runs ?? "runs";
  const config: CoordinatorConfig = {
    runs_dir: runsDir,
    recent_terminal_ms: Number(values["recent-ms"] ?? 86_400_000),
    max_concurrent: Number(values.max ?? 5),
  };

  const provider = providerFor(values.scripted, values.config);
  const launcher = values.dry ? undefined : new SpawnHuntLauncher(Number(values.iterations ?? 6));
  const log = CoordinatorLog.open(join(runsDir, "coordinator.jsonl"));
  const coordinator = new Coordinator(provider, log, config, launcher);
  const queue = new FileAlertQueue(queueDir);

  if (values.once) {
    await coordinator.run(queue);
    console.log(`handled ${log.all().length} alert(s) — log: ${join(runsDir, "coordinator.jsonl")}`);
    return 0;
  }

  console.log(`coordinator watching ${queueDir} (${values.scripted ? "scripted" : "llm"}${values.dry ? ", dry" : ""}) — Ctrl-C to stop`);
  let stop = false;
  process.on("SIGINT", () => {
    stop = true;
  });
  const poll = Number(values.poll ?? 3000);
  while (!stop) {
    await coordinator.run(queue);
    await sleep(poll);
  }
  console.log(`stopped — handled ${log.all().length} alert(s) total`);
  return 0;
}

function feed(values: Values, files: string[]): number {
  const queueDir = values.queue;
  if (queueDir === undefined) {
    console.error(`error: feed needs --queue <dir>\n\n${USAGE}`);
    return 2;
  }
  if (files.length === 0) {
    console.error(`error: feed needs at least one alert file\n\n${USAGE}`);
    return 2;
  }
  for (const file of files) {
    const alert = JSON.parse(readFileSync(file, "utf8")) as Alert;
    enqueueAlert(queueDir, alert);
    console.log(`queued ${alert.alert_id} (${alert.entity})`);
  }
  return 0;
}

type Values = {
  queue?: string;
  runs?: string;
  scripted: boolean;
  config?: string;
  max?: string;
  "recent-ms"?: string;
  iterations?: string;
  poll?: string;
  once: boolean;
  dry: boolean;
};

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    options: {
      queue: { type: "string" },
      runs: { type: "string" },
      scripted: { type: "boolean", default: false },
      config: { type: "string" },
      max: { type: "string" },
      "recent-ms": { type: "string" },
      iterations: { type: "string" },
      poll: { type: "string" },
      once: { type: "boolean", default: false },
      dry: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    allowPositionals: true,
  });

  if (values.help || positionals.length === 0) {
    console.log(USAGE);
    return values.help ? 0 : 2;
  }

  const command = positionals[0];
  if (command === "run") return runDaemon(values as Values);
  if (command === "feed") return feed(values as Values, positionals.slice(1));

  console.error(`error: unknown command ${command}\n\n${USAGE}`);
  return 2;
}

main().then(
  (code) => process.exit(code),
  (error: Error) => {
    console.error(`error: ${error.message}`);
    process.exit(1);
  },
);
