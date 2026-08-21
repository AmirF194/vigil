import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import type { Alert } from "../ai/alert.js";
import { enqueueAlert, FileAlertQueue } from "../ai/alert-queue.js";
import { Coordinator, type CoordinatorConfig } from "../ai/coordinator.js";
import { CoordinatorLog } from "../ai/coordinator-log.js";
import type { HuntLauncher } from "../ai/coordinator-ports.js";
import { heuristicDecision, ScriptedCoordinatorProvider } from "../ai/coordinator-scripted.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "alerts");

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "coord-daemon-"));
});

function config(overrides: Partial<CoordinatorConfig> = {}): CoordinatorConfig {
  return { runs_dir: join(dir, "runs"), recent_terminal_ms: 86_400_000, max_concurrent: 10, ...overrides };
}

function alert(id: string, entity: string): Alert {
  return { alert_id: id, entity, severity: "medium", timestamp: "2026-08-21T00:00:00.000Z", raw: {} };
}

function huntLedgers(): string[] {
  try {
    return readdirSync(config().runs_dir).filter((f) => f.startsWith("hunt-") && f.endsWith(".jsonl"));
  } catch {
    return [];
  }
}

class FakeLauncher implements HuntLauncher {
  readonly launched: string[] = [];
  launch(ledgerPath: string): void {
    this.launched.push(ledgerPath);
  }
}

describe("HuntLauncher wiring", () => {
  it("launches a started hunt, and only a started hunt", async () => {
    const launcher = new FakeLauncher();
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    const coord = new Coordinator(
      new ScriptedCoordinatorProvider([
        { action: "START", reason: "novel" },
        { action: "DROP", reason: "dup" },
      ]),
      log,
      config(),
      launcher,
    );

    await coord.handle(alert("a1", "10.0.0.1"));
    await coord.handle(alert("a2", "10.0.0.2"));

    expect(launcher.launched).toHaveLength(1);
    expect(launcher.launched[0]).toContain(config().runs_dir);
    expect(launcher.launched[0]).toBe(join(config().runs_dir, huntLedgers()[0]!));
  });
});

describe("FileAlertQueue", () => {
  it("hands out enqueued alerts oldest-first, then null", async () => {
    const queueDir = join(dir, "queue");
    enqueueAlert(queueDir, alert("a1", "10.0.0.1"));
    enqueueAlert(queueDir, alert("a2", "10.0.0.2"));
    const queue = new FileAlertQueue(queueDir);

    const first = await queue.pull();
    const second = await queue.pull();
    const third = await queue.pull();

    expect([first?.alert_id, second?.alert_id].sort()).toEqual(["a1", "a2"]);
    expect(third).toBeNull();
  });

  it("claims each alert once — a pulled alert is gone from the dir", async () => {
    const queueDir = join(dir, "queue");
    enqueueAlert(queueDir, alert("a1", "10.0.0.1"));
    const queue = new FileAlertQueue(queueDir);

    await queue.pull();
    expect(readdirSync(queueDir)).toHaveLength(0);
  });

  it("returns null when the queue dir does not exist", async () => {
    expect(await new FileAlertQueue(join(dir, "missing")).pull()).toBeNull();
  });
});

describe("daemon composition (the CLI's --once path, in process)", () => {
  it("drains a queue of alert fixtures: starts distinct hunts, drops the duplicate", async () => {
    const queueDir = join(dir, "queue");
    for (const file of ["novel.json", "duplicate.json", "sparse.json"]) {
      enqueueAlert(queueDir, JSON.parse(readFileSync(join(FIXTURES, file), "utf8")) as Alert);
    }

    const launcher = new FakeLauncher();
    const log = CoordinatorLog.open(join(config().runs_dir, "coordinator.jsonl"));
    const coord = new Coordinator(new ScriptedCoordinatorProvider(heuristicDecision), log, config(), launcher);

    await coord.run(new FileAlertQueue(queueDir));

    // Three alerts handled; two on distinct entities start hunts, the second on
    // 10.0.0.100 is dropped as an exact duplicate. Order-independent.
    expect(log.all()).toHaveLength(3);
    expect(huntLedgers()).toHaveLength(2);
    expect(launcher.launched).toHaveLength(2);
    expect(log.all().filter((e) => e.decision.action === "DROP")).toHaveLength(1);
  });
});
