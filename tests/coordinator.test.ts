import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { Alert } from "../ai/alert.js";
import { Coordinator, COORDINATOR_ACTOR, type CoordinatorConfig } from "../ai/coordinator.js";
import { CoordinatorLog, type CoordEvent } from "../ai/coordinator-log.js";
import type { CoordinatorDecision, CoordinatorInput } from "../ai/coordinator-ports.js";
import { InMemoryAlertQueue, ScriptedCoordinatorProvider } from "../ai/coordinator-scripted.js";
import { inboxPath, steer } from "../ai/inbox.js";
import { Ledger } from "../ai/ledger.js";
import { HuntController, startHunt } from "../ai/loop.js";
import { ScriptedDecisionProvider } from "../ai/scripted.js";
import { buildSpec } from "../ai/spec.js";
import type { Directive, Entity } from "../ai/types.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "coord-"));
});

// A config whose runs_dir is empty unless a test starts a hunt there, so the
// Phase 1 tests fold nothing and the Phase 2 tests fold what they created.
function config(overrides: Partial<CoordinatorConfig> = {}): CoordinatorConfig {
  return { runs_dir: join(dir, "runs"), recent_terminal_ms: 86_400_000, max_concurrent: 10, ...overrides };
}

function alert(id: string, entity: string): Alert {
  return { alert_id: id, entity, severity: "medium", timestamp: "2026-08-21T00:00:00.000Z", raw: {} };
}

const START: CoordinatorDecision = { action: "START", reason: "novel entity" };
const DROP: CoordinatorDecision = { action: "DROP", reason: "duplicate of an active hunt" };

describe("Coordinator (Phase 1)", () => {
  it("handles each queued alert in order and logs one event per alert", async () => {
    const queue = new InMemoryAlertQueue();
    queue.push(alert("a1", "10.0.0.1"));
    queue.push(alert("a2", "host:web-01"));
    queue.push(alert("a3", "10.0.0.2"));

    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    const provider = new ScriptedCoordinatorProvider([START, DROP, START]);

    await new Coordinator(provider, log, config()).run(queue);

    const events = log.all();
    expect(events.map((e) => e.alert_id)).toEqual(["a1", "a2", "a3"]);
    expect(events.map((e) => e.decision.action)).toEqual(["START", "DROP", "START"]);
  });

  it("records a DROP with its reason", async () => {
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    await new Coordinator(new ScriptedCoordinatorProvider([DROP]), log, config()).handle(alert("a1", "10.0.0.1"));

    const [event] = log.all();
    expect(event?.decision.action).toBe("DROP");
    expect(event?.decision.reason).toBe("duplicate of an active hunt");
  });

  it("returns cleanly when the queue is empty", async () => {
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    await new Coordinator(new ScriptedCoordinatorProvider([]), log, config()).run(new InMemoryAlertQueue());
    expect(log.all()).toHaveLength(0);
  });

  it("writes an append-only JSONL that reopens with its history intact", async () => {
    const path = join(dir, "coord.jsonl");
    await new Coordinator(new ScriptedCoordinatorProvider([START]), CoordinatorLog.open(path), config()).handle(
      alert("a1", "10.0.0.1"),
    );

    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect((JSON.parse(lines[0]!) as CoordEvent).alert_id).toBe("a1");

    // A second coordinator over the same file folds the prior event and appends
    // after it, so the log survives a restart.
    await new Coordinator(new ScriptedCoordinatorProvider([DROP]), CoordinatorLog.open(path), config()).handle(
      alert("a2", "10.0.0.2"),
    );
    expect(CoordinatorLog.open(path).all().map((e) => e.alert_id)).toEqual(["a1", "a2"]);
  });
});

describe("Coordinator (Phase 2) — fold + tier-1 dedup", () => {
  // Starts a real hunt in the coordinator's runs_dir. Default checkpoints
  // auto-approve, so the hunt is active the moment it is created — exactly what
  // the fold should pick up.
  function startHuntOn(entity: string, hypothesis = "a host is beaconing outbound"): string {
    const spec = buildSpec({ prompt: hypothesis, entity });
    return startHunt(spec, config().runs_dir).projection.hunt.hunt_id;
  }

  // Captures what the coordinator showed the decider, so the fold and the
  // precomputed match can be asserted directly.
  function capturing(): { provider: ScriptedCoordinatorProvider; seen: CoordinatorInput[] } {
    const seen: CoordinatorInput[] = [];
    const provider = new ScriptedCoordinatorProvider((input) => {
      seen.push(input);
      return DROP;
    });
    return { provider, seen };
  }

  it("folds an active hunt into a one-line summary keyed by its seed entity", async () => {
    const huntId = startHuntOn("10.0.0.1");
    const { provider, seen } = capturing();

    await new Coordinator(provider, CoordinatorLog.open(join(dir, "coord.jsonl")), config()).handle(
      alert("a1", "10.0.0.2"),
    );

    expect(seen[0]?.hunts).toHaveLength(1);
    const summary = seen[0]!.hunts[0]!;
    expect(summary.hunt_id).toBe(huntId);
    expect(summary.seed_entity).toBe("ip:10.0.0.1");
    expect(summary.status).toBe("active");
    expect(summary.active_hypotheses).toContain("a host is beaconing outbound");
  });

  it("matches an alert on the same entity to that hunt (tier-1)", async () => {
    const huntId = startHuntOn("10.0.0.1");
    const { provider, seen } = capturing();

    await new Coordinator(provider, CoordinatorLog.open(join(dir, "coord.jsonl")), config()).handle(
      alert("a1", "10.0.0.1"),
    );

    expect(seen[0]?.exact_match?.hunt_id).toBe(huntId);
  });

  it("returns no match when the alert entity is not a live hunt's seed", async () => {
    startHuntOn("10.0.0.1");
    const { provider, seen } = capturing();

    await new Coordinator(provider, CoordinatorLog.open(join(dir, "coord.jsonl")), config()).handle(
      alert("a1", "host:web-99"),
    );

    expect(seen[0]?.hunts).toHaveLength(1);
    expect(seen[0]?.exact_match).toBeNull();
  });

  it("folds nothing when the runs dir does not exist", async () => {
    const { provider, seen } = capturing();
    await new Coordinator(provider, CoordinatorLog.open(join(dir, "coord.jsonl")), config()).handle(
      alert("a1", "10.0.0.1"),
    );
    expect(seen[0]?.hunts).toEqual([]);
    expect(seen[0]?.exact_match).toBeNull();
  });

  it("logs the folded state it decided against", async () => {
    startHuntOn("10.0.0.1");
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    await new Coordinator(new ScriptedCoordinatorProvider([DROP]), log, config()).handle(alert("a1", "10.0.0.1"));

    expect(log.all()[0]?.state_seen).toHaveLength(1);
    expect(log.all()[0]?.state_seen[0]?.seed_entity).toBe("ip:10.0.0.1");
  });
});

describe("Coordinator (Phase 3) — executing decisions", () => {
  function coordinator(decisions: CoordinatorDecision[]): Coordinator {
    return new Coordinator(
      new ScriptedCoordinatorProvider(decisions),
      CoordinatorLog.open(join(dir, "coord.jsonl")),
      config(),
    );
  }

  function startHuntOn(entity: string): string {
    return startHunt(buildSpec({ prompt: "a host is beaconing outbound", entity }), config().runs_dir)
      .projection.hunt.hunt_id;
  }

  function huntLedgers(): string[] {
    try {
      return readdirSync(config().runs_dir).filter((f) => f.endsWith(".jsonl") && !f.endsWith(".inbox.jsonl"));
    } catch {
      return [];
    }
  }

  function inbox(huntId: string): Directive[] {
    const path = inboxPath(join(config().runs_dir, `${huntId}.jsonl`));
    if (!existsSync(path)) return [];
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Directive);
  }

  it("START creates a new active hunt seeded on the alert entity", async () => {
    await coordinator([{ action: "START", reason: "novel entity" }]).handle(alert("a1", "10.0.0.5"));

    const files = huntLedgers();
    expect(files).toHaveLength(1);
    const ledger = Ledger.open(join(config().runs_dir, files[0]!));
    expect((ledger.projection.hunt.scope["entity"] as Entity).value).toBe("10.0.0.5");
    expect(ledger.projection.hunt.status).toBe("active");
  });

  it("STEER appends a lead to the target hunt's inbox as the coordinator", async () => {
    const huntId = startHuntOn("10.0.0.1");
    await coordinator([{ action: "STEER", reason: "duplicate", hunt_ids: [huntId], directive: "check DNS too" }]).handle(
      alert("a1", "10.0.0.1"),
    );

    const directives = inbox(huntId);
    expect(directives).toHaveLength(1);
    expect(directives[0]?.kind).toBe("lead");
    expect(directives[0]?.actor).toBe(COORDINATOR_ACTOR);
    expect(directives[0]?.text).toBe("check DNS too");
  });

  it("RELATE notes each hunt about the others over the shared entity", async () => {
    const h1 = startHuntOn("10.0.0.1");
    const h2 = startHuntOn("10.0.0.2");
    await coordinator([{ action: "RELATE", reason: "same campaign", hunt_ids: [h1, h2] }]).handle(
      alert("a1", "10.0.0.3"),
    );

    const n1 = inbox(h1);
    const n2 = inbox(h2);
    expect(n1).toHaveLength(1);
    expect(n1[0]?.kind).toBe("note");
    expect(n1[0]?.actor).toBe(COORDINATOR_ACTOR);
    expect(n1[0]?.text).toContain(h2);
    expect(n2[0]?.text).toContain(h1);
  });

  it("STEER to a vanished hunt is skipped, not an orphan inbox or a throw", async () => {
    await coordinator([{ action: "STEER", reason: "stale", hunt_ids: ["hunt-gone"], directive: "x" }]).handle(
      alert("a1", "10.0.0.1"),
    );
    expect(existsSync(inboxPath(join(config().runs_dir, "hunt-gone.jsonl")))).toBe(false);
  });

  it("DROP touches no hunt", async () => {
    const huntId = startHuntOn("10.0.0.1");
    await coordinator([{ action: "DROP", reason: "duplicate" }]).handle(alert("a1", "10.0.0.1"));
    expect(inbox(huntId)).toHaveLength(0);
  });
});

describe("Coordinator (Phase 4) — guardrails", () => {
  function startHuntOn(entity: string): void {
    startHunt(buildSpec({ prompt: "a host is beaconing outbound", entity }), config().runs_dir);
  }

  function huntLedgers(): string[] {
    try {
      return readdirSync(config().runs_dir).filter((f) => f.endsWith(".jsonl") && !f.endsWith(".inbox.jsonl"));
    } catch {
      return [];
    }
  }

  // Ends a hunt so a slot frees, the way the CLI's abort path does: queue an abort
  // and advance once with an empty decision provider.
  async function terminate(file: string): Promise<void> {
    const path = join(config().runs_dir, file);
    steer(path, "abort", "test teardown", { actor: "test" });
    await new HuntController(Ledger.open(path), new ScriptedDecisionProvider([])).advanceIteration();
  }

  const START: CoordinatorDecision = { action: "START", reason: "novel entity" };

  it("handles a redelivered alert once, returning the prior decision", async () => {
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    // Only one scripted decision: a second decide() would throw, proving the
    // redelivery never reached the provider.
    const coord = new Coordinator(new ScriptedCoordinatorProvider([START]), log, config());

    const first = await coord.handle(alert("a1", "10.0.0.1"));
    const second = await coord.handle(alert("a1", "10.0.0.1"));

    expect(first.action).toBe("START");
    expect(second).toEqual(first);
    expect(huntLedgers()).toHaveLength(1);
    expect(log.all().filter((e) => e.alert_id === "a1")).toHaveLength(1);
  });

  it("DEFERs a START at the concurrency cap without starting a hunt", async () => {
    startHuntOn("10.0.0.9"); // one active hunt, cap is 1
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    const coord = new Coordinator(new ScriptedCoordinatorProvider([START]), log, config({ max_concurrent: 1 }));

    const decision = await coord.handle(alert("a1", "10.0.0.1"));

    expect(decision.action).toBe("DEFER");
    expect(huntLedgers()).toHaveLength(1); // still just the pre-existing hunt
    expect(log.handled("a1")).toBe(false); // deferred, still retriable
  });

  it("does not defer a non-START decision at the cap", async () => {
    startHuntOn("10.0.0.9");
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    const coord = new Coordinator(
      new ScriptedCoordinatorProvider([{ action: "DROP", reason: "dup" }]),
      log,
      config({ max_concurrent: 1 }),
    );

    const decision = await coord.handle(alert("a1", "10.0.0.1"));

    expect(decision.action).toBe("DROP");
    expect(log.handled("a1")).toBe(true);
  });

  it("drains a deferred START once a slot frees", async () => {
    const queue = new InMemoryAlertQueue();
    queue.push(alert("a1", "10.0.0.1"));
    queue.push(alert("a2", "10.0.0.2"));
    const log = CoordinatorLog.open(join(dir, "coord.jsonl"));
    const coord = new Coordinator(new ScriptedCoordinatorProvider([START, START, START]), log, config({ max_concurrent: 1 }));

    await coord.run(queue);
    expect(huntLedgers()).toHaveLength(1); // a2 deferred at the cap
    expect(log.handled("a2")).toBe(false);

    await terminate(huntLedgers()[0]!); // free the one slot
    await coord.run(new InMemoryAlertQueue()); // empty queue, but the final drain runs

    expect(huntLedgers()).toHaveLength(2); // a2's hunt now started
    expect(log.handled("a2")).toBe(true);
  });
});
