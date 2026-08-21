import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { alertToSpec, type Alert } from "./alert.js";
import type {
  AlertQueue,
  CoordinatorDecision,
  CoordinatorDecisionProvider,
  HuntLauncher,
  HuntSummary,
} from "./coordinator-ports.js";
import type { CoordinatorLog } from "./coordinator-log.js";
import { key } from "./entities.js";
import { steer } from "./inbox.js";
import { Ledger } from "./ledger.js";
import { startHunt } from "./loop.js";
import { parseEntity } from "./spec.js";
import type { DirectiveKind, Entity, HuntState } from "./types.js";

// Stamped on every inbox directive the coordinator writes, so a hunt's ledger
// shows a machine correlated this — distinct from a person's steer and from a
// policy default.
export const COORDINATOR_ACTOR = "coordinator";

// The first config the coordinator carries. runs_dir is where the hunt ledgers
// live; recent_terminal_ms is how far back a finished hunt still counts as worth
// deduping against — a duplicate alert often arrives just after a hunt closes.
export interface CoordinatorConfig {
  runs_dir: string;
  recent_terminal_ms: number;
  // Ceiling on concurrent active hunts. A START past it is deferred, not dropped.
  max_concurrent: number;
}

// The layer above the hunts. It consumes alerts and decides what to do with each
// one, but never reaches inside a running hunt: in later phases it starts hunts
// and appends to their inboxes, and that is all.
//
// Phase 2 gives the decider eyes: handle() folds the live hunts and runs the
// deterministic tier-1 dedup before asking. The actions (Phase 3) and the
// guardrails (Phase 4) still hang off handle() and run() without changing shape.
export class Coordinator {
  // Alerts waiting for a slot: START decisions withheld at the cap. In memory —
  // on a crash the source queue redelivers, so this is a runtime buffer, not a
  // durable one.
  private readonly deferred: Alert[] = [];
  // Serializes handle() so two alerts can never race the fold and the cap check.
  private lock: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly provider: CoordinatorDecisionProvider,
    private readonly log: CoordinatorLog,
    private readonly config: CoordinatorConfig,
    // Optional: with no launcher, START creates the hunt but leaves it for a
    // runner to advance — the Phase 1–5 behavior. With one, the hunt is run.
    private readonly launcher?: HuntLauncher,
  ) {}

  // One alert, under the lock. Everything after the lock — idempotency, fold,
  // decide, cap, execute — runs to completion before the next alert begins.
  async handle(alert: Alert): Promise<CoordinatorDecision> {
    const run = this.lock.then(() => this.handleLocked(alert));
    // Swallow on the chain only: the caller still sees a rejection, but one
    // failed alert must not break the lock for every alert after it.
    this.lock = run.catch(() => undefined);
    return run;
  }

  private async handleLocked(alert: Alert): Promise<CoordinatorDecision> {
    // A redelivered alert already has an outcome; return it without deciding or
    // acting again. A DEFER is not final, so a deferred alert falls through and
    // is reconsidered.
    if (this.log.handled(alert.alert_id)) return this.log.decisionFor(alert.alert_id)!;
    return this.decideAndExecute(alert);
  }

  // The decision path: fold, decide, then either defer (START at the cap) or log
  // and act. Recording precedes acting, so the log is the whole story even if an
  // action later fails.
  private async decideAndExecute(alert: Alert): Promise<CoordinatorDecision> {
    const hunts = this.fold();
    const exact_match = this.exactMatch(alert, hunts);
    const decision = await this.provider.decide({ alert, hunts, exact_match });

    if (decision.action === "START" && this.atCapacity(hunts)) return this.defer(alert, hunts);

    this.log.append(alert.alert_id, decision, hunts);
    await this.execute(decision, alert);
    return decision;
  }

  // Drains the queue in order, then reconsiders anything deferred once the last
  // alert has possibly freed or filled slots. run() is the single serial driver;
  // handle()'s lock guards against any stray concurrent caller.
  async run(queue: AlertQueue): Promise<void> {
    for (let alert = await queue.pull(); alert !== null; alert = await queue.pull()) {
      await this.handle(alert);
      await this.drainDeferred();
    }
    await this.drainDeferred();
  }

  private atCapacity(hunts: HuntSummary[]): boolean {
    return hunts.filter((hunt) => hunt.status === "active").length >= this.config.max_concurrent;
  }

  // Buffers the alert and records a DEFER — audited, but not final, so the alert
  // stays eligible for another pass.
  private defer(alert: Alert, hunts: HuntSummary[]): CoordinatorDecision {
    const decision: CoordinatorDecision = {
      action: "DEFER",
      reason: `at the concurrency cap of ${this.config.max_concurrent} active hunt(s); waiting for a slot`,
    };
    this.deferred.push(alert);
    this.log.append(alert.alert_id, decision, hunts);
    return decision;
  }

  // Reconsiders buffered alerts while capacity allows. Each is re-decided from the
  // current state, so one that now matches a started hunt becomes a STEER rather
  // than a second hunt. One pass over the current backlog: an alert that defers
  // again lands back in the buffer and waits for the next pass, so this never spins.
  private async drainDeferred(): Promise<void> {
    let remaining = this.deferred.length;
    while (remaining > 0 && !this.atCapacity(this.fold())) {
      const alert = this.deferred.shift();
      if (alert === undefined) break;
      await this.decideAndExecute(alert);
      remaining -= 1;
    }
  }

  // Reads every hunt ledger in runs_dir and reduces each to a one-line summary —
  // the same "state is a fold over the ledger" the hunt engine itself relies on,
  // done once per hunt. Derived fresh each call rather than cached, so there is no
  // second copy of hunt state to drift.
  private fold(): HuntSummary[] {
    let files: string[];
    try {
      files = readdirSync(this.config.runs_dir);
    } catch {
      // No runs dir yet: nothing to dedup against.
      return [];
    }

    const now = Date.now();
    const summaries: HuntSummary[] = [];
    for (const file of files) {
      // A hunt's inbox lives beside it as <ledger>.inbox.jsonl and also ends in
      // .jsonl; it is not a ledger, so skip it.
      if (!file.endsWith(".jsonl") || file.endsWith(".inbox.jsonl")) continue;

      try {
        // .projection is a lazy fold, so both the open and the fold must be
        // guarded: a partial file, or a .jsonl that is not a hunt ledger at all
        // (the coordinator's own log lives here too), is skipped rather than
        // blinding the whole fold.
        const { hunt, hypotheses } = Ledger.open(join(this.config.runs_dir, file)).projection;
        if (!this.inScope(hunt, now)) continue;

        const entity = hunt.scope["entity"] as Entity | undefined;
        summaries.push({
          hunt_id: hunt.hunt_id,
          seed_entity: entity === undefined ? null : key(entity),
          active_hypotheses: [...hypotheses.values()]
            .filter((hypothesis) => hypothesis.status === "active")
            .map((hypothesis) => hypothesis.statement),
          status: hunt.status,
        });
      } catch {
        continue;
      }
    }
    return summaries;
  }

  // Active and parked hunts are always in play; a terminal one only while it is
  // recent. pending_approval is deliberately excluded — a hunt not yet allowed to
  // start is not yet something to relate an alert to.
  private inScope(hunt: HuntState, now: number): boolean {
    if (hunt.status === "active" || hunt.status === "parked") return true;
    if (hunt.status !== "terminal" || hunt.terminated_at === null) return false;
    return now - Date.parse(hunt.terminated_at) <= this.config.recent_terminal_ms;
  }

  // Deterministic tier-1 dedup: normalize the alert entity to the same key the
  // hunt engine uses, and match it against each hunt's seed. Exact and free — the
  // fuzzy, LLM-judged relation is a later tier. Returns the first match, since an
  // alert entity maps to at most one sensible hunt to feed.
  private exactMatch(alert: Alert, hunts: HuntSummary[]): HuntSummary | null {
    let alertKey: string;
    try {
      alertKey = key(parseEntity(alert.entity));
    } catch {
      // An entity we cannot parse has no deterministic match; the decider still
      // sees the alert and the fold.
      return null;
    }
    return hunts.find((hunt) => hunt.seed_entity === alertKey) ?? null;
  }

  // Carries out the decision after it is logged. DROP was the whole of its own
  // action — the reason is already on the record — so it does nothing here.
  private async execute(decision: CoordinatorDecision, alert: Alert): Promise<void> {
    switch (decision.action) {
      case "START":
        this.start(alert);
        return;
      case "STEER":
        this.steerHunts(decision);
        return;
      case "RELATE":
        this.relate(decision, alert);
        return;
      case "DROP":
        return;
    }
  }

  // Creates the hunt, then hands it to the launcher to run — the same split the
  // CLI makes between starting a hunt and running its loop. startHunt auto-approves
  // it to active; the launcher advances it out of process.
  private start(alert: Alert): void {
    const ledger = startHunt(alertToSpec(alert), this.config.runs_dir);
    this.launcher?.launch(ledger.path);
  }

  // Feeds the alert into existing hunts as real work: a lead joins the frontier.
  private steerHunts(decision: CoordinatorDecision): void {
    const text = decision.directive ?? "feed the correlated alert into this hunt";
    for (const huntId of decision.hunt_ids ?? []) this.nudge(huntId, "lead", text);
  }

  // Tells each related hunt about the others without opening work: a note reaches
  // the next digest but adds nothing to the frontier. One-time, at relate.
  private relate(decision: CoordinatorDecision, alert: Alert): void {
    const hunts = decision.hunt_ids ?? [];
    for (const huntId of hunts) {
      const siblings = hunts.filter((id) => id !== huntId);
      const text =
        decision.directive ??
        `related to hunt(s) ${siblings.join(", ") || "(none)"} over shared entity ${alert.entity}`;
      this.nudge(huntId, "note", text);
    }
  }

  // Appends one directive to a hunt's inbox, stamped as the coordinator. Skips a
  // hunt whose ledger has since vanished rather than creating an orphan inbox.
  private nudge(huntId: string, kind: DirectiveKind, text: string): void {
    const path = this.ledgerPath(huntId);
    if (!existsSync(path)) return;
    steer(path, kind, text, { actor: COORDINATOR_ACTOR });
  }

  private ledgerPath(huntId: string): string {
    return join(this.config.runs_dir, `${huntId}.jsonl`);
  }
}
