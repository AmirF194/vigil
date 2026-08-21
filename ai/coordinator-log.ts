import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { newId } from "./ledger.js";
import type { CoordinatorDecision, HuntSummary } from "./coordinator-ports.js";

// The coordinator's own record, separate from any hunt ledger: one line per alert
// handled, carrying the decision and the state it was made against. It is the only
// place a DROP is explained, since a dropped alert starts no hunt and so leaves no
// trace in any hunt's ledger.
//
// Append-only JSONL, the same shape as the hunt ledgers, so it reads the same way
// and survives a restart.
export interface CoordEvent {
  event_id: string;
  alert_id: string;
  decision: CoordinatorDecision;
  // The hunt summaries the decider saw. Empty until the Phase 2 fold lands.
  state_seen: HuntSummary[];
  created_at: string;
}

export class CoordinatorLog {
  private constructor(
    readonly path: string,
    private readonly events: CoordEvent[],
  ) {}

  // Folds whatever is already on disk so a restarted coordinator continues its
  // own history rather than starting a fresh file.
  static open(path: string): CoordinatorLog {
    let events: CoordEvent[] = [];
    try {
      events = readFileSync(path, "utf8")
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as CoordEvent);
    } catch {
      // No file yet: the first append creates it.
    }
    // The runs dir may not exist on a first run — the coordinator can decide (and
    // log) before any hunt is ever started.
    mkdirSync(dirname(path), { recursive: true });
    return new CoordinatorLog(path, events);
  }

  // Records one handled alert. The event id and timestamp are stamped here so the
  // caller only supplies what it decided, not how it is filed.
  append(alert_id: string, decision: CoordinatorDecision, state_seen: HuntSummary[]): CoordEvent {
    const event: CoordEvent = {
      event_id: newId("coord"),
      alert_id,
      decision,
      state_seen,
      created_at: new Date().toISOString(),
    };
    this.events.push(event);
    appendFileSync(this.path, `${JSON.stringify(event)}\n`);
    return event;
  }

  all(): readonly CoordEvent[] {
    return this.events;
  }

  // True once a FINAL decision is on record for this alert. A DEFER does not count:
  // a deferred alert must still be reconsidered when a slot frees, so it is not yet
  // "handled".
  handled(alert_id: string): boolean {
    return this.events.some((event) => event.alert_id === alert_id && event.decision.action !== "DEFER");
  }

  // The last final decision recorded for an alert, or null. Lets a redelivered
  // alert return its prior outcome without deciding or acting again.
  decisionFor(alert_id: string): CoordinatorDecision | null {
    for (let i = this.events.length - 1; i >= 0; i -= 1) {
      const event = this.events[i]!;
      if (event.alert_id === alert_id && event.decision.action !== "DEFER") return event.decision;
    }
    return null;
  }
}
