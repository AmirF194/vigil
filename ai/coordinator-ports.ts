import type { Alert } from "./alert.js";

// The seams the coordinator is built around, mirroring ai/ports.ts: the decision
// maker is injected, so tests run a scripted stand-in and production runs an LLM,
// and the alert transport is injected, so tests run in memory and production runs
// a real queue. Nothing here touches a ledger or a hunt.

// A one-line view of a hunt, folded from its ledger. Empty in Phase 1 — the fold
// arrives in Phase 2 — but the type is the contract the decider reads, so it is
// defined now and shared by the input and the audit event.
export interface HuntSummary {
  hunt_id: string;
  seed_entity: string | null;
  active_hypotheses: string[];
  status: string; // active | parked | terminal
}

// START/STEER/RELATE/DROP are what the provider chooses. DEFER is authored by the
// coordinator, never the provider — the same way STALLED is written by the hunt
// controller and no lead may emit it. It means a START was withheld because the
// concurrency cap is full, and the alert waits for a slot.
export type CoordinatorAction = "START" | "STEER" | "RELATE" | "DROP" | "DEFER";

// One decision about one alert. reason is always required — it is what a DROP
// leaves behind, the answer to "why did no hunt start for this?".
export interface CoordinatorDecision {
  action: CoordinatorAction;
  reason: string;
  hunt_ids?: string[]; // targets for STEER / RELATE
  directive?: string; // nudge text for STEER / RELATE
}

// Exactly what the decider is shown for one alert. exact_match is precomputed by
// the coordinator (Phase 2) so the decider never redoes the deterministic check;
// it is null in Phase 1.
export interface CoordinatorInput {
  alert: Alert;
  hunts: HuntSummary[];
  exact_match: HuntSummary | null;
}

// One input in, one decision out. The coordinator applies it — the provider never
// starts a hunt or writes an inbox itself, the same way a DecisionProvider never
// touches the ledger.
export interface CoordinatorDecisionProvider {
  decide(input: CoordinatorInput): Promise<CoordinatorDecision>;
}

// The alert transport. pull returns the next alert, or null when nothing is left
// to hand out. A real queue impl and an in-memory fake both satisfy this.
export interface AlertQueue {
  pull(): Promise<Alert | null>;
}

// Advances a hunt the coordinator has started. A port so the coordinator only
// decides and launches — running the hunt loop stays a separate concern, exactly
// as the CLI splits startHunt from run(). The real impl spawns the runner; a test
// fake records the calls.
export interface HuntLauncher {
  launch(ledgerPath: string): void;
}
