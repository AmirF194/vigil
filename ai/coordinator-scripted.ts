import type { Alert } from "./alert.js";
import type {
  AlertQueue,
  CoordinatorDecision,
  CoordinatorDecisionProvider,
  CoordinatorInput,
} from "./coordinator-ports.js";

// The test fakes, mirroring ai/scripted.ts: the coordinator itself is real, only
// the model behind its one decision and the queue transport are stand-ins. This
// is how the whole coordinator runs deterministically with no model calls.

// A canned decider. Give it a fixed list to hand out in order, or a function to
// compute a decision from what the coordinator shows it.
export class ScriptedCoordinatorProvider implements CoordinatorDecisionProvider {
  private next = 0;

  constructor(
    private readonly script: CoordinatorDecision[] | ((input: CoordinatorInput) => CoordinatorDecision),
  ) {}

  async decide(input: CoordinatorInput): Promise<CoordinatorDecision> {
    if (typeof this.script === "function") return this.script(input);
    const decision = this.script[this.next];
    if (decision === undefined) throw new Error(`scripted coordinator ran out of decisions at ${this.next}`);
    this.next += 1;
    return decision;
  }
}

// A no-LLM decision policy: drop an alert that exactly matches a running hunt,
// start one otherwise. Enough to exercise the whole daemon — queue, fold, dedup,
// launch, log — without a model, the way --scripted exercises the hunt loop.
export function heuristicDecision(input: CoordinatorInput): CoordinatorDecision {
  if (input.exact_match !== null) {
    return { action: "DROP", reason: `exact duplicate of ${input.exact_match.hunt_id}` };
  }
  return { action: "START", reason: "no live hunt is seeded on this entity" };
}

// A FIFO alert source held in memory. The feeder pushes; the coordinator pulls
// until it returns null.
export class InMemoryAlertQueue implements AlertQueue {
  private readonly alerts: Alert[] = [];

  push(alert: Alert): void {
    this.alerts.push(alert);
  }

  async pull(): Promise<Alert | null> {
    return this.alerts.shift() ?? null;
  }
}
