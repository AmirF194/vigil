import type OpenAI from "openai";
import type { CoordinatorDecision, CoordinatorDecisionProvider, CoordinatorInput, HuntSummary } from "./coordinator-ports.js";
import { Limiter } from "./limiter.js";
import { createClient, llm_output } from "./llm.js";
import type { Rates } from "./spec.js";

// The real decider, behind the same CoordinatorDecisionProvider port the scripted
// one implements. It reuses the hunt engine's LLM plumbing — llm_output does the
// schema-constrained emit, the retry on a bad emission, and the cost accounting —
// so this file is only a prompt, a schema, and the mapping back to a decision.

// DEFER is deliberately absent: it is the coordinator's own outcome at the cap,
// never something the model may choose.
export const DECISION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["action", "reason"],
  properties: {
    action: { type: "string", enum: ["START", "STEER", "RELATE", "DROP"] },
    reason: { type: "string" },
    // Targets for STEER / RELATE. Ignored for START and DROP.
    hunt_ids: { type: "array", items: { type: "string" } },
    // The nudge text a STEER or RELATE writes into a hunt's inbox.
    directive: { type: "string" },
  },
} as const;

export const SYSTEM_PROMPT = `You are the threat-hunt coordinator. A new alert has arrived. Decide what to do with it, given the hunts already running.

Choose exactly one action:
- START: the alert is novel — no running hunt covers it. A new hunt will be created on its entity.
- STEER: the alert belongs to an existing hunt (a duplicate, or a fresh lead for it). Set hunt_ids to that hunt, and directive to what it should look at.
- RELATE: the alert is a separate but related investigation (same campaign, adjacent entity). Set hunt_ids to the hunts to cross-link; each is told about the others.
- DROP: the alert needs no action — an exact duplicate already being handled, with nothing to add.

Rules:
- Prefer STEER or DROP over START when an exact entity match is shown: do not open a second hunt on an entity already being hunted.
- Use RELATE only for genuinely distinct hunts that should know about each other.
- Always give a concise reason. For a DROP, the reason is the whole record of why no hunt ran, so make it specific.
- hunt_ids must be ids drawn from the live hunts shown to you.`;

function renderHunt(hunt: HuntSummary): string {
  const hypotheses = hunt.active_hypotheses.length === 0 ? "(no active hypotheses)" : hunt.active_hypotheses.join("; ");
  return `- ${hunt.hunt_id} [${hunt.status}] seed ${hunt.seed_entity ?? "(none)"}: ${hypotheses}`;
}

export function renderCoordinatorInput(input: CoordinatorInput): string {
  const { alert, hunts, exact_match } = input;
  const lines = [
    "# New alert",
    `alert_id: ${alert.alert_id}`,
    `entity: ${alert.entity}`,
    `rule: ${alert.rule_name ?? "(none)"}`,
    `severity: ${alert.severity}`,
    `observed: ${alert.timestamp}`,
    "",
    "# Exact entity match",
    exact_match === null ? "none — no running hunt is seeded on this entity" : renderHunt(exact_match),
    "",
    `# Live hunts (${hunts.length})`,
    hunts.length === 0 ? "none" : hunts.map(renderHunt).join("\n"),
  ];
  return lines.join("\n");
}

export class LlmCoordinatorProvider implements CoordinatorDecisionProvider {
  constructor(
    private readonly model: string,
    private readonly rates: Rates,
    // Its own limiter and client: the coordinator's traffic is not a hunt's, and
    // it runs even when no hunt is live. Defaults are modest — one alert at a time.
    private readonly limiter: Limiter = new Limiter({ rpm: 60, tpm: 200_000 }, 2, 3),
    private readonly client: OpenAI = createClient(),
  ) {}

  async decide(input: CoordinatorInput): Promise<CoordinatorDecision> {
    const result = await llm_output<CoordinatorDecision>({
      client: this.client,
      model: this.model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: renderCoordinatorInput(input) },
      ],
      schema: DECISION_SCHEMA as unknown as Record<string, unknown>,
      limiter: this.limiter,
      rates: this.rates,
    });
    return result.value;
  }
}
