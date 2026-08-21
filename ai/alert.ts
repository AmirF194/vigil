import { buildSpec, type HuntSpec } from "./spec.js";

// What arrives from a detection source. The coordinator turns one of these into
// a decision: start a hunt, feed an existing one, relate some, or drop it.
//
// Fields beyond the entity are optional on purpose — a real alert stream is
// ragged, and the rule name in particular is often missing. The coordinator must
// still decide something from the entity alone.
export interface Alert {
  // Stable across redelivery. Later phases use it to avoid handling one twice;
  // Phase 1 only records it.
  alert_id: string;
  // The primary entity, in the same raw form a hunt seed takes: "10.0.0.1",
  // "host:web-01".
  entity: string;
  rule_name?: string;
  severity: string;
  // ISO 8601, as the source observed it.
  timestamp: string;
  // Everything else the source sent, untouched.
  raw: Record<string, unknown>;
}

// Alert to hunt spec, with no model in the loop: the entity becomes the seed and
// the rule name, when present, becomes the question. Phase 5 replaces this with
// the LLM version that synthesizes a richer prompt and maps a rule name to a
// playbook; the deterministic form keeps Phase 3 testable without a model.
export function alertToSpec(alert: Alert): HuntSpec {
  const prompt = alert.rule_name
    ? `${alert.rule_name} on ${alert.entity}`
    : `investigate suspicious activity on ${alert.entity}`;
  return buildSpec({ prompt, entity: alert.entity });
}
