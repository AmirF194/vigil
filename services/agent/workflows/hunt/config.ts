import type { Counts, RunSpec } from "../../core/spec.js";

// The core spec carries domain config as untyped numeric bags, so what a
// threshold means is stated here rather than in a harness the hunt shares.

export interface Verdicts {
  min_corroborating_sources: number;
  gap_lock_threshold: number;
}

// Two systems because one system agreeing with itself is not corroboration;
// three gaps because a hypothesis with that much unseen has not been cleared.
export const DEFAULT_VERDICTS: Verdicts = { min_corroborating_sources: 2, gap_lock_threshold: 3 };

export interface Termination {
  priority_floor: number;
  park_ttl_ms: number;
  hard_max_calls: number;
  hard_max_cost_usd: number;
}

// A frontier score tops out at 16, so five is a novel lead bearing on one active
// hypothesis: below it a lead is backlog rather than a reason to keep spending.
export const DEFAULT_TERMINATION: Termination = {
  priority_floor: 5,
  park_ttl_ms: 604_800_000,
  hard_max_calls: 24,
  hard_max_cost_usd: 10,
};

export interface DigestPolicy {
  evidence_window: number;
  resurface: number;
  rare_pairing_max: number;
  graph_warmup: number;
  contrarian_max: number;
  entity_window: number;
  pivot_candidates: number;
}

export const DEFAULT_DIGEST: DigestPolicy = {
  evidence_window: 25,
  resurface: 3,
  rare_pairing_max: 1,
  graph_warmup: 20,
  contrarian_max: 3,
  entity_window: 15,
  pivot_candidates: 5,
};

// A bag the deployment left out keeps the default, key by key: a config naming
// one threshold should not silently drop the rest.
function over<T extends object>(defaults: T, held: Counts): T {
  const merged = { ...defaults } as Record<string, number>;
  for (const key of Object.keys(defaults)) {
    const value = held[key];
    if (typeof value === "number") merged[key] = value;
  }
  return merged as T;
}

export function verdictsOf(spec: RunSpec): Verdicts {
  return over(DEFAULT_VERDICTS, spec.thresholds);
}

export function terminationOf(spec: RunSpec): Termination {
  return over(DEFAULT_TERMINATION, spec.thresholds);
}

export function digestOf(spec: RunSpec): DigestPolicy {
  return over(DEFAULT_DIGEST, spec.digest);
}

export interface EnrichmentChain {
  id: string;
  on: string;
  tool: string;
  query: string;
}

export interface EnrichmentPolicy {
  max_depth: number;
  max_entities: number;
  chains: EnrichmentChain[];
}

export const DEFAULT_ENRICHMENT: EnrichmentPolicy = { max_depth: 1, max_entities: 8, chains: [] };
