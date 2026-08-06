import { isIP } from "node:net";
import type { Entity, EvidenceRecord } from "./types.js";

// A payload full of addresses would otherwise let one record dominate the graph.
const PER_RECORD_CAP = 25;

const CANDIDATES: readonly [string, RegExp][] = [
  ["ip", /\b\d{1,3}(?:\.\d{1,3}){3}\b/g],
  ["ip", /\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b/gi],
  ["hash", /\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b/gi],
  ["domain", /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b/gi],
];

export function key(entity: Entity): string {
  return `${entity.type}:${entity.value}`;
}

// Matched loosely then validated, because a regex tight enough to accept only
// real addresses is unreadable and still wrong on IPv6.
function accepts(type: string, value: string): boolean {
  return type === "ip" ? isIP(value) !== 0 : true;
}

// Extraction rather than worker self-report: it runs for every dispatcher, so a
// worker that omits a field cannot silently disable the floor rules built on it.
export function extract(text: string): Entity[] {
  const found = new Map<string, Entity>();
  for (const [type, pattern] of CANDIDATES) {
    for (const match of text.matchAll(pattern)) {
      const value = match[0].toLowerCase();
      if (!accepts(type, value)) continue;
      const entity = { type, value };
      if (!found.has(key(entity))) found.set(key(entity), entity);
    }
  }
  return [...found.values()].slice(0, PER_RECORD_CAP);
}

export function entitiesOf(record: Pick<EvidenceRecord, "summary" | "payload">): Entity[] {
  return extract(`${record.summary}\n${JSON.stringify(record.payload ?? {})}`);
}

export interface EntityNode {
  entity: Entity;
  count: number;
  first_evidence_id: string;
  pairs: Map<string, number>;
}

export interface GraphView {
  nodes: Map<string, EntityNode>;
  // Entity keys each record was the first to mention, in captured order.
  introduced: Map<string, string[]>;
}

// Compute-on-read over the entities the records already carry: there is no
// second copy of the graph, so there is nothing for it to drift from.
export function entityGraph(ordered: readonly EvidenceRecord[], seed?: Entity): GraphView {
  const nodes = new Map<string, EntityNode>();
  const introduced = new Map<string, string[]>();

  // The seed is the hunt's own target. Reporting it as first-seen would promote
  // whichever record happened to mention it first, which says nothing.
  if (seed !== undefined) {
    nodes.set(key(seed), { entity: seed, count: 0, first_evidence_id: "", pairs: new Map() });
  }

  for (const record of ordered) {
    const entities = record.entities ?? [];
    introduced.set(record.evidence_id, entities.filter((entity) => visit(nodes, entity, record.evidence_id)).map(key));
    couple(nodes, entities.map(key));
  }
  return { nodes, introduced };
}

// Returns true when this record is the first to mention the entity.
function visit(nodes: Map<string, EntityNode>, entity: Entity, evidenceId: string): boolean {
  const node = nodes.get(key(entity));
  if (node !== undefined) {
    node.count += 1;
    return false;
  }
  nodes.set(key(entity), { entity, count: 1, first_evidence_id: evidenceId, pairs: new Map() });
  return true;
}

function couple(nodes: Map<string, EntityNode>, keys: readonly string[]): void {
  for (const id of keys) {
    const pairs = nodes.get(id)!.pairs;
    for (const other of keys) {
      if (other !== id) pairs.set(other, (pairs.get(other) ?? 0) + 1);
    }
  }
}

function recurs(graph: GraphView, id: string): boolean {
  return (graph.nodes.get(id)?.count ?? 0) > 1;
}

// A rare pairing of entities the hunt otherwise knows well. Both must recur, or
// every pair of one-off addresses reads as rare and the signal is only sparsity.
export function hasRarePairing(record: EvidenceRecord, graph: GraphView, max: number): boolean {
  const keys = (record.entities ?? []).map(key).filter((id) => recurs(graph, id));
  return keys.some((id) => {
    const pairs = graph.nodes.get(id)!.pairs;
    return keys.some((other) => other !== id && (pairs.get(other) ?? 0) <= max);
  });
}

// This record was the first sighting of something that went on to recur. A value
// seen exactly once is a one-off, and telemetry is full of them — promoting those
// would fire on nearly every record, which ranks nothing.
export function introducedRecurring(record: EvidenceRecord, graph: GraphView): boolean {
  return (graph.introduced.get(record.evidence_id) ?? []).some((id) => recurs(graph, id));
}
