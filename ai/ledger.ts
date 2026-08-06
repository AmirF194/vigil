import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname } from "node:path";
import {
  SCHEMA_VERSION,
  type DecisionRecord,
  type Directive,
  type DispatchRecord,
  type EvidenceLink,
  type EvidenceRecord,
  type Hypothesis,
  type HuntState,
  type OpenQuestion,
} from "./types.js";

export type PatchTarget = "hunt" | "hypothesis" | "question" | "dispatch";

export type LedgerBody =
  | { kind: "hunt"; hunt: HuntState }
  | { kind: "hypothesis"; hypothesis: Hypothesis }
  | { kind: "question"; question: OpenQuestion }
  | { kind: "evidence"; evidence: EvidenceRecord }
  | { kind: "link"; link: EvidenceLink }
  | { kind: "dispatch"; dispatch: DispatchRecord }
  | { kind: "decision"; decision: DecisionRecord }
  | { kind: "directive"; directive: Directive }
  | { kind: "patch"; target: PatchTarget; id: string; fields: Record<string, unknown> };

export type LedgerEvent = LedgerBody & {
  seq: number;
  ts: string;
  schema_version: number;
};

export interface Projection {
  hunt: HuntState;
  hypotheses: Map<string, Hypothesis>;
  questions: Map<string, OpenQuestion>;
  evidence: Map<string, EvidenceRecord>;
  links: EvidenceLink[];
  dispatches: Map<string, DispatchRecord>;
  decisions: DecisionRecord[];
  directives: Directive[];
}

export function newId(prefix: string, bytes = 6): string {
  return `${prefix}-${randomBytes(bytes).toString("hex")}`;
}

export class LedgerError extends Error {}

// Append-only JSONL. Every mutation is an event; the projection is a fold and
// is never written back, so the file on disk is the whole audit trail.
export class Ledger {
  readonly path: string;
  private events: LedgerEvent[] = [];
  private view: Projection | null = null;

  private constructor(path: string) {
    this.path = path;
  }

  static create(path: string, hunt: HuntState): Ledger {
    if (existsSync(path)) throw new LedgerError(`ledger already exists: ${path}`);
    mkdirSync(dirname(path), { recursive: true });
    const ledger = new Ledger(path);
    ledger.append({ kind: "hunt", hunt });
    return ledger;
  }

  static open(path: string): Ledger {
    if (!existsSync(path)) throw new LedgerError(`no such ledger: ${path}`);
    const ledger = new Ledger(path);
    ledger.events = readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as LedgerEvent);
    return ledger;
  }

  append(body: LedgerBody): LedgerEvent {
    const event: LedgerEvent = {
      ...body,
      seq: this.events.length,
      ts: new Date().toISOString(),
      schema_version: SCHEMA_VERSION,
    };
    appendFileSync(this.path, `${JSON.stringify(event)}\n`);
    this.events.push(event);
    this.view = null;
    return event;
  }

  patch(target: PatchTarget, id: string, fields: Record<string, unknown>): void {
    this.append({ kind: "patch", target, id, fields });
  }

  get projection(): Projection {
    if (this.view === null) this.view = fold(this.events);
    return this.view;
  }
}

export function fold(events: readonly LedgerEvent[]): Projection {
  const first = events[0];
  if (first === undefined || first.kind !== "hunt") {
    throw new LedgerError("ledger does not open with a hunt event");
  }

  const view: Projection = {
    hunt: structuredClone(first.hunt),
    hypotheses: new Map(),
    questions: new Map(),
    evidence: new Map(),
    links: [],
    dispatches: new Map(),
    decisions: [],
    directives: [],
  };

  for (const event of events.slice(1)) {
    switch (event.kind) {
      case "hunt":
        throw new LedgerError(`second hunt event at seq ${event.seq}`);
      case "hypothesis":
        view.hypotheses.set(event.hypothesis.hypothesis_id, structuredClone(event.hypothesis));
        break;
      case "question":
        view.questions.set(event.question.question_id, structuredClone(event.question));
        break;
      case "evidence":
        view.evidence.set(event.evidence.evidence_id, structuredClone(event.evidence));
        break;
      case "link":
        view.links.push(structuredClone(event.link));
        break;
      case "dispatch":
        view.dispatches.set(event.dispatch.dispatch_id, structuredClone(event.dispatch));
        break;
      case "decision":
        view.decisions.push(structuredClone(event.decision));
        break;
      case "directive":
        view.directives.push(structuredClone(event.directive));
        break;
      case "patch":
        applyPatch(view, event);
        break;
    }
  }
  return view;
}

function applyPatch(view: Projection, event: LedgerEvent & { kind: "patch" }): void {
  const target =
    event.target === "hunt"
      ? view.hunt
      : event.target === "hypothesis"
        ? view.hypotheses.get(event.id)
        : event.target === "question"
          ? view.questions.get(event.id)
          : view.dispatches.get(event.id);

  if (target === undefined) {
    throw new LedgerError(`patch at seq ${event.seq} targets unknown ${event.target} ${event.id}`);
  }
  Object.assign(target, event.fields);
}
