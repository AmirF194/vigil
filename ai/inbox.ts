import { appendFileSync, readFileSync } from "node:fs";
import { actorName } from "./lease.js";
import { newId, type Ledger } from "./ledger.js";
import type { Directive, DirectiveKind } from "./types.js";

// A second producer alongside the workers. Any process may append here; only the
// lease holder drains it into the ledger, so the controller stays the sole mutator.
export function inboxPath(ledgerPath: string): string {
  return `${ledgerPath}.inbox.jsonl`;
}

export function steer(ledgerPath: string, kind: DirectiveKind, text: string): Directive {
  const directive: Directive = {
    directive_id: newId("dir", 4),
    actor: actorName(),
    kind,
    text,
    created_at: new Date().toISOString(),
  };
  appendFileSync(inboxPath(ledgerPath), `${JSON.stringify(directive)}\n`);
  return directive;
}

function read(ledgerPath: string): Directive[] {
  try {
    return readFileSync(inboxPath(ledgerPath), "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Directive);
  } catch {
    return [];
  }
}

// Skips what the ledger already recorded rather than truncating, so the inbox
// stays append-only and a drain interrupted halfway simply re-runs.
export function drain(ledger: Ledger): Directive[] {
  const pending = read(ledger.path).slice(ledger.projection.directives.length);
  for (const directive of pending) ledger.append({ kind: "directive", directive });
  return pending;
}
