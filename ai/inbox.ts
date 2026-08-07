import { appendFileSync, readFileSync } from "node:fs";
import { actorName } from "./lease.js";
import { newId, type Ledger } from "./ledger.js";
import type { BudgetGrant, Directive, DirectiveKind } from "./types.js";

// The controller's own voice in the directive stream. Named rather than borrowed
// from the operator so the drain can tell the two apart.
export const CONTROLLER_ACTOR = "controller";

// The stub operator a DEV_MODE deployment attributes to, so the attribution path
// is exercised with auth off rather than skipped. Read here rather than in
// lease.ts: the lease's owner is a process, this is a person.
export const DEV_ACTOR = "dev-admin";

export function directiveActor(): string {
  if (process.env["VIGIL_ACTOR"]) return actorName();
  return process.env["DEV_MODE"] === "true" ? DEV_ACTOR : actorName();
}

// A second producer alongside the workers. Any process may append here; only the
// lease holder drains it into the ledger, so the controller stays the sole mutator.
export function inboxPath(ledgerPath: string): string {
  return `${ledgerPath}.inbox.jsonl`;
}

// What an extension buys, read out of the operator's own words: "+5 iterations",
// "$10 more", "5 iterations and $2.50". Parsed once at queue time so the ledger
// records the ask as numbers, and re-read at drain for a directive written into
// the inbox by hand.
export function parseGrant(text: string): BudgetGrant {
  const iterations = /(\d+(?:\.\d+)?)\s*(?:more\s+)?iterations?/i.exec(text);
  const dollars = /\$\s*(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*(?:usd|dollars?)/i.exec(text);
  const cost = dollars?.[1] ?? dollars?.[2];

  return {
    iterations: Math.max(0, Math.floor(Number(iterations?.[1] ?? 0))),
    cost_usd: Math.max(0, Number(cost ?? 0)),
  };
}

export function grantOf(directive: Directive): BudgetGrant {
  return directive.grant ?? parseGrant(directive.text);
}

// What a directive may carry beyond its text: which checkpoint it answers, which
// entity it suppresses, which lead it pins. Typed at queue time so the drain
// reads fields rather than re-parsing prose. actor is overridable for the one
// case where the queuer is not the operator — an approval nobody was asked for
// must not be attributed to whoever happened to be logged in.
export type DirectiveFields = Partial<
  Pick<Directive, "actor" | "checkpoint_id" | "entity_key" | "question_id" | "hypothesis_id" | "tenant" | "revoke">
>;

export function steer(
  ledgerPath: string,
  kind: DirectiveKind,
  text: string,
  fields: DirectiveFields = {},
): Directive {
  const directive: Directive = {
    directive_id: newId("dir", 4),
    actor: directiveActor(),
    kind,
    text,
    created_at: new Date().toISOString(),
    origin: "inbox",
    ...(kind === "extend" ? { grant: parseGrant(text) } : {}),
    ...fields,
  };
  appendFileSync(inboxPath(ledgerPath), `${JSON.stringify(directive)}\n`);
  return directive;
}

// The controller journaling its own note, so a refusal or a clamped extension
// reaches the next digest through exactly the channel an operator's note uses.
export function journalNote(ledger: Ledger, text: string): Directive {
  const directive: Directive = {
    directive_id: newId("dir", 4),
    actor: CONTROLLER_ACTOR,
    kind: "note",
    text,
    created_at: new Date().toISOString(),
    origin: "controller",
  };
  ledger.append({ kind: "directive", directive });
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

// What the next drain would take, without taking it. The hard abort reads this
// between dispatch settlements: an operator who hit abort mid-iteration should
// not have to wait for workers the hunt has already decided not to want.
export function peek(ledger: Ledger): Directive[] {
  const recorded = ledger.projection.directives.filter((directive) => directive.origin !== "controller").length;
  return read(ledger.path).slice(recorded);
}

// Skips what the ledger already recorded rather than truncating, so the inbox
// stays append-only and a drain interrupted halfway simply re-runs. Only
// operator-authored directives are counted: the controller's own notes live in
// the same stream and would otherwise make the drain skip real input.
export function drain(ledger: Ledger): Directive[] {
  const pending = peek(ledger);
  for (const directive of pending) ledger.append({ kind: "directive", directive });
  return pending;
}
