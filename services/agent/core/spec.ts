import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import type { BudgetLimits } from "../contracts/budget.js";

export class SpecError extends Error {}

// Serial is parallel with one worker, so there is no second loop to maintain.
export interface DispatchPolicy {
  mode: "serial" | "parallel";
  fan_out_over: string;
  max_workers: number;
}

// Opaque counts: what a window means belongs to whoever folds the ledger, and the
// harness would have to know a domain to check any of them.
export type Counts = Readonly<Record<string, number>>;

// One role: what it is told, what shape it must answer in, what it may call.
// description is the one line the lead reads when choosing a worker.
export interface RoleSpec {
  prompt: string;
  description: string;
  output_schema: Record<string, unknown>;
  tools: string[];
}

// Worker keys are the ids the lead may name, so adding a specialist is a YAML
// block rather than a change here. Both companions are optional.
export interface Roles {
  lead: RoleSpec;
  workers: Record<string, RoleSpec>;
  critic?: RoleSpec;
}

// The shape of a loop, operator-authored and never uploaded.
export interface ArchSpec {
  name: string;
  roles: Roles;
  dispatch: DispatchPolicy;
  digest: Counts;
}

// The uploadable layer: the scenario, and what an analyst should know. No schemas.
export interface Playbook {
  name: string;
  objectives: string[];
  scope: Record<string, unknown>;
  directives: Record<string, string>;
  narrative: string;
}

export interface ToolSpec {
  id: string;
  kind: string;
  [key: string]: unknown;
}

export interface Runtime {
  max_turns: number;
  result_cap: number;
  recall_limit: number;
}

// Deployment: where this points, what it may spend, what it may call, which calls
// stop for a human, and the numbers a workflow measures itself against.
export interface Config {
  model: string;
  budgets: BudgetLimits;
  runtime: Runtime;
  tools: ToolSpec[];
  approvals: string[];
  thresholds: Counts;
}

export interface RunSpec extends Config, Omit<Playbook, "directives"> {
  arch: string;
  roles: Roles;
  dispatch: DispatchPolicy;
  digest: Counts;
}

// Reserved directive key: prose every worker needs, such as what the data is.
export const ALL_WORKERS = "workers";

export const DEFAULT_DISPATCH: DispatchPolicy = { mode: "serial", fan_out_over: "questions", max_workers: 1 };
export const DEFAULT_BUDGETS: BudgetLimits = { max_calls: 12, max_cost_usd: 5, max_wall_ms: 1_800_000 };
export const DEFAULT_RUNTIME: Runtime = { max_turns: 8, result_cap: 20_000, recall_limit: 3 };

// Disjoint by design: a key in the wrong file is a load error rather than a silent
// default, and there is no precedence chain to reason about.
const LAYERS = {
  arch: ["name", "roles", "dispatch", "digest"],
  playbook: ["name", "objectives", "scope", "directives", "narrative"],
  config: ["model", "budgets", "runtime", "tools", "approvals", "thresholds"],
} as const;

export type Layer = keyof typeof LAYERS;

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (value === null || value === undefined) return {};
  if (typeof value !== "object" || Array.isArray(value)) throw new SpecError(`${what} must be a mapping`);
  return value as Record<string, unknown>;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function strings(value: unknown, field: string): string[] {
  if (value === undefined || value === null) return [];
  if (typeof value === "string") return [value];
  if (!Array.isArray(value)) throw new SpecError(`${field} must be a string or a list of strings`);
  return value.map(String);
}

// One merge for every block that is a fixed key set over defaults, so an unknown
// key is refused in the same shape wherever it appears.
function merge<T extends object>(raw: unknown, defaults: T, what: string): T {
  const record = asRecord(raw, what);
  const stray = Object.keys(record).filter((key) => !(key in defaults));
  if (stray.length > 0) {
    throw new SpecError(
      `unknown ${what} key(s): ${stray.sort().join(", ")}; expected any of ${Object.keys(defaults).sort().join(", ")}`,
    );
  }
  return { ...defaults, ...record };
}

function counts(raw: unknown, what: string): Counts {
  const record = asRecord(raw, what);
  for (const [field, value] of Object.entries(record)) {
    if (!Number.isInteger(value) || (value as number) < 0) {
      throw new SpecError(`${what}.${field} must be a non-negative integer, got ${String(value)}`);
    }
  }
  return record as Counts;
}

function positive<T extends object>(block: T, what: string): T {
  for (const [field, value] of Object.entries(block)) {
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw new SpecError(`${what}.${field} must be a positive number, got ${String(value)}`);
    }
  }
  return block;
}

function splitFrontMatter(text: string): [Record<string, unknown>, string] {
  const trimmed = text.trimStart();
  if (!trimmed.startsWith("---")) return [asRecord(parseYaml(text), "document"), ""];

  const parts = trimmed.split("---");
  if (parts.length < 3) throw new SpecError("unterminated YAML front matter (expected a closing ---)");
  return [asRecord(parseYaml(parts[1] ?? ""), "front matter"), parts.slice(2).join("---").trim()];
}

// Names the file a stray key belongs in: the three layers are disjoint, so a
// misplaced budgets is a typo with an address, not an unknown key.
function placed(key: string, layer: Layer): string {
  const owner = (Object.keys(LAYERS) as Layer[]).find((other) => (LAYERS[other] as readonly string[]).includes(key));
  if (owner !== undefined) return `${key} belongs in the ${owner} file, not the ${layer} file`;
  return `${key} belongs in no file; a ${layer} file takes any of ${[...LAYERS[layer]].sort().join(", ")}`;
}

// One reader for all three layers. A misplaced budgets would otherwise hand an
// autonomous run the default budget without saying so.
function read(text: string, layer: Layer): [Record<string, unknown>, string] {
  const [front, body] = splitFrontMatter(text);
  const stray = Object.keys(front).filter((key) => !(LAYERS[layer] as readonly string[]).includes(key));
  if (stray.length > 0) throw new SpecError(stray.sort().map((key) => placed(key, layer)).join("; "));
  return [front, body];
}

function load<T>(path: string, parse: (text: string) => T, layer: Layer): T {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new SpecError(`no such ${layer} file: ${path}`);
    throw new SpecError(`unreadable ${layer} file ${path}: ${(error as Error).message}`);
  }
  try {
    return parse(text);
  } catch (error) {
    if (error instanceof SpecError) throw new SpecError(`${path}: ${error.message}`);
    throw new SpecError(`invalid ${layer} file ${path}: ${(error as Error).message}`);
  }
}

// mode is checked against max_workers rather than coerced into it: silently
// rewriting a count the operator wrote makes mode a field nothing reads.
function parseDispatch(raw: unknown): DispatchPolicy {
  const policy = merge(raw, DEFAULT_DISPATCH, "dispatch");
  if (policy.mode !== "serial" && policy.mode !== "parallel") {
    throw new SpecError(`dispatch.mode must be serial or parallel, got ${String(policy.mode)}`);
  }
  if (str(policy.fan_out_over).trim() === "") throw new SpecError("dispatch.fan_out_over must name what an iteration fans out over");
  if (!Number.isInteger(policy.max_workers) || policy.max_workers < 1) {
    throw new SpecError(`dispatch.max_workers must be a positive integer, got ${String(policy.max_workers)}`);
  }
  if (policy.mode === "serial" && policy.max_workers !== 1) {
    throw new SpecError(`dispatch.mode serial is max_workers 1, so ${policy.max_workers} contradicts it; say parallel or drop the count`);
  }
  return policy;
}

// An arch may drop an action its pipeline has no use for, but one no workflow
// handles is a dead end the lead would keep choosing.
function assertVocabulary(schema: Record<string, unknown>, handled: readonly string[]): void {
  const properties = asRecord(schema["properties"], "roles.lead.output_schema.properties");
  const declared = asRecord(properties["action"], "roles.lead.output_schema.properties.action")["enum"];
  if (!Array.isArray(declared) || declared.length === 0) {
    throw new SpecError("roles.lead.output_schema needs a non-empty action enum");
  }
  const invented = declared.map(String).filter((action) => !handled.includes(action));
  if (invented.length > 0) {
    throw new SpecError(`roles.lead declares action(s) no workflow handles: ${invented.sort().join(", ")}`);
  }
}

function parseRole(raw: unknown, name: string): RoleSpec {
  const record = asRecord(raw, `roles.${name}`);
  const prompt = str(record["prompt"]);
  if (prompt.trim() === "") throw new SpecError(`roles.${name} needs a prompt`);
  if (record["output_schema"] === undefined) throw new SpecError(`roles.${name} needs an output_schema`);

  return {
    prompt,
    description: str(record["description"]),
    output_schema: asRecord(record["output_schema"], `roles.${name}.output_schema`),
    tools: strings(record["tools"], `roles.${name}.tools`),
  };
}

// preamble is the discipline every specialist shares, so the arch states it once
// instead of repeating it per worker.
function parseWorkers(raw: unknown, preamble: string): Record<string, RoleSpec> {
  return Object.fromEntries(
    Object.entries(asRecord(raw, "roles.workers")).map(([id, value]) => {
      const role = parseRole(value, `workers.${id}`);
      // Without it the generated roster is blank and the lead chooses on the id alone.
      if (role.description.trim() === "") throw new SpecError(`roles.workers.${id} needs a description`);
      return [id, preamble ? { ...role, prompt: `${preamble}\n\n${role.prompt}` } : role];
    }),
  );
}

const ROLE_GROUPS = ["lead", ALL_WORKERS, "workers_preamble", "critic"];

function parseRoles(raw: unknown, handled: readonly string[]): Roles {
  const record = asRecord(raw, "roles");
  const stray = Object.keys(record).filter((key) => !ROLE_GROUPS.includes(key));
  if (stray.length > 0) {
    throw new SpecError(`unknown role group(s): ${stray.sort().join(", ")}; expected any of ${[...ROLE_GROUPS].sort().join(", ")}`);
  }

  const lead = parseRole(record["lead"], "lead");
  assertVocabulary(lead.output_schema, handled);
  const roles: Roles = { lead, workers: parseWorkers(record[ALL_WORKERS], str(record["workers_preamble"]).trim()) };
  if (record["critic"] !== undefined) roles.critic = parseRole(record["critic"], "critic");
  return roles;
}

export function parseArch(text: string, handled: readonly string[]): ArchSpec {
  const [front] = read(text, "arch");
  return {
    name: str(front["name"]) || "unnamed",
    roles: parseRoles(front["roles"], handled),
    dispatch: parseDispatch(front["dispatch"]),
    digest: counts(front["digest"], "digest"),
  };
}

// Role names are checked against the arch's registry in applyDirectives, not
// here: a playbook is read without knowing which arch it will run under.
export function parsePlaybook(text: string): Playbook {
  const [front, body] = read(text, "playbook");
  const directives = asRecord(front["directives"], "directives");
  return {
    name: str(front["name"]),
    objectives: strings(front["objectives"], "objectives"),
    scope: asRecord(front["scope"], "scope"),
    directives: Object.fromEntries(Object.entries(directives).map(([role, value]) => [role, String(value)])),
    narrative: body || str(front["narrative"]),
  };
}

function parseTools(raw: unknown): ToolSpec[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new SpecError("tools must be a list");
  return raw.map((entry, index) => {
    const tool = asRecord(entry, `tools[${index}]`);
    if (typeof tool["id"] !== "string" || typeof tool["kind"] !== "string") {
      throw new SpecError(`tools[${index}] needs a string id and a string kind`);
    }
    return tool as ToolSpec;
  });
}

export function parseConfig(text: string): Config {
  const [front] = read(text, "config");
  const model = str(front["model"]);
  if (model.trim() === "") throw new SpecError("config needs a model: a deployment that names none bills nothing and answers nothing");

  const tools = parseTools(front["tools"]);
  const declared = new Set(tools.map((tool) => tool.id));
  if (declared.size !== tools.length) throw new SpecError("tools declares the same id twice");

  const approvals = strings(front["approvals"], "approvals");
  const ungranted = approvals.filter((id) => !declared.has(id));
  if (ungranted.length > 0) throw new SpecError(`approvals name tool(s) this config does not declare: ${ungranted.sort().join(", ")}`);

  return {
    model,
    budgets: positive(merge(front["budgets"], DEFAULT_BUDGETS, "budgets"), "budgets"),
    runtime: positive(merge(front["runtime"], DEFAULT_RUNTIME, "runtime"), "runtime"),
    tools,
    approvals,
    thresholds: counts(front["thresholds"], "thresholds"),
  };
}

function extend(role: RoleSpec, name: string, additions: (string | undefined)[], declared: ReadonlySet<string>): RoleSpec {
  const missing = role.tools.filter((id) => !declared.has(id));
  if (missing.length > 0) {
    throw new SpecError(`arch role ${name} needs tool(s) the config does not declare: ${missing.join(", ")}`);
  }
  const prompt = [role.prompt, ...additions.filter((text) => text)].join("\n\n");
  return prompt === role.prompt ? role : { ...role, prompt };
}

// Playbook prose layers onto the arch prompt rather than replacing it: the
// playbook says what this scenario is, the arch says how to reason about any of them.
function applyDirectives(roles: Roles, directives: Record<string, string>, declared: ReadonlySet<string>): Roles {
  const known = new Set(["lead", ALL_WORKERS, "critic", ...Object.keys(roles.workers)]);
  const stray = Object.keys(directives).filter((key) => !known.has(key));
  if (stray.length > 0) {
    throw new SpecError(`directives name unknown role(s): ${stray.sort().join(", ")}; expected any of ${[...known].sort().join(", ")}`);
  }

  const shared = directives[ALL_WORKERS];
  const workers = Object.entries(roles.workers).map(([id, role]) => [id, extend(role, id, [shared, directives[id]], declared)]);
  const applied: Roles = {
    lead: extend(roles.lead, "lead", [directives["lead"]], declared),
    workers: Object.fromEntries(workers) as Record<string, RoleSpec>,
  };
  if (roles.critic !== undefined) applied.critic = extend(roles.critic, "critic", [directives["critic"]], declared);
  return applied;
}

// Generated from the registry rather than written into the prompt, so the roster
// the lead reads cannot drift from the workers that actually exist.
function roster(workers: Record<string, RoleSpec>): string {
  return [
    "## Workers you may dispatch",
    "Name exactly one of these in worker_agent_id when you dispatch.",
    ...Object.entries(workers).map(([id, role]) => `- ${id} — ${role.description}`),
  ].join("\n");
}

// The registry again, as a schema constraint: an unconstrained string is where a
// struggling emission puts its overflow, and the id arrives carrying half a query.
function constrainWorkerId(schema: Record<string, unknown>, workers: Record<string, RoleSpec>): Record<string, unknown> {
  const properties = asRecord(schema["properties"], "roles.lead.output_schema.properties");
  const field = properties["worker_agent_id"];
  if (typeof field !== "object" || field === null) return schema;
  const ids: (string | null)[] = [...Object.keys(workers), null];
  return { ...schema, properties: { ...properties, worker_agent_id: { ...field, enum: ids } } };
}

export interface SpecPaths {
  arch: string;
  playbook: string;
  config: string;
}

// The one place the three layers converge. handled is the workflow's action set,
// which is what makes an arch declaring anything else a load error.
export function buildSpec(paths: SpecPaths, handled: readonly string[]): RunSpec {
  const arch = load(paths.arch, (text) => parseArch(text, handled), "arch");
  const config = load(paths.config, parseConfig, "config");
  const playbook = load(paths.playbook, parsePlaybook, "playbook");

  const declared = new Set(config.tools.map((tool) => tool.id));
  const roles = applyDirectives(arch.roles, playbook.directives, declared);
  const staffed = Object.keys(roles.workers).length > 0;

  return {
    ...config,
    arch: arch.name,
    roles: {
      ...roles,
      lead: {
        ...roles.lead,
        prompt: staffed ? `${roles.lead.prompt}\n\n${roster(roles.workers)}` : roles.lead.prompt,
        output_schema: staffed ? constrainWorkerId(roles.lead.output_schema, roles.workers) : roles.lead.output_schema,
      },
    },
    dispatch: arch.dispatch,
    digest: arch.digest,
    name: playbook.name || arch.name,
    objectives: playbook.objectives,
    scope: playbook.scope,
    narrative: playbook.narrative,
  };
}
