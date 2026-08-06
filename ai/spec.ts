import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { DEFAULT_LEASE_TTL_MS } from "./lease.js";
import { DECISION_ACTIONS, DEFAULT_BUDGETS, ENTITY_TYPES, type Budgets, type Entity, type EntityType } from "./types.js";

export class SpecError extends Error {}

export interface RateLimit {
  rpm: number;
  tpm: number;
}

// Serial is parallel with one worker. The "hypothesis/ledger method" is not a
// mode at all — it is the record vocabulary and the digest rules, both already data.
export interface DispatchPolicy {
  mode: "serial" | "parallel";
  fan_out_over: "questions" | "hypotheses";
  max_workers: number;
}

export interface DigestPolicy {
  evidence_window: number;
  // Routine records resampled per iteration so the window's tail is not lost.
  resurface: number;
  rare_pairing_max: number;
  // Evidence records before the entity rules activate; below it everything is new.
  graph_warmup: number;
  contrarian_max: number;
  entity_window: number;
  pivot_candidates: number;
}

export interface Runtime {
  concurrency: number;
  rate_limit: RateLimit;
  retry_attempts: number;
  // Must exceed a single iteration's wall time, or a live hunt loses its own lease.
  lease_ttl_ms: number;
}

export const TOOL_KINDS = new Set(["duckdb", "expand", "threatfox"]);

export interface ToolSpec {
  id: string;
  kind: string;
  [key: string]: unknown;
}

// One LLM role: what it is told, what shape it must answer in, what it may call.
// description is the one line the Hunt Lead reads when choosing a worker.
export interface RoleSpec {
  prompt: string;
  description: string;
  output_schema: Record<string, unknown>;
  tools: string[];
}

// The agent-ID registry: worker keys are the ids the lead may name, so adding a
// specialist is a YAML block rather than a change here.
export interface Roles {
  lead: RoleSpec;
  workers: Record<string, RoleSpec>;
}

// Reserved directive key: prose every worker needs, such as what the dataset is.
export const ALL_WORKERS = "workers";

// The loop's shape: what the roles are told, what they must answer in, how an
// iteration fans out. Operator-authored and never uploaded.
export interface ArchSpec {
  name: string;
  roles: Roles;
  dispatch: DispatchPolicy;
  digest: DigestPolicy;
}

// The uploadable layer: what to hunt and what an analyst should know. No schemas.
export interface Playbook {
  name: string;
  hypotheses: string[];
  attack_techniques: string[];
  data_domains: string[];
  scope: Record<string, unknown>;
  directives: Record<string, string>;
  narrative: string;
}

// USD per million tokens. Config rather than a table in code: prices move, and
// a model with no rate would bill zero and quietly disable the cost budget.
export interface Rates {
  input: number;
  output: number;
}

// Where this deployment points and what it may spend.
export interface Config {
  model: string;
  rates: Rates;
  budgets: Budgets;
  runtime: Runtime;
  tools: ToolSpec[];
}

export interface HuntSpec extends Config, Omit<Playbook, "directives"> {
  arch: string;
  roles: Roles;
  dispatch: DispatchPolicy;
  digest: DigestPolicy;
}

// Disjoint by design: a key in the wrong file is a load error rather than a
// silent default, and there is no precedence chain to reason about.
const ARCH_KEYS = new Set(["name", "roles", "dispatch", "digest"]);
const PLAYBOOK_KEYS = new Set([
  "name",
  "hypotheses",
  "attack_techniques",
  "data_domains",
  "scope",
  "directives",
  "narrative",
]);
const CONFIG_KEYS = new Set(["model", "rates", "budgets", "runtime", "tools"]);

export const DEFAULT_MODEL = "openai/gpt-4o";
export const DEFAULT_ARCH = packaged("arch/threathunt.yaml");
export const DEFAULT_CONFIG = packaged("vigil.config.yaml");

export const DEFAULT_RUNTIME: Runtime = {
  concurrency: 4,
  rate_limit: { rpm: 60, tpm: 200_000 },
  retry_attempts: 3,
  lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
};

export const DEFAULT_DISPATCH: DispatchPolicy = { mode: "serial", fan_out_over: "questions", max_workers: 1 };
export const DEFAULT_DIGEST: DigestPolicy = {
  evidence_window: 25,
  resurface: 3,
  rare_pairing_max: 1,
  graph_warmup: 20,
  contrarian_max: 3,
  entity_window: 15,
  pivot_candidates: 5,
};

// Resolved against the package rather than the cwd: arch and config ship with
// the tool, so a hunt run from any directory finds the same ones.
function packaged(relative: string): string {
  return fileURLToPath(new URL(`../${relative}`, import.meta.url));
}

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

function splitFrontMatter(text: string): [Record<string, unknown>, string] {
  const trimmed = text.trimStart();
  if (!trimmed.startsWith("---")) return [asRecord(parseYaml(text), "document"), ""];

  const parts = trimmed.split("---");
  if (parts.length < 3) throw new SpecError("unterminated YAML front matter (expected a closing ---)");
  return [asRecord(parseYaml(parts[1] ?? ""), "front matter"), parts.slice(2).join("---").trim()];
}

// One reader for all three layers. A misplaced `budgets` would otherwise hand an
// autonomous hunt the default budget without saying so.
function layer(text: string, keys: ReadonlySet<string>, name: string): [Record<string, unknown>, string] {
  const [front, body] = splitFrontMatter(text);
  const unknown = Object.keys(front).filter((key) => !keys.has(key));
  if (unknown.length > 0) {
    throw new SpecError(
      `${name}: key(s) ${unknown.sort().join(", ")} do not belong in a ${name} file; expected any of ${[...keys].sort().join(", ")}`,
    );
  }
  return [front, body];
}

function load<T>(path: string, parse: (text: string) => T, name: string): T {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new SpecError(`no such ${name}: ${path}`);
    throw new SpecError(`unreadable ${name} ${path}: ${(error as Error).message}`);
  }
  try {
    return parse(text);
  } catch (error) {
    if (error instanceof SpecError) throw new SpecError(`${path}: ${error.message}`);
    throw new SpecError(`invalid ${name} ${path}: ${(error as Error).message}`);
  }
}

function parseDispatch(raw: unknown): DispatchPolicy {
  const record = asRecord(raw, "dispatch");
  const policy = { ...DEFAULT_DISPATCH, ...record } as DispatchPolicy;

  if (policy.mode !== "serial" && policy.mode !== "parallel") {
    throw new SpecError(`dispatch.mode must be serial or parallel, got ${String(policy.mode)}`);
  }
  if (policy.fan_out_over !== "questions" && policy.fan_out_over !== "hypotheses") {
    throw new SpecError(`dispatch.fan_out_over must be questions or hypotheses, got ${String(policy.fan_out_over)}`);
  }
  if (!Number.isInteger(policy.max_workers) || policy.max_workers < 1) {
    throw new SpecError(`dispatch.max_workers must be a positive integer, got ${String(policy.max_workers)}`);
  }
  return policy.mode === "serial" ? { ...policy, max_workers: 1 } : policy;
}

// resurface and rare_pairing_max may be zero, which disables them; the rest size
// a window and a zero-width window shows nothing.
const DIGEST_MINIMA: Record<keyof DigestPolicy, number> = {
  evidence_window: 1,
  resurface: 0,
  rare_pairing_max: 0,
  graph_warmup: 1,
  contrarian_max: 1,
  entity_window: 1,
  pivot_candidates: 1,
};

function parseDigest(raw: unknown): DigestPolicy {
  const policy = { ...DEFAULT_DIGEST, ...asRecord(raw, "digest") } as DigestPolicy;
  for (const [field, minimum] of Object.entries(DIGEST_MINIMA)) {
    const value = policy[field as keyof DigestPolicy];
    if (!Number.isInteger(value) || value < minimum) {
      throw new SpecError(`digest.${field} must be an integer >= ${minimum}, got ${String(value)}`);
    }
  }
  return policy;
}

// An arch may drop a verb its pipeline has no use for, but a verb the controller
// cannot execute is a dead end the lead would keep choosing.
function assertVocabulary(schema: Record<string, unknown>): void {
  const properties = asRecord(schema["properties"], "roles.lead.output_schema.properties");
  const declared = asRecord(properties["action"], "roles.lead.output_schema.properties.action")["enum"];
  if (!Array.isArray(declared) || declared.length === 0) {
    throw new SpecError("roles.lead.output_schema needs a non-empty action enum");
  }
  const invented = declared.map(String).filter((action) => !(DECISION_ACTIONS as readonly string[]).includes(action));
  if (invented.length > 0) {
    throw new SpecError(`roles.lead declares action(s) the controller cannot run: ${invented.sort().join(", ")}`);
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
  const record = asRecord(raw, "roles.workers");
  if (Object.keys(record).length === 0) throw new SpecError("roles.workers must declare at least one worker");

  return Object.fromEntries(
    Object.entries(record).map(([id, value]) => {
      const role = parseRole(value, `workers.${id}`);
      // Without it the generated roster is blank and the lead chooses on the id alone.
      if (role.description.trim() === "") throw new SpecError(`roles.workers.${id} needs a description`);
      return [id, preamble ? { ...role, prompt: `${preamble}\n\n${role.prompt}` } : role];
    }),
  );
}

const ROLE_GROUPS = new Set(["lead", ALL_WORKERS, "workers_preamble"]);

function parseRoles(raw: unknown): Roles {
  const record = asRecord(raw, "roles");
  const unknown = Object.keys(record).filter((key) => !ROLE_GROUPS.has(key));
  if (unknown.length > 0) {
    throw new SpecError(
      `unknown role group(s): ${unknown.sort().join(", ")}; expected any of ${[...ROLE_GROUPS].sort().join(", ")}`,
    );
  }

  const lead = parseRole(record["lead"], "lead");
  assertVocabulary(lead.output_schema);
  return { lead, workers: parseWorkers(record[ALL_WORKERS], str(record["workers_preamble"]).trim()) };
}

export function parseArch(text: string): ArchSpec {
  const [front] = layer(text, ARCH_KEYS, "arch");
  return {
    name: str(front["name"]) || "unnamed",
    roles: parseRoles(front["roles"]),
    dispatch: parseDispatch(front["dispatch"]),
    digest: parseDigest(front["digest"]),
  };
}

// Names are checked against the arch's registry in applyDirectives, not here: a
// playbook is read without knowing which arch it will run under.
function parseDirectives(raw: unknown): Record<string, string> {
  const record = asRecord(raw, "directives");
  return Object.fromEntries(Object.entries(record).map(([role, value]) => [role, String(value)]));
}

export function parsePlaybook(text: string): Playbook {
  const [front, body] = layer(text, PLAYBOOK_KEYS, "playbook");
  return {
    name: str(front["name"]),
    hypotheses: strings(front["hypotheses"], "hypotheses"),
    attack_techniques: strings(front["attack_techniques"], "attack_techniques"),
    data_domains: strings(front["data_domains"], "data_domains"),
    scope: asRecord(front["scope"], "scope"),
    directives: parseDirectives(front["directives"]),
    narrative: body || str(front["narrative"]),
  };
}

function parseBudgets(raw: unknown): Budgets {
  const record = asRecord(raw, "budgets");
  const unknown = Object.keys(record).filter((key) => !(key in DEFAULT_BUDGETS));
  if (unknown.length > 0) {
    throw new SpecError(
      `unknown budget key(s): ${unknown.sort().join(", ")}; expected any of ${Object.keys(DEFAULT_BUDGETS).sort().join(", ")}`,
    );
  }
  return { ...DEFAULT_BUDGETS, ...record } as Budgets;
}

function parseRuntime(raw: unknown): Runtime {
  const record = asRecord(raw, "runtime");
  return {
    ...DEFAULT_RUNTIME,
    ...record,
    rate_limit: { ...DEFAULT_RUNTIME.rate_limit, ...asRecord(record["rate_limit"], "rate_limit") },
  } as Runtime;
}

function parseTools(raw: unknown): ToolSpec[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new SpecError("tools must be a list");
  return raw.map((entry, index) => {
    const tool = asRecord(entry, `tools[${index}]`);
    const id = tool["id"];
    const kind = tool["kind"];
    if (typeof id !== "string") throw new SpecError(`tools[${index}] needs a string id`);
    if (typeof kind !== "string" || !TOOL_KINDS.has(kind)) {
      throw new SpecError(
        `tools[${index}] has unknown kind ${String(kind)}; expected any of ${[...TOOL_KINDS].sort().join(", ")}`,
      );
    }
    return { ...tool, id, kind } as ToolSpec;
  });
}

function parseRates(raw: unknown, model: string): Rates {
  const record = asRecord(raw, "rates");
  const rates = { input: Number(record["input"]), output: Number(record["output"]) };
  if (!Number.isFinite(rates.input) || !Number.isFinite(rates.output)) {
    throw new SpecError(`rates must give input and output USD per million tokens for ${model}`);
  }
  return rates;
}

export function parseConfig(text: string): Config {
  const [front] = layer(text, CONFIG_KEYS, "config");
  const model = str(front["model"]) || DEFAULT_MODEL;
  return {
    model,
    rates: parseRates(front["rates"], model),
    budgets: parseBudgets(front["budgets"]),
    runtime: parseRuntime(front["runtime"]),
    tools: parseTools(front["tools"]),
  };
}

export const loadArch = (path: string): ArchSpec => load(path, parseArch, "arch");
export const loadPlaybook = (path: string): Playbook => load(path, parsePlaybook, "playbook");
export const loadConfig = (path: string): Config => load(path, parseConfig, "config");

// Typed rather than assumed-an-IP: the same seed slot carries hosts, identities
// and hashes. The type must be one the graph also uses, or a hunt could not
// pivot onto its own seed.
export function parseEntity(raw: string): Entity {
  if (isIP(raw) !== 0) return { type: "ip", value: raw.toLowerCase() };

  const separator = raw.indexOf(":");
  if (separator < 0) return { type: "host", value: raw.toLowerCase() };

  const type = raw.slice(0, separator).toLowerCase();
  if (!(ENTITY_TYPES as readonly string[]).includes(type)) {
    throw new SpecError(`unknown entity type ${type}; expected any of ${[...ENTITY_TYPES].sort().join(", ")}`);
  }
  return { type: type as EntityType, value: raw.slice(separator + 1).toLowerCase() };
}

const EMPTY_PLAYBOOK: Playbook = {
  name: "",
  hypotheses: [],
  attack_techniques: [],
  data_domains: [],
  scope: {},
  directives: {},
  narrative: "",
};

function extend(role: RoleSpec, name: string, additions: (string | undefined)[], declared: Set<string>): RoleSpec {
  const missing = role.tools.filter((id) => !declared.has(id));
  if (missing.length > 0) {
    throw new SpecError(`arch role ${name} needs tool(s) the config does not declare: ${missing.join(", ")}`);
  }
  const prompt = [role.prompt, ...additions.filter((text) => text)].join("\n\n");
  return prompt === role.prompt ? role : { ...role, prompt };
}

// Playbook prose layers onto the arch prompt rather than replacing it: the
// playbook says what this dataset is, the arch says how to reason about any of them.
function applyDirectives(roles: Roles, directives: Record<string, string>, declared: Set<string>): Roles {
  const known = new Set(["lead", ALL_WORKERS, ...Object.keys(roles.workers)]);
  const unknown = Object.keys(directives).filter((key) => !known.has(key));
  if (unknown.length > 0) {
    throw new SpecError(
      `directives name unknown role(s): ${unknown.sort().join(", ")}; expected any of ${[...known].sort().join(", ")}`,
    );
  }

  // Dataset facts belong to every worker, so the reserved key lands on all of
  // them before any per-worker prose.
  const shared = directives[ALL_WORKERS];
  const workers = Object.entries(roles.workers).map(([id, role]) => [
    id,
    extend(role, id, [shared, directives[id]], declared),
  ]);
  return {
    lead: extend(roles.lead, "lead", [directives["lead"]], declared),
    workers: Object.fromEntries(workers) as Record<string, RoleSpec>,
  };
}

// Generated from the registry rather than written into the prompt, so the roster
// the lead reads cannot drift from the workers that actually exist.
function roster(workers: Record<string, RoleSpec>): string {
  return [
    "## Workers you may dispatch",
    "Name exactly one of these in worker_agent_id when you INVESTIGATE.",
    ...Object.entries(workers).map(([id, role]) => `- ${id} — ${role.description}`),
  ].join("\n");
}

// The one place the three layers and the flags converge.
export function buildSpec(options: {
  archPath?: string | undefined;
  workflowPath?: string | undefined;
  configPath?: string | undefined;
  prompt?: string | undefined;
  entity?: string | undefined;
}): HuntSpec {
  const arch = loadArch(options.archPath ?? DEFAULT_ARCH);
  const config = loadConfig(options.configPath ?? DEFAULT_CONFIG);
  const playbook = options.workflowPath === undefined ? EMPTY_PLAYBOOK : loadPlaybook(options.workflowPath);

  const hypotheses = [...playbook.hypotheses];
  if (options.prompt) hypotheses.push(options.prompt);
  if (hypotheses.length === 0) {
    throw new SpecError("nothing to test: give --prompt, or a --workflow that declares hypotheses");
  }

  const scope = { ...playbook.scope };
  if (options.entity !== undefined) scope["entity"] = parseEntity(options.entity);

  let name = playbook.name;
  if (!name) {
    const entity = scope["entity"] as Entity | undefined;
    name = options.prompt ?? `hunt on ${entity?.value ?? "unnamed"}`;
    if (name.length > 60) name = `${name.slice(0, 57)}...`;
  }

  const roles = applyDirectives(arch.roles, playbook.directives, new Set(config.tools.map((tool) => tool.id)));

  return {
    ...config,
    arch: arch.name,
    roles: { ...roles, lead: { ...roles.lead, prompt: `${roles.lead.prompt}\n\n${roster(roles.workers)}` } },
    dispatch: arch.dispatch,
    digest: arch.digest,
    name,
    hypotheses,
    attack_techniques: playbook.attack_techniques,
    data_domains: playbook.data_domains,
    scope,
    narrative: playbook.narrative,
  };
}
