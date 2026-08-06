import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { DEFAULT_LEASE_TTL_MS } from "./lease.js";
import { DECISION_ACTIONS, DEFAULT_BUDGETS, type Budgets, type Entity } from "./types.js";

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
}

export interface Runtime {
  concurrency: number;
  rate_limit: RateLimit;
  retry_attempts: number;
  // Must exceed a single iteration's wall time, or a live hunt loses its own lease.
  lease_ttl_ms: number;
}

export interface ToolSpec {
  id: string;
  kind: "duckdb" | "expand";
  [key: string]: unknown;
}

// One LLM role: what it is told, what shape it must answer in, what it may call.
export interface RoleSpec {
  prompt: string;
  output_schema: Record<string, unknown>;
  tools: string[];
}

export type RoleName = "lead" | "worker" | "critic";
export const ROLE_NAMES = ["lead", "worker", "critic"] as const satisfies readonly RoleName[];

// The critic is optional. An arch without one still runs a whole hunt; it simply
// has no way to reach proven, which is a legible outcome rather than an error.
export type Roles = { lead: RoleSpec; worker: RoleSpec; critic?: RoleSpec };

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
  directives: Partial<Record<RoleName, string>>;
  narrative: string;
}

// USD per million tokens. Config rather than a table in code: prices move, and
// a model with no rate would bill zero and quietly disable the cost budget.
export interface Rates {
  input: number;
  output: number;
}

// What a hypothesis must clear to be proven, and how much blindness forces it
// inconclusive. Deployment config because a two-tool shop and a full SOC do not
// have the same corroboration available.
export interface Verdicts {
  min_corroborating_sources: number;
  gap_lock_threshold: number;
}

// Where this deployment points and what it may spend.
export interface Config {
  model: string;
  rates: Rates;
  budgets: Budgets;
  runtime: Runtime;
  verdicts: Verdicts;
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
const CONFIG_KEYS = new Set(["model", "rates", "budgets", "runtime", "verdicts", "tools"]);

export const DEFAULT_MODEL = "openai/gpt-4o";
export const DEFAULT_ARCH = packaged("arch/threathunt.yaml");
export const DEFAULT_CONFIG = packaged("vigil.config.yaml");

export const DEFAULT_RUNTIME: Runtime = {
  concurrency: 4,
  rate_limit: { rpm: 60, tpm: 200_000 },
  retry_attempts: 3,
  lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
};

// Two systems because one system agreeing with itself is not corroboration;
// three gaps because a hypothesis with that much unseen around it has not been
// cleared, it has been given up on.
export const DEFAULT_VERDICTS: Verdicts = { min_corroborating_sources: 2, gap_lock_threshold: 3 };

export const DEFAULT_DISPATCH: DispatchPolicy = { mode: "serial", fan_out_over: "questions", max_workers: 1 };
export const DEFAULT_DIGEST: DigestPolicy = { evidence_window: 25 };

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

function parseDigest(raw: unknown): DigestPolicy {
  const policy = { ...DEFAULT_DIGEST, ...asRecord(raw, "digest") } as DigestPolicy;
  if (!Number.isInteger(policy.evidence_window) || policy.evidence_window < 1) {
    throw new SpecError(`digest.evidence_window must be a positive integer, got ${String(policy.evidence_window)}`);
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

function parseRole(raw: unknown, name: RoleName): RoleSpec {
  const record = asRecord(raw, `roles.${name}`);
  const prompt = str(record["prompt"]);
  if (prompt.trim() === "") throw new SpecError(`roles.${name} needs a prompt`);
  if (record["output_schema"] === undefined) throw new SpecError(`roles.${name} needs an output_schema`);

  return {
    prompt,
    output_schema: asRecord(record["output_schema"], `roles.${name}.output_schema`),
    tools: strings(record["tools"], `roles.${name}.tools`),
  };
}

function parseRoles(raw: unknown): Roles {
  const record = asRecord(raw, "roles");
  const unknown = Object.keys(record).filter((key) => !(ROLE_NAMES as readonly string[]).includes(key));
  if (unknown.length > 0) {
    throw new SpecError(`unknown role(s): ${unknown.sort().join(", ")}; expected ${ROLE_NAMES.join(", ")}`);
  }

  const roles: Roles = { lead: parseRole(record["lead"], "lead"), worker: parseRole(record["worker"], "worker") };
  if (record["critic"] !== undefined) roles.critic = parseRole(record["critic"], "critic");
  assertVocabulary(roles.lead.output_schema);
  return roles;
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

function parseDirectives(raw: unknown): Partial<Record<RoleName, string>> {
  const record = asRecord(raw, "directives");
  const unknown = Object.keys(record).filter((key) => !(ROLE_NAMES as readonly string[]).includes(key));
  if (unknown.length > 0) {
    throw new SpecError(`directives name unknown role(s): ${unknown.sort().join(", ")}`);
  }
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

function parseVerdicts(raw: unknown): Verdicts {
  const record = asRecord(raw, "verdicts");
  const unknown = Object.keys(record).filter((key) => !(key in DEFAULT_VERDICTS));
  if (unknown.length > 0) {
    throw new SpecError(
      `unknown verdicts key(s): ${unknown.sort().join(", ")}; expected any of ${Object.keys(DEFAULT_VERDICTS).sort().join(", ")}`,
    );
  }
  const verdicts = { ...DEFAULT_VERDICTS, ...record } as Verdicts;
  // A threshold of zero would either prove everything or lock everything, and
  // both read as a working hunt right up until someone trusts the verdict.
  for (const [key, value] of Object.entries(verdicts)) {
    if (!Number.isInteger(value) || value < 1) {
      throw new SpecError(`verdicts.${key} must be a positive integer, got ${String(value)}`);
    }
  }
  return verdicts;
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
    if (kind !== "duckdb" && kind !== "expand") {
      throw new SpecError(`tools[${index}] has unknown kind ${String(kind)}; expected duckdb or expand`);
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
    verdicts: parseVerdicts(front["verdicts"]),
    tools: parseTools(front["tools"]),
  };
}

export const loadArch = (path: string): ArchSpec => load(path, parseArch, "arch");
export const loadPlaybook = (path: string): Playbook => load(path, parsePlaybook, "playbook");
export const loadConfig = (path: string): Config => load(path, parseConfig, "config");

// Typed rather than assumed-an-IP: the same seed slot carries hosts, identities and hashes.
export function parseEntity(raw: string): Entity {
  if (isIP(raw) !== 0) return { type: "ip", value: raw };
  const separator = raw.indexOf(":");
  if (separator < 0) return { type: "identifier", value: raw };
  return { type: raw.slice(0, separator), value: raw.slice(separator + 1) };
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

// Playbook prose layers onto the arch prompt rather than replacing it: the
// playbook says what this dataset is, the arch says how to reason about any of them.
function applyDirectives(roles: Roles, directives: Partial<Record<RoleName, string>>, declared: Set<string>): Roles {
  const applied = ROLE_NAMES.flatMap((name) => {
    const role = roles[name];
    if (role === undefined) return [];
    const missing = role.tools.filter((id) => !declared.has(id));
    if (missing.length > 0) {
      throw new SpecError(`arch role ${name} needs tool(s) the config does not declare: ${missing.join(", ")}`);
    }
    const directive = directives[name];
    return [[name, directive ? { ...role, prompt: `${role.prompt}\n\n${directive}` } : role]];
  });
  return Object.fromEntries(applied) as Roles;
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

  return {
    ...config,
    arch: arch.name,
    roles: applyDirectives(arch.roles, playbook.directives, new Set(config.tools.map((tool) => tool.id))),
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
