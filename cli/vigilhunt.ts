#!/usr/bin/env -S npx tsx
import { parseArgs } from "node:util";
import { createInterface } from "node:readline/promises";
import { HuntController, resumeHunt, startHunt } from "../ai/loop.js";
import { createEnricher } from "../ai/enrich.js";
import { criticFor, LlmDecisionProvider, LlmWorkerDispatcher } from "../ai/llm.js";
import { Lease } from "../ai/lease.js";
import { steer } from "../ai/inbox.js";
import {
  ScriptedDecisionProvider,
  ScriptedDisconfirmationCritic,
  ScriptedWorkerDispatcher,
  type ScriptedDecision,
} from "../ai/scripted.js";
import { buildSpec, SpecError, type HuntSpec } from "../ai/spec.js";
import { buildTools, closeTools } from "../ai/tools.js";
import type { Ledger } from "../ai/ledger.js";
import type { Digest, Entity, WorkerEvidence } from "../ai/types.js";

const USAGE = `vigilhunt --prompt <prompt> --id <entity> --workflow <playbook.yaml>

  --prompt    the question to hunt; may be used alone
  --id        seed entity (10.0.0.1, host:web-01); never alone
  --workflow  playbook: hypotheses, ATT&CK mapping, directives; never alone

  --arch PATH      loop architecture (default arch/threathunt.yaml)
  --config PATH    model, budgets and tools (default vigil.config.yaml)
  --iterations N   turns to run (default 1)
  --scripted       run without an LLM, for wiring checks
  --yes            skip the hypothesis approval prompt

vigilhunt --resume <ledger.jsonl> [--iterations N]
  Continue a hunt. Its spec came with the ledger, so no spec flags apply.

vigilhunt --steer <ledger.jsonl> --prompt <text> [--lead | --abort]
  Queue an operator directive. Applied at the next iteration boundary.
  --lead adds it to the frontier; --abort halts the hunt.

Ctrl-C pauses after the current iteration and offers a directive prompt.`;

// The three entry rules, verbatim: --workflow and --id each need company,
// --prompt may stand alone.
function validateEntry(prompt?: string, entity?: string, workflow?: string): string | null {
  if (prompt === undefined && entity === undefined && workflow === undefined) {
    return "nothing to hunt: give --prompt, or --workflow with --prompt or --id";
  }
  if (workflow !== undefined && prompt === undefined && entity === undefined) {
    return "--workflow never runs alone: add --prompt or --id";
  }
  if (entity !== undefined && prompt === undefined && workflow === undefined) {
    return "--id names a target but does not say what to look for: add --prompt or --workflow";
  }
  return null;
}

async function approve(spec: HuntSpec, assumeYes: boolean): Promise<boolean> {
  console.log(`\nHunt: ${spec.name}`);
  spec.hypotheses.forEach((statement, index) => console.log(`  H${index + 1}. ${statement}`));

  const entity = spec.scope["entity"] as Entity | undefined;
  if (entity !== undefined) console.log(`  target: ${entity.type} ${entity.value}`);
  console.log(`  budgets: ${spec.budgets.max_iterations} iterations, $${spec.budgets.max_cost_usd.toFixed(2)}`);
  console.log(`  arch: ${spec.arch} (${spec.dispatch.mode}, up to ${spec.dispatch.max_workers} worker(s))`);
  console.log(`  model: ${spec.model}`);

  if (assumeYes || !process.stdin.isTTY) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question("\nApprove and start this hunt? [y/N] ");
  rl.close();
  return ["y", "yes"].includes(answer.trim().toLowerCase());
}

// Carries observables and a payload rather than a bare sentence, and couples them
// to the hunt's own seed, so --scripted exercises extraction, the graph, pivot
// candidates, EXPAND and the enrichment chains rather than skipping any of them.
// Two source systems, because the verdict predicates a scripted walk has to
// clear are the same ones a real hunt clears — one system agreeing with itself
// would never reach proven. Declared domains when the playbook has them, or the
// controller would collapse invented labels into one and nothing would prove.
function scriptedEvidence(spec: HuntSpec, hypothesisId: string): WorkerEvidence[] {
  const seed = (spec.scope["entity"] as Entity | undefined)?.value ?? "10.0.0.5";
  const sources = spec.data_domains.length >= 2 ? spec.data_domains.slice(0, 2) : ["scripted-siem", "scripted-edr"];

  return sources.map((source) => ({
    source_system: source,
    summary: `${source}: ${seed} reached cdn.example.com and 45.77.53.176, no telemetry was queried`,
    payload: {
      rows: [
        { src_ip: seed, dest_ip: "45.77.53.176", dest_host: "cdn.example.com", process: "powershell.exe", connections: 412 },
      ],
    },
    salience: "routine" as const,
    why_notable: "",
    provenance: "worker",
    attacker_influenceable: false,
    instruction_like: false,
    supports: [hypothesisId],
  }));
}

// Answers every chain the config declares, so --scripted exercises the depth
// bound, the once-per-entity rule and the value guard without a database.
function scriptedEnricher(spec: HuntSpec) {
  const chains = spec.enrichment.chains;
  if (chains.length === 0) return undefined;

  return async (entity: Entity) =>
    chains
      .filter((chain) => chain.on === entity.type)
      .map((chain) => ({
        source_system: chain.id,
        summary: `${chain.id} on ${entity.type}:${entity.value}: scripted, no query was run`,
        payload: { chain: chain.id, entity: `${entity.type}:${entity.value}`, result: "scripted" },
        salience: "routine" as const,
        why_notable: `deterministic ${chain.id} enrichment; no one chose to run it`,
        provenance: `enrichment:${chain.id}`,
        attacker_influenceable: true,
        instruction_like: false,
      }));
}

const SCRIPTED_INVESTIGATE = {
  action: "INVESTIGATE" as const,
  rationale: "scripted wiring check",
  query_intent: "scripted query",
};

// Investigate for most of the run rather than concluding at once, so --scripted
// exercises dispatch, steering and resume; the last two turns walk the verdict
// path, which is the other half of the wiring.
function scriptedRun(iterations: number, hypothesisId: string): ScriptedDecision[] {
  if (iterations < 3) return Array.from({ length: iterations }, () => SCRIPTED_INVESTIGATE);

  return [
    ...Array.from({ length: iterations - 2 }, () => SCRIPTED_INVESTIGATE),
    // Cites what exists by the time it runs: the evidence ids are not knowable
    // when the script is written.
    (digest: Digest) => ({
      action: "VALIDATE" as const,
      rationale: "scripted verdict check",
      target_hypothesis_id: hypothesisId,
      evidence_citations: digest.recent_evidence.map((record) => record.evidence_id),
    }),
    { action: "CONCLUDE" as const, rationale: "scripted wiring check complete" },
  ];
}

// First Ctrl-C parks after the current iteration so nothing is lost; a second
// exits, and the interrupted iteration is reaped on the next resume.
function onInterrupt(pause: () => void): void {
  let asked = false;
  process.on("SIGINT", () => {
    if (asked) process.exit(130);
    asked = true;
    console.log("\npausing after this iteration — Ctrl-C again to stop now");
    pause();
  });
}

async function directivePrompt(ledgerPath: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question("\nsteer (blank to continue, /lead <text>, /abort): ")).trim();
  rl.close();

  if (answer === "") return true;
  if (answer === "/abort") {
    steer(ledgerPath, "abort", "operator halted the hunt");
    return false;
  }
  const lead = answer.startsWith("/lead ");
  steer(ledgerPath, lead ? "lead" : "note", lead ? answer.slice(6).trim() : answer);
  return true;
}

async function run(ledger: Ledger, spec: HuntSpec, values: Values): Promise<void> {
  const lease = Lease.acquire(ledger.path, spec.runtime.lease_ttl_ms);
  process.on("exit", () => lease.release());

  const tools = values.scripted ? [] : await buildTools(spec, ledger);
  const hypothesisId = [...ledger.projection.hypotheses.keys()][0] ?? "";
  const controller = values.scripted
    ? new HuntController(
        ledger,
        new ScriptedDecisionProvider(scriptedRun(Number(values.iterations), hypothesisId)),
        new ScriptedWorkerDispatcher(scriptedEvidence(spec, hypothesisId)),
        spec.dispatch,
        spec.digest,
        scriptedEnricher(spec),
        new ScriptedDisconfirmationCritic(),
        spec.verdicts,
      )
    : new HuntController(
        ledger,
        new LlmDecisionProvider(spec, tools),
        new LlmWorkerDispatcher(spec, tools),
        spec.dispatch,
        spec.digest,
        createEnricher(spec, tools),
        criticFor(spec, tools),
        spec.verdicts,
      );

  const reaped = controller.reap();
  if (reaped > 0) console.log(`reaped ${reaped} interrupted dispatch(es) — their leads are open again`);

  let paused = false;
  onInterrupt(() => {
    paused = true;
  });

  try {
    for (let turn = 0; turn < Number(values.iterations); turn += 1) {
      const result = await controller.advanceIteration();
      const outcome = result.hunt_outcome === null ? "" : ` (${result.hunt_outcome})`;
      const enriched = result.enriched === 0 ? "" : ` enriched+${result.enriched}`;
      console.log(
        `  [${result.iteration}] ${result.action.padEnd(12)} evidence+${result.evidence_appended}${enriched}` +
          `  $${result.cost_usd.toFixed(4)}  ${result.hunt_status}${outcome}`,
      );
      if (result.hunt_status === "terminal") break;
      lease.renew();

      if (paused) {
        paused = false;
        if (!(await directivePrompt(ledger.path))) break;
      }
    }
  } finally {
    await closeTools(tools);
    lease.release();
  }

  summarize(ledger);
}

type Values = { iterations: string; scripted: boolean; yes: boolean };

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      prompt: { type: "string" },
      id: { type: "string" },
      workflow: { type: "string" },
      arch: { type: "string" },
      config: { type: "string" },
      resume: { type: "string" },
      steer: { type: "string" },
      lead: { type: "boolean", default: false },
      abort: { type: "boolean", default: false },
      iterations: { type: "string", default: "1" },
      scripted: { type: "boolean", default: false },
      yes: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    console.log(USAGE);
    return 0;
  }

  if (values.steer !== undefined) {
    if (!values.abort && !values.prompt) {
      console.error("error: --steer needs --prompt <text>, or --abort");
      return 2;
    }
    const kind = values.abort ? "abort" : values.lead ? "lead" : "note";
    const directive = steer(values.steer, kind, values.prompt ?? "operator halted the hunt");
    console.log(`queued ${kind} ${directive.directive_id} for the next iteration boundary`);
    return 0;
  }

  if (values.resume !== undefined) {
    if (values.prompt ?? values.id ?? values.workflow ?? values.arch ?? values.config) {
      console.error("error: --resume takes its spec from the ledger; drop the spec flags");
      return 2;
    }
    const { ledger, spec } = resumeHunt(values.resume);
    console.log(`resuming ${ledger.projection.hunt.hunt_id} at iteration ${ledger.projection.hunt.iteration}`);
    await run(ledger, spec, values);
    return 0;
  }

  const invalid = validateEntry(values.prompt, values.id, values.workflow);
  if (invalid !== null) {
    console.error(`error: ${invalid}\n\n${USAGE}`);
    return 2;
  }

  let spec: HuntSpec;
  try {
    spec = buildSpec({
      archPath: values.arch,
      workflowPath: values.workflow,
      configPath: values.config,
      prompt: values.prompt,
      entity: values.id,
    });
  } catch (error) {
    console.error(`error: ${error instanceof SpecError ? error.message : String(error)}`);
    return 2;
  }

  if (!(await approve(spec, values.yes))) {
    console.log("aborted — no hunt created");
    return 1;
  }

  const ledger = startHunt(spec, "runs");
  console.log(`\ncreated ${ledger.projection.hunt.hunt_id} -> ${ledger.path}`);
  await run(ledger, spec, values);
  return 0;
}

function summarize(ledger: Ledger): void {
  const { hunt, hypotheses, evidence, questions } = ledger.projection;

  console.log("\nhypotheses");
  for (const hypothesis of hypotheses.values()) {
    console.log(`  [${hypothesis.status.padEnd(12)}] ${hypothesis.statement}`);
    // A verdict nobody can read the reasoning of is not an auditable verdict.
    if (hypothesis.resolution_reason) console.log(`                 ${hypothesis.resolution_reason}`);
  }

  const gaps = [...evidence.values()].filter((record) => record.provenance === "tool_failure");
  console.log(`\nevidence (${evidence.size}, ${gaps.length} visibility gap(s))`);
  for (const record of evidence.values()) {
    console.log(`  ${record.evidence_id}  ${record.salience.padEnd(9)} ${record.summary}`);
  }

  const open = [...questions.values()].filter((question) => question.status === "open");
  if (open.length > 0) {
    console.log(`\nopen questions (${open.length})`);
    for (const question of open) console.log(`  ${question.question}`);
  }

  console.log(`\n$${hunt.cost_usd.toFixed(4)} over ${hunt.iteration} iteration(s)`);
  // Running out of --iterations otherwise reads exactly like reaching a verdict.
  if (hunt.status !== "terminal") {
    console.log(`still active — resume with: vigilhunt --resume ${ledger.path}`);
  }
}

main().then(
  (code) => process.exit(code),
  (error: Error) => {
    console.error(`error: ${error.message}`);
    process.exit(1);
  },
);
