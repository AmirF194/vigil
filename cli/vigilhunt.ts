#!/usr/bin/env -S npx tsx
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { createInterface } from "node:readline/promises";
import { HuntController, resumeHunt, startHunt } from "../ai/loop.js";
import { createEnricher } from "../ai/enrich.js";
import { criticFor, LlmDecisionProvider, LlmWorkerDispatcher } from "../ai/llm.js";
import { Lease } from "../ai/lease.js";
import { directiveActor, steer, type DirectiveFields } from "../ai/inbox.js";
import { pendingCheckpoints, resolutionOf, AUTO_ACTOR } from "../ai/checkpoints.js";
import { buildReport, renderReport, reportPath } from "../ai/report.js";
import {
  ScriptedDecisionProvider,
  ScriptedDisconfirmationCritic,
  ScriptedWorkerDispatcher,
  type ScriptedDecision,
} from "../ai/scripted.js";
import { buildSpec, parseEntity, SpecError, type HuntSpec } from "../ai/spec.js";
import { key } from "../ai/entities.js";
import { buildTools, closeTools } from "../ai/tools.js";
import { Ledger } from "../ai/ledger.js";
import type { Decision, Digest, DirectiveKind, Entity, WorkerEvidence } from "../ai/types.js";

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

vigilhunt --steer <ledger.jsonl> --prompt <text> [--lead | --abort | --extend | --conclude]
  Queue an operator directive. Applied at the next iteration boundary.
  --lead adds it to the frontier; --abort halts the hunt.
  At the budget checkpoint a parked hunt takes one of three answers:
  --extend --prompt "+5 iterations" (or "+$10"), --conclude, or --abort.

vigilhunt --steer <ledger.jsonl> --approve <checkpoint_id>
vigilhunt --steer <ledger.jsonl> --reject <checkpoint_id> --prompt <reason>
  Answer a raised checkpoint. The ledger is the authority: the answer is
  journaled and applied at the next boundary, whichever process runs it.

vigilhunt --steer <ledger.jsonl> --benign <entity> [--revoke]
vigilhunt --steer <ledger.jsonl> --gap <text> [--hypothesis <id>]
vigilhunt --steer <ledger.jsonl> --boost <question_id>
  Steer a running hunt. --benign stops the hunt chasing an entity without
  removing a single record; --revoke lifts it again. --gap declares a blind
  spot no query would report. --boost pins an open question to the top of
  the frontier. All three are reversible, attributed, and delete nothing.

vigilhunt checkpoints <ledger.jsonl>
  List what the hunt is waiting on: id, class, question and age.

vigilhunt report <ledger.jsonl>
  Rebuild the hunt report from the ledger. Derived, so it works at any time
  and on hunts that ended long ago.

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

function describe(spec: HuntSpec): void {
  console.log(`\nHunt: ${spec.name}`);
  spec.hypotheses.forEach((statement, index) => console.log(`  H${index + 1}. ${statement}`));

  const entity = spec.scope["entity"] as Entity | undefined;
  if (entity !== undefined) console.log(`  target: ${entity.type} ${entity.value}`);
  console.log(`  budgets: ${spec.budgets.max_iterations} iterations, $${spec.budgets.max_cost_usd.toFixed(2)}`);
  console.log(`  arch: ${spec.arch} (${spec.dispatch.mode}, up to ${spec.dispatch.max_workers} worker(s))`);
  console.log(`  model: ${spec.model}`);
}

// The prompt is delivery; the ledger is the record. startHunt has already raised
// the hypothesis_approval checkpoint, so this resolves it with a directive —
// attributed to the operator when a human answered, to policy when nobody was
// asked. A rejection returns false and the caller ends the hunt through
// terminate(), which is how a hunt that never ran still gets a report.
async function approve(ledger: Ledger, spec: HuntSpec, assumeYes: boolean): Promise<boolean> {
  describe(spec);

  const checkpoint = pendingCheckpoints(ledger.projection).find((entry) => entry.class === "hypothesis_approval");
  if (checkpoint === undefined) {
    // Policy resolved it inside startHunt. Nothing to ask, and nothing to
    // journal twice.
    return true;
  }

  const fields: DirectiveFields = { checkpoint_id: checkpoint.checkpoint_id };
  if (assumeYes) {
    steer(ledger.path, "approve", "--yes on the command line", fields);
    console.log(`\napproved ${checkpoint.checkpoint_id} as ${directiveActor()} (--yes)`);
    return true;
  }
  if (!process.stdin.isTTY) {
    // No operator to ask. Journaled as policy rather than as a person, so the
    // ledger never claims a human approved something nobody saw.
    steer(ledger.path, "approve", "no TTY: nobody was asked", { ...fields, actor: AUTO_ACTOR });
    console.log(`\napproved ${checkpoint.checkpoint_id} as ${AUTO_ACTOR} (no TTY)`);
    return true;
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question("\nApprove and start this hunt? [y/N] ")).trim().toLowerCase();
  rl.close();

  const approved = ["y", "yes"].includes(answer);
  steer(ledger.path, approved ? "approve" : "reject", approved ? "approved at the prompt" : "rejected at the prompt", fields);
  console.log(`${approved ? "approved" : "rejected"} ${checkpoint.checkpoint_id} as ${directiveActor()}`);
  return approved;
}

// Carries observables and a payload rather than a bare sentence, and couples them
// to the hunt's own seed, so --scripted exercises extraction, the graph, pivot
// candidates, EXPAND and the enrichment chains rather than skipping any of them.
// Two source systems, because the verdict predicates a scripted walk has to
// clear are the same ones a real hunt clears — one system agreeing with itself
// would never reach proven. Declared domains when the playbook has them, or the
// controller would collapse invented labels into one and nothing would prove.
function scriptedEvidence(spec: HuntSpec, hypothesisIds: string[]): WorkerEvidence[] {
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
    // Every hypothesis, because the controller will not conclude while one is
    // active: a scripted walk that resolves only the first never reaches an end.
    supports: hypothesisIds,
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

// Turns spent gathering before the walk starts testing verdicts, so a VALIDATE
// has something to rest on.
const SCRIPTED_WARMUP = 2;

// Read off the digest each turn rather than fixed in advance, because a
// checkpoint parks the hunt mid-walk: whatever an operator did while it was
// parked is what the next turn has to start from. A fixed script would re-run
// the CONCLUDE it was refused for on a hunt where it would now be granted, and
// call that a passing wiring check.
function scriptedNext(digest: Digest): Decision {
  if (digest.iteration <= SCRIPTED_WARMUP) return SCRIPTED_INVESTIGATE;

  // A verdict that landed goes to incident response mid-hunt, which is the
  // whole point of HANDOFF_IR — the hunt keeps running for the rest.
  const proven = digest.hypotheses.find((hypothesis) => hypothesis.status === "proven");
  if (proven !== undefined) {
    return {
      action: "HANDOFF_IR",
      rationale: "scripted escalation: a confirmed compromise goes to IR without waiting for the hunt to end",
      target_hypothesis_id: proven.hypothesis_id,
    };
  }

  const active = digest.hypotheses.find((hypothesis) => hypothesis.status === "active");
  if (active === undefined) return { action: "CONCLUDE", rationale: "scripted wiring check complete" };

  // One CONCLUDE the controller should refuse, so the scripted walk exercises
  // the termination predicate rather than only the happy path.
  if (digest.iteration === SCRIPTED_WARMUP + 1) {
    return { action: "CONCLUDE", rationale: "scripted early stop — the controller should refuse this" };
  }

  // Cites what exists by the time it runs: the evidence ids are not knowable
  // when the script is written.
  return {
    action: "VALIDATE",
    rationale: "scripted verdict check",
    target_hypothesis_id: active.hypothesis_id,
    evidence_citations: digest.recent_evidence.map((record) => record.evidence_id),
  };
}

function scriptedRun(iterations: number): ScriptedDecision[] {
  return Array.from({ length: Math.max(iterations, 1) }, () => scriptedNext);
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
  const hypothesisIds = [...ledger.projection.hypotheses.keys()];
  const controller = values.scripted
    ? new HuntController(
        ledger,
        new ScriptedDecisionProvider(scriptedRun(Number(values.iterations))),
        new ScriptedWorkerDispatcher(scriptedEvidence(spec, hypothesisIds)),
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
      if (result.note) console.log(`       ${result.note}`);
      // Parked is as final for this process as terminal: only an operator
      // directive moves it, and running on would spend past the budget.
      if (result.hunt_status !== "active") break;
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

function age(since: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - Date.parse(since)) / 60_000));
  if (minutes < 60) return `${minutes}m ago`;
  return minutes < 1440 ? `${Math.round(minutes / 60)}h ago` : `${Math.round(minutes / 1440)}d ago`;
}

// Delivery, not authority: everything printed here is folded from the JSONL, so
// a checkpoint raised by a process that has since died still shows up.
function checkpoints(path: string): number {
  const ledger = Ledger.open(path);
  const { hunt } = ledger.projection;
  const pending = pendingCheckpoints(ledger.projection);

  console.log(`${hunt.hunt_id} — ${hunt.name} (${hunt.status})`);

  if (pending.length === 0) {
    console.log("\nno pending checkpoints");
    // The budget park is 08's, and takes a different set of answers. Named here
    // anyway: an operator asking what a hunt is waiting on means the question,
    // not the mechanism.
    if (hunt.status === "parked") {
      console.log(`\nparked all the same — ${hunt.parked_reason ?? "awaiting an operator"}`);
      console.log(`  extend:   vigilhunt --steer ${path} --extend --prompt "+5 iterations"`);
      console.log(`  conclude: vigilhunt --steer ${path} --conclude`);
      console.log(`  abort:    vigilhunt --steer ${path} --abort`);
    }
    const resolved = ledger.projection.resolutions.length;
    if (resolved > 0) console.log(`\n${resolved} checkpoint(s) already resolved — vigilhunt report ${path}`);
    return 0;
  }

  console.log(`\n${pending.length} pending checkpoint(s):\n`);
  for (const checkpoint of pending) {
    console.log(`  ${checkpoint.checkpoint_id}  ${checkpoint.class.padEnd(19)} iteration ${checkpoint.raised_iteration}, raised ${age(checkpoint.raised_at)}`);
    console.log(`      ${checkpoint.question}`);
    console.log(`      approve: vigilhunt --steer ${path} --approve ${checkpoint.checkpoint_id}`);
    console.log(`      reject:  vigilhunt --steer ${path} --reject ${checkpoint.checkpoint_id} --prompt "why"`);
    console.log("");
  }
  return 0;
}

// Replay-derived: the report is rebuilt from the JSONL, so it works on a hunt
// that ended long ago and on one still running.
function report(path: string): number {
  const ledger = Ledger.open(path);
  const rendered = renderReport(buildReport(ledger.projection));
  const out = reportPath(path);
  writeFileSync(out, rendered);
  console.log(rendered);
  console.log(`written to ${out}`);
  return 0;
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
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
      extend: { type: "boolean", default: false },
      conclude: { type: "boolean", default: false },
      approve: { type: "string" },
      reject: { type: "string" },
      benign: { type: "string" },
      gap: { type: "string" },
      boost: { type: "string" },
      hypothesis: { type: "string" },
      revoke: { type: "boolean", default: false },
      iterations: { type: "string", default: "1" },
      scripted: { type: "boolean", default: false },
      yes: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    allowPositionals: true,
  });

  if (values.help) {
    console.log(USAGE);
    return 0;
  }

  if (positionals[0] === "report" || positionals[0] === "checkpoints") {
    const path = positionals[1];
    if (path === undefined) {
      console.error(`error: ${positionals[0]} needs a ledger path\n\n${USAGE}`);
      return 2;
    }
    return positionals[0] === "report" ? report(path) : checkpoints(path);
  }
  if (positionals.length > 0) {
    console.error(`error: unknown command ${positionals[0]}\n\n${USAGE}`);
    return 2;
  }

  if (values.steer !== undefined) {
    // The typed set first: each carries its target in a field, so the drain
    // never has to read the operator's prose to find out what they meant.
    const typed: [string, DirectiveKind, string, DirectiveFields][] = [
      [values.approve ?? "", "approve", values.prompt ?? "approved", { checkpoint_id: values.approve }],
      [values.reject ?? "", "reject", values.prompt ?? "rejected", { checkpoint_id: values.reject }],
      [
        values.benign ?? "",
        "benign",
        values.prompt ?? `${values.benign} is known-benign`,
        // Typed the same way a seed entity is, so "45.77.53.176" and
        // "host:web-01" both land on the key the graph actually uses. An
        // untyped value would suppress nothing and say it had.
        {
          entity_key: values.benign === undefined ? undefined : key(parseEntity(values.benign)),
          ...(values.revoke ? { revoke: true } : {}),
        },
      ],
      [values.gap ?? "", "gap", values.gap ?? "", { ...(values.hypothesis ? { hypothesis_id: values.hypothesis } : {}) }],
      [values.boost ?? "", "boost", values.prompt ?? `take ${values.boost} next`, { question_id: values.boost }],
    ];
    const chosen = typed.find(([target]) => target !== "");

    if (chosen !== undefined) {
      const [, kind, text, fields] = chosen;
      const directive = steer(values.steer, kind, text, fields);
      console.log(`queued ${kind} ${directive.directive_id} as ${directive.actor} for the next iteration boundary`);
      return 0;
    }

    if (!values.abort && !values.conclude && !values.prompt) {
      console.error(
        "error: --steer needs --prompt <text>, or one of --abort, --conclude, --approve <id>, " +
          "--reject <id>, --benign <entity>, --gap <text>, --boost <question_id>",
      );
      return 2;
    }
    if (values.extend && !values.prompt) {
      console.error('error: --extend needs --prompt with the grant, e.g. --prompt "+5 iterations" or "+$10"');
      return 2;
    }
    const kind = values.abort
      ? "abort"
      : values.conclude
        ? "conclude"
        : values.extend
          ? "extend"
          : values.lead
            ? "lead"
            : "note";
    const directive = steer(values.steer, kind, values.prompt ?? `operator sent ${kind}`);
    console.log(`queued ${kind} ${directive.directive_id} as ${directive.actor} for the next iteration boundary`);
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

  // Created before the prompt, not after: the approval is a checkpoint on this
  // hunt's ledger, and a hunt that was declined is a record of a hunt that was
  // declined rather than a hunt that never existed.
  const ledger = startHunt(spec, "runs");
  console.log(`\ncreated ${ledger.projection.hunt.hunt_id} -> ${ledger.path}`);

  if (!(await approve(ledger, spec, values.yes))) {
    // Through the controller, so the rejection ends the hunt the way every
    // other ending does — terminate(), and therefore Finalize and a report.
    const controller = new HuntController(ledger, new ScriptedDecisionProvider([]));
    await controller.advanceIteration();
    console.log(`rejected — ${ledger.projection.hunt.outcome}, report: ${reportPath(ledger.path)}`);
    return 1;
  }

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

  const backlog = [...questions.values()].filter((question) => question.status === "parked");
  if (backlog.length > 0) {
    console.log(`\nparked to the backlog (${backlog.length})`);
    for (const question of backlog) console.log(`  ${question.question}`);
  }

  console.log(`\n$${hunt.cost_usd.toFixed(4)} over ${hunt.iteration} iteration(s)`);

  for (const handoff of ledger.projection.handoffs) {
    console.log(`\nescalated ${handoff.hypothesis_id} to incident response as ${handoff.case_id}`);
    console.log(`  case file: ${handoff.case_file}`);
  }

  if (hunt.status === "terminal") {
    console.log(`${hunt.outcome} — report: ${reportPath(ledger.path)}`);
    return;
  }

  // What it is actually waiting on, named where the operator is standing.
  const pending = pendingCheckpoints(ledger.projection);
  if (pending.length > 0) {
    console.log(`\nwaiting on ${pending.length} checkpoint(s) — vigilhunt checkpoints ${ledger.path}`);
    for (const checkpoint of pending) {
      console.log(`  ${checkpoint.checkpoint_id}  ${checkpoint.class}: ${checkpoint.question}`);
      console.log(`    approve: vigilhunt --steer ${ledger.path} --approve ${checkpoint.checkpoint_id}`);
      console.log(`    reject:  vigilhunt --steer ${ledger.path} --reject ${checkpoint.checkpoint_id} --prompt "why"`);
    }
    return;
  }

  // The three answers a budget-parked hunt takes.
  if (hunt.status === "parked") {
    console.log(`parked — ${hunt.parked_reason ?? "awaiting an operator"}`);
    console.log(`  extend:   vigilhunt --steer ${ledger.path} --extend --prompt "+5 iterations"`);
    console.log(`  conclude: vigilhunt --steer ${ledger.path} --conclude`);
    console.log(`  abort:    vigilhunt --steer ${ledger.path} --abort`);
    return;
  }
  // Running out of --iterations otherwise reads exactly like reaching a verdict.
  console.log(`still active — resume with: vigilhunt --resume ${ledger.path}`);
}

main().then(
  (code) => process.exit(code),
  (error: Error) => {
    console.error(`error: ${error.message}`);
    process.exit(1);
  },
);
