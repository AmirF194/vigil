#!/usr/bin/env -S npx tsx
import { parseArgs } from "node:util";
import { createInterface } from "node:readline/promises";
import { HuntController, startHunt } from "../ai/loop.js";
import { LlmDecisionProvider, LlmWorkerDispatcher } from "../ai/llm.js";
import { ScriptedDecisionProvider, ScriptedWorkerDispatcher } from "../ai/scripted.js";
import { buildSpec, SpecError, type HuntSpec } from "../ai/spec.js";
import { buildTools, closeTools } from "../ai/tools.js";
import type { Entity } from "../ai/types.js";

const USAGE = `vigilhunt --prompt <prompt> --id <entity> --workflow <spec.yaml>

  --prompt    the question to hunt; may be used alone
  --id        seed entity (10.0.0.1, host:web-01); never alone
  --workflow  hunt spec with roles, tools and budgets; never alone

  --iterations N   turns to run (default 1)
  --scripted       run without an LLM, for wiring checks
  --yes            skip the hypothesis approval prompt`;

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
  console.log(`  model: ${spec.model}`);

  if (assumeYes || !process.stdin.isTTY) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question("\nApprove and start this hunt? [y/N] ");
  rl.close();
  return ["y", "yes"].includes(answer.trim().toLowerCase());
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      prompt: { type: "string" },
      id: { type: "string" },
      workflow: { type: "string" },
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

  const invalid = validateEntry(values.prompt, values.id, values.workflow);
  if (invalid !== null) {
    console.error(`error: ${invalid}\n\n${USAGE}`);
    return 2;
  }

  let spec: HuntSpec;
  try {
    spec = buildSpec({ specPath: values.workflow, prompt: values.prompt, entity: values.id });
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

  const tools = values.scripted ? [] : await buildTools(spec, ledger);
  const controller = values.scripted
    ? new HuntController(ledger, new ScriptedDecisionProvider([]), new ScriptedWorkerDispatcher())
    : new HuntController(ledger, new LlmDecisionProvider(spec, tools), new LlmWorkerDispatcher(spec, tools));

  try {
    for (let turn = 0; turn < Number(values.iterations); turn += 1) {
      const result = await controller.advanceIteration();
      const outcome = result.hunt_outcome === null ? "" : ` (${result.hunt_outcome})`;
      console.log(
        `  [${result.iteration}] ${result.action.padEnd(12)} evidence+${result.evidence_appended}` +
          `  $${result.cost_usd.toFixed(4)}  ${result.hunt_status}${outcome}`,
      );
      if (result.hunt_status === "terminal") break;
    }
  } finally {
    await closeTools(tools);
  }

  summarize(ledger);
  return 0;
}

function summarize(ledger: ReturnType<typeof startHunt>): void {
  const { hunt, hypotheses, evidence, questions } = ledger.projection;

  console.log("\nhypotheses");
  for (const hypothesis of hypotheses.values()) {
    console.log(`  [${hypothesis.status.padEnd(12)}] ${hypothesis.statement}`);
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
    console.log("still active — stopped at the --iterations limit, not at a verdict.");
  }
}

main().then(
  (code) => process.exit(code),
  (error: Error) => {
    console.error(`error: ${error.message}`);
    process.exit(1);
  },
);
