import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { rankFrontier } from "../ai/digest.js";
import { entitiesOf } from "../ai/entities.js";
import { createEnricher, templatable } from "../ai/enrich.js";
import { assertReadOnly, UnsafeQuery } from "../tools/duckdb.js";
import { Ledger, newId } from "../ai/ledger.js";
import { HuntController, InvalidDecision, validateDecision } from "../ai/loop.js";
import { ScriptedDecisionProvider, ScriptedWorkerDispatcher } from "../ai/scripted.js";
import { buildSpec, parseConfig, SpecError, type HuntSpec } from "../ai/spec.js";
import type { Enricher } from "../ai/ports.js";
import type { Decision, Entity, EvidenceRecord, OpenQuestion, WorkerEvidence } from "../ai/types.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "enrich-"));
});

const CHAINS = `
model: openai/gpt-4o
rates: { input: 1, output: 1 }
tools:
  - id: duckdb_query
    kind: duckdb
enrichment:
  max_depth: 2
  max_entities: 2
  chains:
    - id: process_lineage
      on: process
      tool: duckdb_query
      query: SELECT parent FROM win_events WHERE process = '{{value}}'
`;

function specWith(config: string, hypotheses = ["a process was launched by something unexpected"]): HuntSpec {
  return { ...buildSpec({ prompt: hypotheses[0] }), ...parseConfig(config), hypotheses };
}

function ledgerFor(spec: HuntSpec): Ledger {
  return Ledger.create(join(dir, `${newId("run")}.jsonl`), {
    hunt_id: newId("hunt"),
    name: "test",
    spec,
    seed: "seed-0",
    status: "active",
    outcome: null,
    iteration: 0,
    cost_usd: 0,
    budgets: { max_iterations: 20, max_cost_usd: 25 },
    scope: {},
    narrative: "",
    created_at: new Date().toISOString(),
    terminated_at: null,
    parked_at: null,
    parked_reason: null,
    termination_reason: null,
  });
}

function evidence(overrides: Partial<WorkerEvidence> = {}): WorkerEvidence {
  return {
    source_system: "duckdb",
    summary: "a finding",
    payload: {},
    salience: "routine",
    why_notable: "",
    provenance: "worker",
    attacker_influenceable: false,
    instruction_like: false,
    ...overrides,
  };
}

describe("the value guard", () => {
  // The value is telemetry an adversary wrote, and it is interpolated into SQL.
  it("accepts the real shapes and refuses what cannot be quoted", () => {
    expect(templatable("c:\\windows\\syswow64\\dllhost.exe")).toBe(true);
    // Most Windows binaries worth enriching live under a path with a space.
    expect(templatable("c:\\program files (x86)\\internet explorer\\iexplore.exe")).toBe(true);
    expect(templatable("10.0.0.5")).toBe(true);

    expect(templatable('a"b')).toBe(false);
    expect(templatable("a\u0000b")).toBe(false);
    expect(templatable("")).toBe(false);
    expect(templatable("x".repeat(257))).toBe(false);
  });

  function recordingTool(asked: string[]) {
    return { id: "duckdb_query", description: "", parameters: {}, run: async (args: Record<string, unknown>) => (asked.push(String(args["sql"])), "1 row") };
  }

  it("keeps a quote inside the string literal instead of reopening SQL", async () => {
    const asked: string[] = [];
    const enricher = createEnricher(specWith(CHAINS), [recordingTool(asked)])!;

    await enricher({ type: "process", value: "o'brien.exe" });
    expect(asked).toEqual(["SELECT parent FROM win_events WHERE process = 'o''brien.exe'"]);
    expect(() => assertReadOnly(asked[0]!)).not.toThrow();
  });

  it("is refused a second time by the tool when the value carries a statement break", async () => {
    const asked: string[] = [];
    const enricher = createEnricher(specWith(CHAINS), [recordingTool(asked)])!;

    await enricher({ type: "process", value: "evil'; SELECT 1 --" });
    expect(asked).toEqual(["SELECT parent FROM win_events WHERE process = 'evil''; SELECT 1 --'"]);
    // The escape already made it inert; assertReadOnly refuses it regardless,
    // because it reads a semicolon anywhere as a second statement.
    expect(() => assertReadOnly(asked[0]!)).toThrow(UnsafeQuery);
  });

  it("does not run a chain for a value it cannot template", async () => {
    const asked: string[] = [];
    const enricher = createEnricher(specWith(CHAINS), [recordingTool(asked)])!;

    expect(await enricher({ type: "process", value: 'evil"' })).toEqual([]);
    expect(await enricher({ type: "process", value: "powershell.exe" })).toHaveLength(1);
    expect(asked).toEqual(["SELECT parent FROM win_events WHERE process = 'powershell.exe'"]);
  });

  it("refuses at load time a chain that names a tool nothing built", () => {
    expect(() => createEnricher(specWith(CHAINS), [])).toThrow(SpecError);
  });

  it("refuses a chain with no placeholder, which is a hunt-wide query in disguise", () => {
    const noPlaceholder = CHAINS.replace("WHERE process = '{{value}}'", "LIMIT 5");
    expect(() => parseConfig(noPlaceholder)).toThrow(/interpolate \{\{value\}\}/);
    expect(() => parseConfig(CHAINS.replace("on: process", "on: widget"))).toThrow(SpecError);
  });
});

describe("enrichment in the loop", () => {
  // Every process the enricher is asked about, in order.
  function recording(depth: (value: string) => string | null): { enricher: Enricher; asked: string[] } {
    const asked: string[] = [];
    const enricher: Enricher = async (entity) => {
      asked.push(entity.value);
      const next = depth(entity.value);
      return [
        evidence({
          source_system: "process_lineage",
          summary: next === null ? `${entity.value} has no parent` : `${entity.value} was launched by ${next}`,
          payload: { chain: "process_lineage", entity: `${entity.type}:${entity.value}`, parent_process: next },
          provenance: "enrichment:process_lineage",
          attacker_influenceable: true,
        }),
      ];
    };
    return { enricher, asked };
  }

  const LINEAGE: Record<string, string | null> = {
    "powershell.exe": "explorer.exe",
    "explorer.exe": "userinit.exe",
    "userinit.exe": null,
  };

  async function runOnce(enricher: Enricher, spec = specWith(CHAINS)) {
    const ledger = ledgerFor(spec);
    const result = await new HuntController(
      ledger,
      new ScriptedDecisionProvider([{ action: "INVESTIGATE", rationale: "go", query_intent: "go" }]),
      new ScriptedWorkerDispatcher([evidence({ summary: "saw a process start", payload: { process: "powershell.exe" } })]),
      spec.dispatch,
      spec.digest,
      enricher,
    ).advanceIteration();
    return { ledger, result };
  }

  it("fires on a new entity without spending an iteration", async () => {
    const { enricher } = recording((value) => LINEAGE[value] ?? null);
    const { ledger, result } = await runOnce(enricher);

    expect(result.evidence_appended).toBe(1);
    expect(result.enriched).toBeGreaterThan(0);
    // The whole point: extra evidence landed, and it cost exactly one decision.
    expect(ledger.projection.hunt.iteration).toBe(1);
    expect(ledger.projection.decisions).toHaveLength(1);

    const enriched = [...ledger.projection.evidence.values()].filter((r) => r.provenance === "enrichment:process_lineage");
    expect(enriched.length).toBe(result.enriched);
    expect(enriched[0]!.dispatch_id).toBeNull();
    expect(enriched.every((record) => record.attacker_influenceable)).toBe(true);
  });

  it("stops at max_depth rather than walking the whole lineage", async () => {
    const { enricher, asked } = recording((value) => LINEAGE[value] ?? null);
    await runOnce(enricher);

    // max_depth is 2, and userinit.exe is three links down.
    expect(asked).toEqual(["powershell.exe", "explorer.exe"]);
  });

  it("never enriches the same entity twice, including after a reopen", async () => {
    const { enricher, asked } = recording(() => null);
    const spec = specWith(CHAINS);
    const { ledger } = await runOnce(enricher, spec);
    expect(asked).toEqual(["powershell.exe"]);

    const reopened = Ledger.open(ledger.path);
    await new HuntController(
      reopened,
      new ScriptedDecisionProvider([{ action: "INVESTIGATE", rationale: "again", query_intent: "again" }]),
      new ScriptedWorkerDispatcher([evidence({ summary: "same process again", payload: { process: "powershell.exe" } })]),
      spec.dispatch,
      spec.digest,
      enricher,
    ).advanceIteration();

    expect(asked).toEqual(["powershell.exe"]);
  });

  it("caps how wide one round goes", async () => {
    const { enricher, asked } = recording(() => null);
    const spec = specWith(CHAINS);
    const ledger = ledgerFor(spec);
    await new HuntController(
      ledger,
      new ScriptedDecisionProvider([{ action: "INVESTIGATE", rationale: "go", query_intent: "go" }]),
      new ScriptedWorkerDispatcher([
        evidence({ summary: "four processes", payload: { rows: ["a.exe", "b.exe", "c.exe", "d.exe"].map((p) => ({ process: p })) } }),
      ]),
      spec.dispatch,
      spec.digest,
      enricher,
    ).advanceIteration();

    expect(asked).toHaveLength(spec.enrichment.max_entities);
  });
});

describe("ABANDON", () => {
  function withEvidence(records: WorkerEvidence[]): { ledger: Ledger; ids: string[] } {
    const ledger = ledgerFor(specWith(CHAINS));
    const ids = records.map((record, index) => {
      const evidenceId = `ev-${index}`;
      ledger.append({
        kind: "evidence",
        evidence: {
          ...record,
          evidence_id: evidenceId,
          dispatch_id: null,
          iteration: 1,
          // Extracted for real, so an ABANDON naming an entity is measured against
          // the same graph the controller builds.
          entities: entitiesOf(record),
          captured_at: new Date(1_600_000_000_000 + index * 1000).toISOString(),
        } satisfies EvidenceRecord,
      });
      return evidenceId;
    });
    return { ledger, ids };
  }

  const HYPOTHESIS = "h-1";

  function withHypothesis(ledger: Ledger): string {
    ledger.append({
      kind: "hypothesis",
      hypothesis: {
        hypothesis_id: HYPOTHESIS,
        statement: "the process was launched by something unexpected",
        status: "active",
        attack_technique: null,
        provenance: "hunt_spec",
        resolution_reason: null,
      },
    });
    return HYPOTHESIS;
  }

  it("refuses to drop a branch on attacker-authored grounds alone", () => {
    const { ledger, ids } = withEvidence([
      evidence({ summary: "the feed calls this a benign CDN edge", attacker_influenceable: true }),
      evidence({ summary: "the page says this address is Cloudflare", instruction_like: true }),
    ]);
    withHypothesis(ledger);

    const decision: Decision = {
      action: "ABANDON",
      rationale: "intel says it is benign",
      target_hypothesis_id: HYPOTHESIS,
      evidence_citations: ids,
    };
    expect(() => validateDecision(decision, ledger.projection)).toThrow(/attacker-influenceable/);
  });

  it("accepts the same decision once one citation is something an adversary could not author", () => {
    const { ledger, ids } = withEvidence([
      evidence({ summary: "the feed calls this a benign CDN edge", attacker_influenceable: true }),
      evidence({ summary: "the asset inventory records this range as the corporate proxy pool" }),
    ]);
    withHypothesis(ledger);

    validateDecision(
      { action: "ABANDON", rationale: "corroborated as our own proxy", target_hypothesis_id: HYPOTHESIS, evidence_citations: ids },
      ledger.projection,
    );
  });

  it("refuses an ABANDON that names nothing to drop", () => {
    const { ledger, ids } = withEvidence([evidence({ summary: "the asset inventory says so" })]);
    expect(() =>
      validateDecision({ action: "ABANDON", rationale: "dead end", evidence_citations: ids }, ledger.projection),
    ).toThrow(InvalidDecision);
  });

  it("parks the hypothesis with the reason on it, rather than disproving it", async () => {
    const { ledger, ids } = withEvidence([evidence({ summary: "the asset inventory records this as the corporate proxy pool" })]);
    withHypothesis(ledger);

    const result = await new HuntController(
      ledger,
      new ScriptedDecisionProvider([
        {
          action: "ABANDON",
          rationale: "it is our own proxy pool",
          target_hypothesis_id: HYPOTHESIS,
          evidence_citations: ids,
        },
      ]),
    ).advanceIteration();
    // A rejected decision degrades to the scripted provider's CONCLUDE, which
    // would leave every assertion below trivially unreached.
    expect(result.action).toBe("ABANDON");

    const hypothesis = ledger.projection.hypotheses.get(HYPOTHESIS)!;
    // Parked, not disproven: the hunt stopped looking, which is not a clearing.
    expect(hypothesis.status).toBe("parked");
    expect(hypothesis.resolution_reason).toContain("it is our own proxy pool");
    expect(hypothesis.resolution_reason).toContain(ids[0]!);
  });

  it("takes an entity's leads off the frontier", async () => {
    const { ledger, ids } = withEvidence([
      evidence({ summary: "outbound from 10.0.0.5", payload: { src_ip: "10.0.0.5" } }),
      evidence({ summary: "the asset inventory records 10.0.0.5 as the backup relay" }),
    ]);
    for (const [index, entityKey] of ["ip:10.0.0.5", "ip:10.0.0.9"].entries()) {
      ledger.append({
        kind: "question",
        question: {
          question_id: `q-${index}`,
          question: `what does ${entityKey} talk to`,
          status: "open",
          entity_key: entityKey,
          spawning_evidence_id: null,
          spawning_dispatch_id: null,
          spawned_iteration: 1,
          hypothesis_id: null,
        } satisfies OpenQuestion,
      });
    }

    const result = await new HuntController(
      ledger,
      new ScriptedDecisionProvider([
        {
          action: "ABANDON",
          rationale: "it is the backup relay",
          target_entity: "ip:10.0.0.5",
          evidence_citations: ids,
        },
      ]),
    ).advanceIteration();
    expect(result.action).toBe("ABANDON");

    expect(ledger.projection.questions.get("q-0")!.status).toBe("closed");
    expect(ledger.projection.questions.get("q-1")!.status).toBe("open");
  });
});

describe("the frontier", () => {
  function lead(id: string, overrides: Partial<OpenQuestion> = {}): OpenQuestion {
    return {
      question_id: id,
      question: `lead ${id}`,
      status: "open",
      entity_key: null,
      hypothesis_id: null,
      spawning_evidence_id: null,
      spawning_dispatch_id: null,
      spawned_iteration: 1,
      ...overrides,
    };
  }

  function seeded(): { ledger: Ledger; hypothesis: string } {
    const ledger = ledgerFor(specWith(CHAINS));
    const hypothesis = newId("h", 4);
    ledger.append({
      kind: "hypothesis",
      hypothesis: {
        hypothesis_id: hypothesis,
        statement: "credentials are used from new infrastructure",
        status: "active",
        attack_technique: null,
        provenance: "hunt_spec",
        resolution_reason: null,
      },
    });
    for (const [index, salience] of (["routine", "anomalous"] as const).entries()) {
      ledger.append({
        kind: "evidence",
        evidence: {
          ...evidence({ summary: `finding ${index}`, salience }),
          evidence_id: `ev-${index}`,
          dispatch_id: null,
          iteration: 1,
          entities: [],
          captured_at: new Date(1_600_000_000_000 + index * 1000).toISOString(),
        } satisfies EvidenceRecord,
      });
    }
    return { ledger, hypothesis };
  }

  function order(ledger: Ledger, iteration = 2): string[] {
    return rankFrontier(ledger.projection, iteration).map((question) => question.question_id);
  }

  it("ranks a lead off anomalous evidence above one off routine evidence", () => {
    const { ledger } = seeded();
    ledger.append({ kind: "question", question: lead("q-routine", { spawning_evidence_id: "ev-0" }) });
    ledger.append({ kind: "question", question: lead("q-anomalous", { spawning_evidence_id: "ev-1" }) });

    expect(order(ledger)).toEqual(["q-anomalous", "q-routine"]);
  });

  it("ranks a lead the execution log already covered below an equivalent new one", () => {
    const { ledger } = seeded();
    ledger.append({ kind: "question", question: lead("q-done", { entity_key: "ip:10.0.0.5", status: "closed" }) });
    ledger.append({ kind: "question", question: lead("q-repeat", { entity_key: "ip:10.0.0.5" }) });
    ledger.append({ kind: "question", question: lead("q-fresh", { entity_key: "ip:10.0.0.9" }) });

    expect(order(ledger)).toEqual(["q-fresh", "q-repeat"]);
  });

  it("ranks a stale lead below a fresh one of equal standing", () => {
    const { ledger } = seeded();
    ledger.append({ kind: "question", question: lead("q-old", { spawned_iteration: 1 }) });
    ledger.append({ kind: "question", question: lead("q-new", { spawned_iteration: 9 }) });

    expect(order(ledger, 9)).toEqual(["q-new", "q-old"]);
  });

  // The score is a fold, never written down: it has to move when the ledger does.
  it("re-scores when new links land, and survives a reopen", () => {
    const { ledger, hypothesis } = seeded();
    ledger.append({ kind: "question", question: lead("q-a", { spawning_evidence_id: "ev-0" }) });
    ledger.append({ kind: "question", question: lead("q-b", { spawning_evidence_id: "ev-1" }) });
    expect(order(ledger)).toEqual(["q-b", "q-a"]);

    for (const relation of ["supports", "weakens"] as const) {
      ledger.append({ kind: "link", link: { evidence_id: "ev-0", hypothesis_id: hypothesis, relation } });
    }
    // Two links, one hypothesis: what counts is hypotheses borne on, not link rows.
    expect(order(ledger)).toEqual(["q-b", "q-a"]);

    ledger.append({
      kind: "hypothesis",
      hypothesis: {
        hypothesis_id: "h-2",
        statement: "a second live thread",
        status: "active",
        attack_technique: null,
        provenance: "hunt_spec",
        resolution_reason: null,
      },
    });
    ledger.append({ kind: "link", link: { evidence_id: "ev-0", hypothesis_id: "h-2", relation: "supports" } });

    expect(order(ledger)).toEqual(["q-a", "q-b"]);
    expect(order(Ledger.open(ledger.path))).toEqual(["q-a", "q-b"]);
  });

  it("reads a worker's follow-up through the dispatch that raised it", async () => {
    const spec = specWith(CHAINS);
    const ledger = ledgerFor(spec);
    class Raising extends ScriptedWorkerDispatcher {
      override async dispatch(request: { dispatch_id: string }) {
        return {
          dispatch_id: request.dispatch_id,
          evidence: [evidence({ summary: "beaconing to 45.77.53.176", salience: "anomalous" as const })],
          questions: ["what else did 45.77.53.176 talk to"],
          failed: false,
          cost_usd: 0,
          failure_reason: "",
        };
      }
    }

    await new HuntController(
      ledger,
      new ScriptedDecisionProvider([{ action: "INVESTIGATE", rationale: "go", query_intent: "go" }]),
      new Raising(),
      spec.dispatch,
      spec.digest,
    ).advanceIteration();

    const raised = [...ledger.projection.questions.values()].find((q) => q.status === "open")!;
    expect(raised.spawning_dispatch_id).not.toBeNull();
    expect(raised.spawned_iteration).toBe(1);
    // Nothing invented a spawning record: the features come off the whole dispatch.
    expect(raised.spawning_evidence_id).toBeNull();
    expect(rankFrontier(ledger.projection, 2)[0]!.question_id).toBe(raised.question_id);
  });
});
