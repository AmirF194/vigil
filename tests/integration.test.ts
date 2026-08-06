import { existsSync, mkdtempSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import type OpenAI from "openai";
import { Limiter } from "../ai/limiter.js";
import { LlmDecisionProvider, LlmWorkerDispatcher, resetEmitMode } from "../ai/llm.js";
import { HuntController, startHunt } from "../ai/loop.js";
import { buildSpec } from "../ai/spec.js";
import { buildTools, closeTools, type Tool } from "../ai/tools.js";
import { Ledger } from "../ai/ledger.js";

type Body = OpenAI.Chat.ChatCompletionCreateParamsNonStreaming;

const DATABASE = `${homedir()}/Downloads/botsv3_duckdb/botsv3.duckdb`;

const BEACON_SQL = `WITH d AS (
  SELECT src_ip, dest_ip, dest_port,
         epoch(ts - lag(ts) OVER (PARTITION BY src_ip, dest_ip, dest_port ORDER BY ts)) AS gap
  FROM net_flow
  WHERE src_ip LIKE '192.168.%' AND dest_ip NOT LIKE '192.168.%' AND dest_ip NOT LIKE '172.16.%'
)
SELECT src_ip, dest_ip, dest_port, count(*) beacons, round(stddev(gap), 2) jitter
FROM d WHERE gap BETWEEN 1 AND 3600
GROUP BY 1, 2, 3 HAVING count(*) > 20 AND stddev(gap) < 5 ORDER BY beacons DESC`;

function completion(message: Record<string, unknown>): OpenAI.Chat.ChatCompletion {
  return {
    choices: [{ message, finish_reason: "stop", index: 0, logprobs: null }],
    usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
  } as unknown as OpenAI.Chat.ChatCompletion;
}

// Everything downstream of the HTTP call is real: the controller, both roles,
// the tool loop, the DuckDB tool, and the ledger. Only the gateway is stubbed.
function fakeGateway(hypothesisId: string, bodies: Body[]) {
  const leadDecisions = [
    { action: "INVESTIGATE", rationale: "establish a beaconing baseline", query_intent: "find regular outbound intervals" },
    { action: "CONCLUDE", rationale: "beaconing confirmed" },
  ];
  let workerQueried = false;

  return async (body: Body): Promise<OpenAI.Chat.ChatCompletion> => {
    bodies.push(body);
    const isEmit = body.response_format !== undefined || body.tool_choice !== undefined;
    const isLead = String(body.messages[0]?.content ?? "").includes("Hunt Lead");

    if (isLead) {
      if (!isEmit) return completion({ role: "assistant", content: "considering the ledger" });
      return completion({ role: "assistant", content: JSON.stringify(leadDecisions.shift()) });
    }

    if (isEmit) {
      return completion({
        role: "assistant",
        content: JSON.stringify({
          results: [
            {
              summary: "192.168.70.186 beacons to 45.77.53.176:443 with 4.4s jitter over 2641 connections",
              salience: "anomalous",
              why_notable: "fixed-interval outbound to a host with no business relationship",
              supports: [hypothesisId],
            },
          ],
          ips_to_check: ["45.77.53.176"],
        }),
      });
    }

    if (!workerQueried) {
      workerQueried = true;
      return completion({
        role: "assistant",
        tool_calls: [
          { id: "c1", type: "function", function: { name: "duckdb_query", arguments: JSON.stringify({ sql: BEACON_SQL }) } },
        ],
      });
    }
    return completion({ role: "assistant", content: "query complete" });
  };
}

describe.skipIf(!existsSync(DATABASE))("hunt end to end (stubbed gateway, real everything else)", () => {
  let tools: Tool[] = [];
  beforeEach(() => resetEmitMode());
  afterAll(async () => closeTools(tools));

  it("runs a hunt from spec to verdict and leaves a replayable ledger", async () => {
    const spec = buildSpec({ workflowPath: "frothly.yaml" });
    const ledger = startHunt(spec, mkdtempSync(join(tmpdir(), "hunt-")));
    const hypothesisId = [...ledger.projection.hypotheses.keys()][0]!;

    const bodies: Body[] = [];
    const client = { chat: { completions: { create: fakeGateway(hypothesisId, bodies) } } } as unknown as OpenAI;
    const limiter = new Limiter({ rpm: 10_000, tpm: 10_000_000 }, 4, 1);
    tools = await buildTools(spec, ledger);

    const controller = new HuntController(
      ledger,
      new LlmDecisionProvider(spec, tools, limiter, client),
      new LlmWorkerDispatcher(spec, tools, limiter, client),
      spec.dispatch,
      spec.digest,
    );

    const first = await controller.advanceIteration();
    expect(first.action).toBe("INVESTIGATE");
    expect(first.evidence_appended).toBe(1);
    expect(first.cost_usd).toBeGreaterThan(0);

    // The worker's SQL really ran: the C2 came back through the tool loop.
    const toolResults = bodies.flatMap((body) => body.messages.filter((message) => message.role === "tool"));
    expect(JSON.stringify(toolResults)).toContain("45.77.53.176");

    const evidence = [...ledger.projection.evidence.values()];
    expect(evidence[0]!.salience).toBe("anomalous");
    expect(ledger.projection.links).toEqual([
      { evidence_id: evidence[0]!.evidence_id, hypothesis_id: hypothesisId, relation: "supports" },
    ]);
    expect([...ledger.projection.questions.values()][0]!.question).toBe("check 45.77.53.176");

    const second = await controller.advanceIteration();
    expect(second.hunt_status).toBe("terminal");
    expect(second.hunt_outcome).toBe("completed");

    // The unlinked second hypothesis is inconclusive, never disproven.
    const statuses = [...ledger.projection.hypotheses.values()].map((h) => h.status);
    expect(statuses).toEqual(["inconclusive", "inconclusive"]);

    // The digest the lead saw is on the record, and the file replays to the same state.
    const decisions = ledger.projection.decisions;
    expect(decisions).toHaveLength(2);
    expect(decisions[1]!.digest_presented.recent_evidence[0]!.summary).toContain("45.77.53.176");
    expect(Ledger.open(ledger.path).projection).toEqual(ledger.projection);
  });
});
