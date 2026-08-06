import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { afterAll, describe, expect, it } from "vitest";
import { createDuckDBTool } from "../tools/duckdb.js";
import type { Tool } from "../ai/tools.js";

const DATABASE = `${homedir()}/Downloads/botsv3_duckdb/botsv3.duckdb`;

// Skips rather than fails when the dataset is not on this machine.
describe.skipIf(!existsSync(DATABASE))("duckdb tool against BOTSv3", () => {
  let tool: Tool | undefined;

  afterAll(async () => {
    await tool?.close?.();
  });

  async function get(): Promise<Tool> {
    tool ??= await createDuckDBTool({
      id: "duckdb_query",
      kind: "duckdb",
      database: DATABASE,
      max_rows: 20,
      timeout_ms: 60_000,
    });
    return tool;
  }

  it("advertises the mapped views in its description", async () => {
    const description = (await get()).description;
    for (const view of ["net_flow", "dns", "http", "win_events", "endpoint", "cloud", "events"]) {
      expect(description).toContain(view);
    }
    expect(description).toContain("src_ip IS NOT NULL");
  });

  it("finds the known C2 by inter-arrival regularity", async () => {
    const output = await (await get()).run({
      sql: `WITH d AS (
              SELECT src_ip, dest_ip, dest_port,
                     epoch(ts - lag(ts) OVER (PARTITION BY src_ip, dest_ip, dest_port ORDER BY ts)) AS gap
              FROM net_flow
              WHERE src_ip LIKE '192.168.%' AND dest_ip NOT LIKE '192.168.%' AND dest_ip NOT LIKE '172.16.%'
            )
            SELECT src_ip, dest_ip, dest_port, count(*) beacons, round(stddev(gap), 2) jitter
            FROM d WHERE gap BETWEEN 1 AND 3600
            GROUP BY 1, 2, 3 HAVING count(*) > 20 AND stddev(gap) < 5
            ORDER BY beacons DESC`,
    });
    expect(output).toContain("45.77.53.176");
  });

  it("caps rows and serves a repeated query from the execution cache", async () => {
    const query = { sql: "SELECT ts, host FROM dns ORDER BY ts LIMIT 500" };
    const first = await (await get()).run(query);
    expect(first).toContain("capped at 20");
    expect(await (await get()).run(query)).toBe(first);
  });

  it("refuses a write", async () => {
    await expect((await get()).run({ sql: "DROP TABLE events" })).rejects.toThrow(/SELECT and WITH/);
  });
});
