import { homedir } from "node:os";
import { DuckDBInstance, type DuckDBConnection } from "@duckdb/node-api";
import type { Tool } from "../ai/tools.js";
import type { ToolSpec } from "../ai/spec.js";

export class UnsafeQuery extends Error {}

const DEFAULT_MAX_ROWS = 500;
const DEFAULT_TIMEOUT_MS = 30_000;

function expandHome(path: string): string {
  return path.startsWith("~/") ? `${homedir()}/${path.slice(2)}` : path;
}

// Read-only is enforced by the connection too; this rejects the obvious cases
// early so a destructive attempt shows up as a refusal rather than a driver error.
export function assertReadOnly(sql: string): void {
  const stripped = sql
    .replace(/--[^\n]*/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .trim()
    .replace(/;\s*$/, "");

  if (stripped.includes(";")) throw new UnsafeQuery("only a single statement is allowed");
  if (!/^(select|with)\b/i.test(stripped)) throw new UnsafeQuery("only SELECT and WITH queries are allowed");
}

async function describeSchema(connection: DuckDBConnection): Promise<string> {
  const reader = await connection.runAndReadAll(
    `SELECT table_name, string_agg(column_name || ' ' || data_type, ', ' ORDER BY ordinal_position) AS cols
     FROM information_schema.columns WHERE table_schema = 'main' GROUP BY 1 ORDER BY 1`,
  );
  return reader
    .getRowObjectsJson()
    .map((row) => `${String(row["table_name"])}(${String(row["cols"])})`)
    .join("\n");
}

const GAPS = `Known gaps in this dataset, filter accordingly:
- net_flow and http mix per-flow records with Splunk Stream rollups; rollup rows have NULL src_ip. Add "src_ip IS NOT NULL" when you need real flows.
- net_flow.action is only populated for cisco:asa and vpcflow rows.
- Sysmon rows in win_events reuse columns by meaning: log_name=Channel, account_name=User, process=Image, message=CommandLine.
- The "events" table is lossless and holds everything, including sourcetypes no view maps.`;

export async function createDuckDBTool(config: ToolSpec): Promise<Tool> {
  const path = expandHome(String(config["database"] ?? ""));
  const maxRows = Number(config["max_rows"] ?? DEFAULT_MAX_ROWS);
  const timeoutMs = Number(config["timeout_ms"] ?? DEFAULT_TIMEOUT_MS);

  const instance = await DuckDBInstance.create(path, { access_mode: "READ_ONLY" });
  const connection = await instance.connect();
  if (config["memory_limit"] !== undefined) {
    await connection.run(`SET memory_limit='${String(config["memory_limit"])}'`);
  }
  const schema = await describeSchema(connection);

  // Identical queries are common across workers chasing adjacent leads, so the
  // cache is both the dedup the audit trail wants and the cheapest latency win.
  const cache = new Map<string, string>();

  return {
    id: config.id,
    description: `Run one read-only SQL query against the security telemetry (DuckDB).\n\nTables:\n${schema}\n\n${GAPS}\n\nAt most ${maxRows} rows are returned.`,
    parameters: {
      type: "object",
      additionalProperties: false,
      required: ["sql"],
      properties: { sql: { type: "string", description: "A single SELECT or WITH query." } },
    },

    async run(args) {
      const sql = String(args["sql"] ?? "").trim();
      assertReadOnly(sql);

      const cached = cache.get(sql);
      if (cached !== undefined) return cached;

      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`query exceeded ${timeoutMs}ms`)), timeoutMs),
      );
      const reader = await Promise.race([connection.streamAndReadUntil(sql, maxRows), timeout]);
      const rows = reader.getRowObjectsJson().slice(0, maxRows);

      const result =
        rows.length === 0
          ? "0 rows"
          : `${rows.length} row(s)${rows.length === maxRows ? ` (capped at ${maxRows})` : ""}\n${JSON.stringify(rows)}`;
      cache.set(sql, result);
      return result;
    },

    async close() {
      connection.closeSync();
    },
  };
}
