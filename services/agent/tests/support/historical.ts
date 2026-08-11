import { gunzipSync } from "node:zlib";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { HuntEvent } from "../../workflows/hunt/ledger.js";

export const RUNS = join(import.meta.dirname, "..", "fixtures", "runs");

// The file ledger's shape, which predates the harness envelope. Each record put
// its body under a key named for its kind rather than under a payload.
interface Historical {
  kind: string;
  seq: number;
  ts: string;
  schema_version: number;
  [key: string]: unknown;
}

const RENAMED: Record<string, string> = { hunt: "run" };

// A patch carried its fields beside the kind; everything else carried one object
// under a key named for the kind.
function payloadOf(record: Historical): unknown {
  if (record.kind === "patch") return { target: record["target"], id: record["id"], fields: record["fields"] };
  if (record.kind === "hunt") return { hunt: record["hunt"] };
  if (record.kind === "finalize") return record["report"];
  return record[record.kind];
}

export function asHarnessEvents(text: string, runId: string): HuntEvent[] {
  return text
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => {
      const record = JSON.parse(line) as Historical;
      return {
        run_id: runId,
        run_kind: "hunt",
        seq: record.seq,
        ts: record.ts,
        kind: RENAMED[record.kind] ?? record.kind,
        payload: payloadOf(record),
        schema_version: record.schema_version,
      } as HuntEvent;
    });
}

export function gunzipped(name: string): string {
  return gunzipSync(readFileSync(join(RUNS, name))).toString("utf8");
}

// The ten real ledgers. Sidecars and the torn file are deliberately not here:
// one is not a ledger and the other is the subject of its own test.
export function historicalRuns(): string[] {
  return readdirSync(RUNS)
    .filter((name) => name.endsWith(".jsonl.gz"))
    .map((name) => name.replace(".jsonl.gz", ""))
    .sort();
}
