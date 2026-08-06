import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { inflateRawSync } from "node:zlib";
import type { Tool } from "../ai/tools.js";
import type { ToolSpec } from "../ai/spec.js";

export class IntelFeedError extends Error {}

export const DEFAULT_FEED = "https://threatfox.abuse.ch/export/json/recent/";

// ThreatFox ioc_type values, mapped to the observable kinds a hunt deals in.
const IOC_TYPES: Record<string, string> = {
  "ip:port": "ip",
  domain: "domain",
  url: "url",
  md5_hash: "hash_md5",
  sha1_hash: "hash_sha1",
  sha256_hash: "hash_sha256",
};

export interface Indicator {
  type: string;
  value: string;
  malware: string;
  threat_type: string;
  confidence: number | null;
  first_seen: string;
  tags: string[];
}

// The feed stores ip:port; a hunt carries the bare address.
function bareIp(value: string): string {
  if (value.startsWith("[")) return value.slice(1).split("]")[0] ?? value;
  return value.split(":").length === 2 ? (value.split(":")[0] ?? value) : value;
}

function labels(entry: Record<string, unknown>): string[] {
  const raw = entry["tags"];
  const tags = typeof raw === "string" ? raw.split(",") : Array.isArray(raw) ? raw.map(String) : [];
  return [...new Set(tags.map((tag) => tag.trim()).filter((tag) => tag !== ""))];
}

function toIndicator(entry: Record<string, unknown>): Indicator | null {
  const type = IOC_TYPES[String(entry["ioc_type"] ?? "")];
  const raw = String(entry["ioc_value"] ?? "").trim();
  if (type === undefined || raw === "") return null;

  const confidence = entry["confidence_level"];
  return {
    type,
    value: type === "ip" ? bareIp(raw) : raw,
    malware: String(entry["malware_printable"] ?? entry["malware"] ?? ""),
    threat_type: String(entry["threat_type"] ?? ""),
    confidence: confidence === undefined || confidence === null ? null : Number(confidence),
    first_seen: String(entry["first_seen_utc"] ?? ""),
    tags: labels(entry),
  };
}

// The export is an object of id -> entry (or id -> [entry]), not a flat list.
export function parseExport(raw: unknown): Map<string, Indicator[]> {
  const index = new Map<string, Indicator[]>();
  if (raw === null || typeof raw !== "object") throw new IntelFeedError("feed is not a JSON object");

  for (const entries of Object.values(raw as Record<string, unknown>)) {
    for (const entry of Array.isArray(entries) ? entries : [entries]) {
      const indicator = toIndicator((entry ?? {}) as Record<string, unknown>);
      if (indicator === null) continue;
      const key = indicator.value.toLowerCase();
      index.set(key, [...(index.get(key) ?? []), indicator]);
    }
  }
  return index;
}

// recent/ is plain JSON; the full dump ships as a single-member full.json.zip,
// whose payload is raw deflate immediately past the local header.
function unwrap(body: Buffer): string {
  if (body.subarray(0, 2).toString() !== "PK") return body.toString("utf8");
  const nameLength = body.readUInt16LE(26);
  const extraLength = body.readUInt16LE(28);
  return inflateRawSync(body.subarray(30 + nameLength + extraLength)).toString("utf8");
}

async function readFeed(feed: string): Promise<string> {
  if (!/^https?:\/\//i.test(feed)) {
    const path = feed.startsWith("~/") ? `${homedir()}/${feed.slice(2)}` : feed;
    return readFileSync(path, "utf8");
  }

  // The public recent export needs no key. Where one is required it is a
  // credential, so it comes from the environment: vigil.config.yaml is committed.
  const key = process.env["THREATFOX_API_KEY"];
  const headers: Record<string, string> = { Accept: "application/json" };
  if (key) headers["Auth-Key"] = key;

  const response = await fetch(feed, { headers });
  if (!response.ok) {
    const hint = key ? "" : "; the feed may want THREATFOX_API_KEY";
    throw new IntelFeedError(`${feed} returned ${response.status} ${response.statusText}${hint}`);
  }
  return unwrap(Buffer.from(await response.arrayBuffer()));
}

function describe(hits: Indicator[]): string {
  return hits
    .map((hit) => {
      const parts = [`${hit.type} ${hit.value}`, hit.malware || hit.threat_type];
      if (hit.confidence !== null) parts.push(`confidence ${hit.confidence}`);
      if (hit.first_seen) parts.push(`first seen ${hit.first_seen}`);
      if (hit.tags.length > 0) parts.push(`tags: ${hit.tags.join(", ")}`);
      return parts.filter((part) => part).join(" | ");
    })
    .join("\n");
}

async function index(feed: string): Promise<Map<string, Indicator[]> | Error> {
  try {
    return parseExport(JSON.parse(await readFeed(feed)));
  } catch (error) {
    return error as Error;
  }
}

// Indexed once at build rather than queried per call: a hunt stays deterministic
// and replayable, and a worker chasing forty observables costs no network at all.
export async function createThreatFoxTool(config: ToolSpec): Promise<Tool> {
  const feed = String(config["feed"] ?? DEFAULT_FEED);
  // An unreachable feed must not kill a hunt that may never ask for intel. It
  // surfaces per call instead, where a failure is already recorded as a gap
  // rather than mistaken for a clean miss.
  const loaded = await index(feed);
  const size = loaded instanceof Error ? "unavailable" : `${loaded.size} indicators`;

  return {
    id: config.id,
    description: `Look up observables in the ThreatFox indicator feed (${size} from ${feed}).\n\nAccepts IPs, domains, URLs and file hashes. A miss means the feed does not know the value, not that it is benign — the feed is a rolling recent window.`,
    parameters: {
      type: "object",
      additionalProperties: false,
      required: ["observables"],
      properties: {
        observables: { type: "array", items: { type: "string" }, description: "IPs, domains, URLs or hashes." },
      },
    },

    async run(args) {
      if (loaded instanceof Error) throw new IntelFeedError(`intel feed unavailable: ${loaded.message}`);
      const observables = Array.isArray(args["observables"]) ? args["observables"].map(String) : [];
      if (observables.length === 0) return "no observables given";

      const lines = observables.map((observable) => {
        const hits = loaded.get(observable.trim().toLowerCase());
        return hits === undefined ? `${observable}: not in feed` : `${observable}:\n${describe(hits)}`;
      });
      return lines.join("\n");
    },
  };
}
