import { describe, expect, it } from "vitest";
import { buildEntityGraph, defang, entitiesOf, fromPayload, fromText, key } from "../ai/entities.js";
import { parseEntity, SpecError } from "../ai/spec.js";
import type { Entity, EvidenceRecord } from "../ai/types.js";

function values(entities: Entity[], type?: string): string[] {
  return entities.filter((e) => type === undefined || e.type === type).map((e) => e.value).sort();
}

describe("extraction", () => {
  // The failures that motivated this ticket: in a Sysmon dataset every process
  // and DLL was becoming a domain node, poisoning the rules built on the graph.
  it("does not read a file name as a domain", () => {
    for (const text of ["kernel32.dll loaded by svchost.exe", "powershell.exe ran setup.msi", "invoice.pdf on disk"]) {
      expect(values(fromText(text), "domain")).toEqual([]);
    }
  });

  it("still reads a real domain", () => {
    expect(values(fromText("beacon to froth.ly and evil.example.com"), "domain")).toEqual([
      "evil.example.com",
      "froth.ly",
    ]);
  });

  it("does not read a version string as an address", () => {
    expect(values(fromText("agent version 1.2.3.4"))).toEqual([]);
    expect(values(fromText("v10.0.0.5 released"))).toEqual([]);
    // A bare address in the same shape is still an address.
    expect(values(fromText("outbound to 10.0.0.5"), "ip")).toEqual(["10.0.0.5"]);
  });

  it("normalizes defanged indicators, which is how intel writes them", () => {
    expect(defang("45.77.53[.]176")).toBe("45.77.53.176");
    expect(values(fromText("c2 at 45.77.53[.]176 via hxxp://evil[.]com/a"), "ip")).toEqual(["45.77.53.176"]);
    expect(values(fromText("hxxp://evil[.]com/a"), "url")).toEqual(["http://evil.com/a"]);
  });

  it("sees the identities the AWS hypothesis is about", () => {
    const found = fromText("arn:aws:iam::123456789012:user/bstoll used AKIAJOAVWCHV6MTPQTQQ, mail bstoll@froth.ly");
    expect(values(found, "arn")).toEqual(["arn:aws:iam::123456789012:user/bstoll"]);
    expect(values(found, "aws_key")).toEqual(["AKIAJOAVWCHV6MTPQTQQ"]);
    expect(values(found, "email")).toEqual(["bstoll@froth.ly"]);
  });

  it("recognizes every hash length and rejects a short hex run", () => {
    expect(values(fromText(`md5 ${"a".repeat(32)} sha1 ${"b".repeat(40)}`), "hash")).toHaveLength(2);
    expect(values(fromText("deadbeef"), "hash")).toEqual([]);
  });
});

describe("payload typing", () => {
  it("types a value by the key it arrived under, not by its shape", () => {
    const typed = fromPayload({ rows: [{ process: "powershell.exe", dest_host: "evil.example.com" }] });
    expect(typed).toContainEqual({ type: "process", value: "powershell.exe" });
    expect(typed).toContainEqual({ type: "domain", value: "evil.example.com" });
  });

  it("keeps the user and the ip apart when only the key can tell them apart", () => {
    const typed = fromPayload({ user: "bstoll", src_ip: "10.0.0.5", arn: "arn:aws:s3:::frothly-bucket" });
    expect(typed).toContainEqual({ type: "user", value: "bstoll" });
    expect(typed).toContainEqual({ type: "ip", value: "10.0.0.5" });
    expect(typed).toContainEqual({ type: "arn", value: "arn:aws:s3:::frothly-bucket" });
  });

  it("refuses a value that does not match the type its key claims", () => {
    // Placeholders and rollup nulls are everywhere in telemetry.
    expect(fromPayload({ src_ip: "-" })).toEqual([]);
    expect(fromPayload({ src_ip: "not-an-address" })).toEqual([]);
    expect(fromPayload({ dest_host: "kernel32.dll" })).toEqual([]);
  });

  it("falls back to pattern matching under a key it does not recognise", () => {
    expect(fromPayload({ notes: "saw 10.0.0.5 today" })).toEqual([{ type: "ip", value: "10.0.0.5" }]);
  });

  it("merges both paths and deduplicates", () => {
    const merged = entitiesOf({
      summary: "10.0.0.5 ran powershell.exe",
      payload: { src_ip: "10.0.0.5", process: "powershell.exe" },
    });
    expect(values(merged, "ip")).toEqual(["10.0.0.5"]);
    expect(values(merged, "process")).toEqual(["powershell.exe"]);
  });
});

describe("seed entities", () => {
  it("types a seed into the same namespace the graph uses", () => {
    expect(parseEntity("10.0.0.1")).toEqual({ type: "ip", value: "10.0.0.1" });
    expect(parseEntity("host:web-01")).toEqual({ type: "host", value: "web-01" });
    expect(parseEntity("user:bstoll")).toEqual({ type: "user", value: "bstoll" });
    expect(parseEntity("web-01")).toEqual({ type: "host", value: "web-01" });
  });

  it("refuses a type the graph could never produce", () => {
    // Otherwise a hunt cannot pivot onto its own seed: no node would match it.
    expect(() => parseEntity("widget:thing")).toThrow(SpecError);
  });
});

describe("the graph port", () => {
  function evidenceOf(pairs: [string, Record<string, unknown>][]): EvidenceRecord[] {
    return pairs.map(([summary, payload], index) => ({
      evidence_id: `ev-${index}`,
      dispatch_id: null,
      iteration: 1,
      source_system: "duckdb",
      summary,
      payload,
      salience: "routine" as const,
      why_notable: "",
      provenance: "worker",
      attacker_influenceable: false,
      instruction_like: false,
      entities: entitiesOf({ summary, payload }),
      captured_at: new Date(1_600_000_000_000 + index * 1000).toISOString(),
    }));
  }

  const records = evidenceOf([
    ["10.0.0.5 to 45.77.53.176", {}],
    ["10.0.0.5 to 45.77.53.176", {}],
    ["10.0.0.9 to cdn.example.com", {}],
  ]);

  it("answers adjacency, ranked, and knows nothing of an entity it never saw", () => {
    const graph = buildEntityGraph(records);

    expect(graph.neighbours("ip:10.0.0.5")).toEqual([{ key: "ip:45.77.53.176", count: 2 }]);
    expect(graph.neighbours("ip:203.0.113.1")).toEqual([]);
    expect(graph.node("ip:203.0.113.1")).toBeUndefined();
    expect(graph.node("ip:10.0.0.5")!.count).toBe(2);
  });

  it("agrees with a direct scan of the records it was built from", () => {
    const graph = buildEntityGraph(records);
    for (const node of graph.nodes()) {
      const scanned = records.filter((r) => r.entities.some((e) => key(e) === key(node.entity)));
      expect(node.count).toBe(scanned.length);
      expect(node.first_evidence_id).toBe(scanned[0]!.evidence_id);
    }
  });

  // The defect this ticket fixes, asserted at the level it actually bit: process
  // names recurring constantly used to become familiar entities and then
  // manufacture rare pairings against each other.
  it("does not manufacture rare pairings out of process names", () => {
    const sysmon = evidenceOf(
      Array.from({ length: 8 }, (_, index) => [
        `process start on host-${index % 2}`,
        { process: "powershell.exe", parent_image: "explorer.exe", dest_host: "cdn.example.com" },
      ] as [string, Record<string, unknown>]),
    );
    const graph = buildEntityGraph(sysmon);

    expect(graph.nodes().some((node) => node.entity.type === "domain" && node.entity.value.endsWith(".exe"))).toBe(false);
    expect(sysmon.every((record) => !graph.hasRarePairing(record, 1))).toBe(true);
  });
});
