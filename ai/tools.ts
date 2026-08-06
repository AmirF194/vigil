import type { Ledger } from "./ledger.js";
import type { HuntSpec } from "./spec.js";
import { createDuckDBTool } from "../tools/duckdb.js";

export interface Tool {
  id: string;
  description: string;
  parameters: Record<string, unknown>;
  run(args: Record<string, unknown>): Promise<string>;
  close?(): Promise<void>;
}

export function toOpenAITools(tools: readonly Tool[]) {
  return tools.map((tool) => ({
    type: "function" as const,
    function: { name: tool.id, description: tool.description, parameters: tool.parameters },
  }));
}

// Raw payloads stay retrievable by id, so digest compression is never the only
// copy of a detail the Hunt Lead might need.
function createExpandTool(id: string, ledger: Ledger): Tool {
  return {
    id,
    description: "Retrieve the full raw payload of one evidence record by its id.",
    parameters: {
      type: "object",
      additionalProperties: false,
      required: ["evidence_id"],
      properties: { evidence_id: { type: "string" } },
    },
    async run(args) {
      const evidenceId = String(args["evidence_id"] ?? "");
      const record = ledger.projection.evidence.get(evidenceId);
      if (record === undefined) return `no such evidence: ${evidenceId}`;
      return JSON.stringify(record, null, 2);
    },
  };
}

export async function buildTools(spec: HuntSpec, ledger: Ledger): Promise<Tool[]> {
  const tools: Tool[] = [];
  for (const config of spec.tools) {
    if (config.kind === "duckdb") tools.push(await createDuckDBTool(config));
    if (config.kind === "expand") tools.push(createExpandTool(config.id, ledger));
  }
  return tools;
}

export async function closeTools(tools: readonly Tool[]): Promise<void> {
  await Promise.all(tools.map((tool) => tool.close?.()));
}
