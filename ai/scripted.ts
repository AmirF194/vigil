import type { DecisionProvider, WorkerDispatcher } from "./ports.js";
import type {
  Decision,
  DecisionResult,
  Digest,
  DispatchRequest,
  DispatchResult,
} from "./types.js";

export const SCRIPTED_MODEL_ID = "scripted";

// Replays a fixed sequence, then concludes. The fallback stops a hunt that
// outlives its script from looping forever.
export class ScriptedDecisionProvider implements DecisionProvider {
  readonly seenDigests: Digest[] = [];
  private readonly decisions: Decision[];

  constructor(
    decisions: Iterable<Decision>,
    private readonly costPerDecision = 0,
    private readonly modelId = SCRIPTED_MODEL_ID,
  ) {
    this.decisions = [...decisions];
  }

  get exhausted(): boolean {
    return this.decisions.length === 0;
  }

  async decide(digest: Digest): Promise<DecisionResult> {
    this.seenDigests.push(digest);
    const decision = this.decisions.shift() ?? {
      action: "CONCLUDE" as const,
      rationale: "scripted provider exhausted",
    };
    return {
      decision,
      model_id: this.modelId,
      prompt_version: "scripted/v0",
      cost_usd: this.costPerDecision,
    };
  }
}

export class ScriptedWorkerDispatcher implements WorkerDispatcher {
  readonly requests: DispatchRequest[] = [];
  private readonly failAgentIds: Set<string>;

  constructor(
    private readonly evidence: DispatchResult["evidence"] = [],
    failAgentIds: Iterable<string> = [],
  ) {
    this.failAgentIds = new Set(failAgentIds);
  }

  async dispatch(request: DispatchRequest): Promise<DispatchResult> {
    this.requests.push(request);
    if (this.failAgentIds.has(request.agent_id)) {
      return {
        dispatch_id: request.dispatch_id,
        evidence: [],
        failed: true,
        failure_reason: `scripted failure for ${request.agent_id}`,
      };
    }
    return {
      dispatch_id: request.dispatch_id,
      evidence: structuredClone(this.evidence),
      failed: false,
      failure_reason: "",
    };
  }
}
