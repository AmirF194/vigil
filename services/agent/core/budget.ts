import {
  ZERO_TOKENS,
  type Budget,
  type BudgetLimits,
  type Quota,
  type Refusal,
  type Spend,
  type SpendPayload,
  type TokenCounts,
} from "../contracts/budget.js";

export function addTokens(left: TokenCounts, right: TokenCounts): TokenCounts {
  return {
    input: left.input + right.input,
    output: left.output + right.output,
    cache_read: left.cache_read + right.cache_read,
    cache_write: left.cache_write + right.cache_write,
  };
}

// Nothing to ask, so nothing refuses on cost. For tests and for any deployment
// running without a gateway key, where the iteration cap is the only ceiling.
export const unmeteredQuota: Quota = { spent: async () => null };

// One pool per run. Calls and elapsed time are counted here because no gateway
// knows either; dollars are read from the gateway because it is the one that bills.
export function budgetOf(limits: BudgetLimits, quota: Quota, providerType: string, now = Date.now): Budget {
  return new Pool(limits, quota, providerType, now);
}

class Pool implements Budget {
  private calls = 0;
  private cost = 0;
  private tokens: TokenCounts = ZERO_TOKENS;
  private readonly started: number;

  constructor(
    readonly limits: BudgetLimits,
    private readonly quota: Quota,
    private readonly providerType: string,
    private readonly now: () => number,
  ) {
    this.started = now();
  }

  get spent(): Spend {
    return { calls: this.calls, cost_usd: this.cost, tokens: { ...this.tokens } };
  }

  // Wall before cost: a run already over time should not spend a gateway round
  // trip finding out it is also over budget.
  async beginCall(): Promise<Refusal | null> {
    const limit = this.limits.max_calls;
    if (this.calls >= limit) return { reason: "calls_exhausted", used: this.calls, limit };

    const used_ms = this.now() - this.started;
    if (used_ms >= this.limits.max_wall_ms) {
      return { reason: "wall_exhausted", used_ms, limit_ms: this.limits.max_wall_ms };
    }

    const refusal = await this.overspent();
    if (refusal !== null) return refusal;

    this.calls += 1;
    return null;
  }

  record(payload: SpendPayload): void {
    this.tokens = addTokens(this.tokens, payload.tokens);
    if (payload.cost_usd !== null) this.cost += payload.cost_usd;
  }

  // An unreadable quota is not a refusal. The gateway enforces the ceiling on its
  // own side, so a blip here costs the pre-flight courtesy, never the cap.
  private async overspent(): Promise<Refusal | null> {
    const reported = await this.quota.spent();
    if (reported === null) return null;

    this.cost = reported.used_usd;
    const limit_usd = Math.min(this.limits.max_cost_usd, reported.limit_usd);
    if (reported.used_usd < limit_usd) return null;
    return { reason: "cost_exhausted", used_usd: reported.used_usd, limit_usd };
  }

  payloadFor(model_id: string, role: string, tokens: TokenCounts, cost_usd: number | null): SpendPayload {
    return { model_id, provider_type: this.providerType, role, tokens, cost_usd };
  }
}
