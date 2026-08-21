# vigil-coordinator

A layer above the hunts. It consumes alerts and, for each one, decides whether to
start a new hunt, feed an existing one, relate several, or drop it — then acts on
that decision. It never reaches inside a running hunt: it only *creates* hunts and
appends directives to their inboxes, so the rule that **only a hunt's own
controller mutates its ledger** still holds.

```
alert → fold live hunts → dedup → decide → log → act
                                              ├─ START  create a hunt + launch its runner
                                              ├─ STEER  lead into an existing hunt's inbox
                                              ├─ RELATE note each related hunt about the others
                                              └─ DROP   nothing (the reason is the record)
```

## Running it

The coordinator watches a directory; a feeder drops alert JSON into it.

```bash
# No LLM, no gateway: decide with a heuristic, create hunts but don't run them.
npx tsx cli/vigil-coordinator.ts feed --queue /tmp/alerts tests/fixtures/alerts/*.json
npx tsx cli/vigil-coordinator.ts run  --queue /tmp/alerts --runs runs --scripted --dry --once
```

`--scripted` decides with a no-model heuristic (drop an exact duplicate, start
anything else). `--dry` creates the hunt ledger but does not launch a runner for
it. `--once` drains the queue and exits instead of polling. Drop all three for the
real thing:

```bash
BIFROST_URL=http://localhost:8080 \
  npx tsx cli/vigil-coordinator.ts run --queue /tmp/alerts --max 5
```

Now each `START` spawns `vigilhunt --resume` as a detached child, which takes the
hunt's lease and runs its loop — so a started hunt actually investigates. The LLM
decider reads `model` and `rates` from `vigil.config.yaml` (override with
`--config`).

| flag | default | what |
|---|---|---|
| `--queue <dir>` | — | directory the feeder drops alerts into (required) |
| `--runs <dir>` | `runs` | where hunt ledgers and the coordinator log live |
| `--scripted` | off | decide with the heuristic instead of a model |
| `--dry` | off | create hunts but launch no runner |
| `--once` | off | drain once and exit; otherwise poll |
| `--max <n>` | 5 | cap on concurrent active hunts |
| `--recent-ms <ms>` | 24h | how long a finished hunt stays in scope for dedup |
| `--iterations <n>` | 6 | iterations each started hunt is launched with |
| `--poll <ms>` | 3000 | how often to re-check the queue |

## What an alert is

A structured record. Only `entity` is load-bearing; the rest, `rule_name`
especially, may be missing and the coordinator still decides from the entity.

```json
{ "alert_id": "alert-1", "entity": "10.0.0.100", "rule_name": "beaconing",
  "severity": "high", "timestamp": "2026-08-21T09:00:00.000Z", "raw": {} }
```

## Deduping

Two tiers. **Exact:** the alert entity is normalized to the same key the hunt
engine uses and matched against each live hunt's seed — cheap and certain. **Fuzzy:**
the LLM decider judges whether the alert is *related* to a hunt even when the
entities differ (same campaign). Live state is a **fold over `runs/*.jsonl`**,
derived fresh each alert — active, parked, and recently-terminal hunts — so there
is no second copy to drift.

## Backpressure and idempotency

A `START` past `--max` active hunts becomes a `DEFER`: the alert is buffered and
reconsidered when a slot frees, **never dropped**. A redelivered alert (same
`alert_id`) returns its prior decision without acting again. Alerts are handled
one at a time, so two can never race the fold or the cap check.

## The coordinator log

`runs/coordinator.jsonl` — one append-only line per alert handled, carrying the
decision and the state it was made against. It is the only place a `DROP` is
explained, since a dropped alert starts no hunt and leaves no other trace. Every
directive the coordinator writes into a hunt's inbox is stamped with a
`coordinator` actor, distinct from a person's steer and from a policy default.

## Layout

| path | what |
|---|---|
| `cli/vigil-coordinator.ts` | the daemon (`run` poll loop) and feeder (`feed`) |
| `ai/coordinator.ts` | fold, dedup, decide, execute, defer, drain |
| `ai/coordinator-ports.ts` | the seams: decision provider, alert queue, hunt launcher |
| `ai/coordinator-llm.ts` | the LLM decider, over the hunt engine's `llm_output` |
| `ai/coordinator-scripted.ts` | the scripted decider and in-memory queue, for tests |
| `ai/coordinator-log.ts` | the coordinator's append-only record |
| `ai/coordinator-launcher.ts` | spawns `vigilhunt --resume` to run a started hunt |
| `ai/alert-queue.ts` | the directory-backed queue and its feeder |
| `ai/alert.ts` | the alert shape and the deterministic alert→spec mapping |
