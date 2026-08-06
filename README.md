# vigilhunt

An isolated, YAML-driven agent loop for hypothesis-driven threat hunting.

A deterministic controller owns the loop and all state. Two LLM roles sit behind
injectable ports: a **lead** that reads a ledger digest and emits one typed
decision, and a **worker** that turns a query intent into evidence. What each
role is told, must answer in, and may call is declared in YAML, so a different
workflow is a config change rather than a code change.

```
vigilhunt --prompt <prompt> --id <entity> --workflow <playbook.yaml>
```

- `--prompt` — the question to hunt; may be used alone
- `--id` — seed entity (`10.0.0.1`, `host:web-01`); never alone
- `--workflow` — the playbook; never alone

`--arch`, `--config`, `--iterations`, `--scripted` and `--yes` modify an already
valid entry; none of them can make one valid.

## Running it

```bash
npm install
npm run hunt -- --prompt "a host is beaconing outbound" --scripted --yes   # no LLM
BIFROST_URL=http://localhost:8080 \
  npm run hunt -- --workflow frothly.yaml --id 192.168.70.186 --iterations 8
npm test
```

`--scripted` runs the whole controller with no model and no database, which is
how the loop mechanics are tested.

## Steering, pausing, resuming

A hunt is a series of re-entrant steps over its ledger, so it survives being
stopped and can be steered between iterations.

```bash
vigilhunt --resume runs/hunt-<id>.jsonl --iterations 1     # exactly one step
vigilhunt --steer  runs/hunt-<id>.jsonl --prompt "pivot to DNS if this stalls"
vigilhunt --steer  runs/hunt-<id>.jsonl --prompt "check 45.77.53.176" --lead
vigilhunt --steer  runs/hunt-<id>.jsonl --abort
```

`--steer` appends to `<ledger>.inbox.jsonl` from any process and returns. The
running hunt drains the inbox at its next iteration boundary and ingests each
directive into the ledger, so a second producer never breaks the rule that only
the controller mutates state. A `note` steers the next decision, a `lead` joins
the frontier, an `abort` ends the hunt as `aborted` before another model call.

**Directives are the one thing in the digest that is direction.** They render
outside the `<vigil:evidence>` delimiters and are labelled as coming from an
authenticated operator — the deliberate inverse of the injection boundary.

**Ctrl-C** pauses after the current iteration and offers a directive prompt, so
a graceful pause loses nothing. A second Ctrl-C stops immediately; the
interrupted iteration is reaped on the next resume, its lead handed back to the
frontier and its dispatch recorded as a visibility gap. Worst case is one lost
iteration.

The resumed hunt reads no YAML: the resolved spec is written onto the ledger at
hunt start, so editing `arch/threathunt.yaml` mid-run cannot change a hunt in
flight. A `<ledger>.lease` file serializes advancement across processes; a lease
is reclaimed once expired, which is what stands in for a watchdog.

LLM traffic goes through [Bifrost](https://github.com/maximhq/bifrost) on its
OpenAI-format surface, so models are provider-prefixed (`openai/gpt-4o`) and the
gateway holds the provider keys.

## Three layers

Keys are **disjoint**: each belongs to exactly one file and appearing in the
wrong one is a load error, so there is no precedence chain to reason about.

| file | owns | authored by |
|---|---|---|
| `arch/threathunt.yaml` | the lead, the worker registry, their prompts and output schemas, `dispatch`, `digest` | operator |
| `frothly.yaml` (`--workflow`) | hypotheses, ATT&CK mapping, data domains, scope, `directives`, narrative | uploadable |
| `vigil.config.yaml` | `model`, `rates`, `budgets`, `runtime`, `tools` | operator |

The playbook is the only layer meant to be handed around, and it deliberately
cannot declare a schema, a tool, a model, or a budget. Its `directives` are
appended per role to the arch prompt rather than replacing it: the arch says how
to reason about any dataset, the playbook says what this one is.

An arch may **narrow** the decision vocabulary — drop `HANDOFF_IR` if there is no
IR team to hand off to — but never widen it. A verb the controller cannot execute
is rejected at load rather than becoming a dead end the lead keeps choosing.

`rates` is USD per million tokens and is required. It lives in config rather than
a table in code because a model with no known rate would bill zero and silently
disable `budgets.max_cost_usd`.

## The ledger

One JSONL file per hunt under `runs/`, one event per line, append-only. State is
a fold over that file and is never written back, so the file is the whole audit
trail: every decision with the digest exactly as the model saw it, every query
with its cost, and every hypothesis transition.

Workers append evidence; only the controller mutates state. Unresolved
hypotheses close as `inconclusive`, never `disproven` — the hunt stopped
looking, which is not the same as having cleared them.

## The digest

What the lead sees is lossy but never silently so. A **promote-only salience
floor** may raise a worker's own tag and never lower it: sanitizer-flagged or
attacker-influenceable, contradicts an active hypothesis, first sighting of an
entity that went on to recur, or a rare pairing of two familiar entities. Only a
human demotes.

Promotion is protection — **only `routine` is ever compressed.** Anomalous and
notable records survive verbatim at any window size, so raising a mis-tagged
record is what keeps it readable.

Two rules take the entity graph as input, and both stay dormant below
`digest.graph_warmup`: early on, every entity is new and every pairing has count
one, so they would promote the whole ledger and rank nothing. They also ignore
values seen exactly once — telemetry is mostly one-off addresses, and a rule that
fires on nearly every record says nothing.

Routine records that fall out of the window are **named, not dropped**: the
`Compressed` block lists their ids, and a small seeded sample is resurfaced each
turn, weighted toward records the lead has never been shown. The seed is
journaled on the hunt event, so a resumed hunt resurfaces exactly what an
uninterrupted one would and a replay is exact — fold the events up to any
decision, rebuild, and you get the digest that decision was made against.

The entity graph itself is a fold over the entities stored on each record. There
is no second copy to drift, and because extraction is stored at capture rather
than recomputed, tightening the pattern later cannot rewrite the graph a past
decision was made against.

## EXPAND

`EXPAND` cites evidence ids, returns their raw payloads, and **does not consume an
iteration** — it re-asks the lead with more in front of it, bounded, with the cost
still charged against `max_cost_usd`. It is how a record named in the `Compressed`
block gets read again. The inline `expand` tool is cheaper when the lead is
mid-thought; the action is the portable path, since tool calling is exactly what
the gateway fallback downgrades away from.

Payloads are attacker-controlled, so they render inside `<vigil:evidence>` like
all evidence, and the total is capped per expansion — whole records are dropped at
the boundary and named, rather than one being cut mid-JSON.

```bash
jq -r 'select(.kind=="evidence") | .evidence.summary' runs/hunt-*.jsonl
```

## Workers

`roles.workers` in the arch **is** the agent-ID registry: its keys are the ids the
lead may name in `worker_agent_id`, and a decision naming anything else is
rejected before a worker runs. The roster the lead reads is generated from that
map, so a prompt cannot drift from the specialists that exist.

| agent id | tools | for |
|---|---|---|
| `threat_hunter` | `duckdb_query` | broad behavioural hunting across every domain |
| `network_analyst` | `duckdb_query` | traffic shape — intervals, jitter, volume asymmetry, DNS, HTTP |
| `threat_intel` | `intel_lookup` | reputation and attribution for observables; no SQL |

A fourth specialist is a YAML block — a description, a prompt, a tool scope. If it
needed a change under `ai/`, the arch layer would have failed. `roles.workers_preamble`
carries the discipline they share, and a playbook's `directives.workers` carries what
they all need to know about one dataset.

## Tools

The lead gets `expand` (retrieve a raw evidence payload) and the query tools stay
off it. The arch names tool ids; the config says what they point at, and a role
naming a tool the config never declared fails at load — so swapping the substrate
is a config entry and a factory, never a controller change.

The DuckDB tool is read-only, rejects anything that is not a single `SELECT`/
`WITH`, caps rows and wall time, and caches identical queries so parallel
workers chasing adjacent leads do not re-run them.

`intel_lookup` indexes the ThreatFox feed once at hunt start and answers from
memory, so lookups cost no network and a hunt stays replayable. Point `feed` at a
local export or a URL — the public recent export needs no key, and where one is
wanted it comes from `THREATFOX_API_KEY`, never from the committed config. An
unreachable feed surfaces as a visibility gap on the calls that need it rather
than failing a hunt that may never ask for intel.

BOTSv3 is from 2018 and ThreatFox is a rolling recent window, so the live feed
will not match that dataset; point `feed` at a seeded local export to exercise
the worker against it.

## The evidence boundary

Worker output is model text derived from attacker-controlled telemetry, so the
controller sanitizes every record before it reaches the ledger — in
`persistDispatch`, not in a dispatcher, so no implementation can skip it. Control
characters are stripped, `<vigil:` sequences are neutralized so nothing can close
the delimiters that contain it, fields are capped with the truncation marked, and
instruction-like text is flagged. Worker-raised questions render as bare markdown,
so they are additionally collapsed to one line.

Flagging feeds machinery that already exists: the salience floor raises a flagged
record to `notable`, and the digest tells the lead that telemetry content is data.
Operator directives are the deliberate exception — authenticated, and never
sanitized, because they are direction.

## Topology

Serial and swarm are the same loop with a different `dispatch`:

```yaml
dispatch:
  mode: parallel          # serial is max_workers: 1
  fan_out_over: questions # or hypotheses
  max_workers: 4
```

On INVESTIGATE the controller opens one worker per open lead, capped, and merges
results in request order however they complete — so two runs over the same
inputs produce the same ledger. A lead is closed when it is taken, not when it
is answered, so nothing is re-issued next turn. Failures become visibility-gap
records and the hunt continues.

The "hypothesis/ledger method" is not a mode: it is the record vocabulary and
the digest rules, and both are already data.

## Layout

| path | what |
|---|---|
| `ai/loop.ts` | the controller: read → decide → dispatch → persist |
| `ai/ledger.ts` | append-only JSONL and its projection |
| `ai/digest.ts` | ledger → what the lead sees: salience floor, resurfacing, compression, contrarian quota |
| `ai/entities.ts` | extraction at capture, and the entity graph as a fold |
| `ai/llm.ts` | `input()`, `output_schema()`, `llm_output()`, and the two role implementations |
| `ai/limiter.ts` | RPM/TPM buckets, concurrency gate, jittered backoff |
| `ai/spec.ts` | the three YAML layers, their merge, and the worker registry |
| `ai/sanitize.ts` | the worker evidence boundary |
| `ai/lease.ts` | per-hunt lockfile so one process advances a ledger |
| `ai/inbox.ts` | the operator directive queue |
| `tools/duckdb.ts` | read-only SQL over the telemetry |
| `tools/threatfox.ts` | the indicator feed behind `intel_lookup` |

The dataset used by `frothly.yaml` is Splunk BOTSv3 converted to DuckDB
(1.94M events). Point `tools[].database` wherever yours lives; the DuckDB tests
skip when it is absent.
