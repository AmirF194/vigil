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
| `arch/threathunt.yaml` | roles, their prompts and output schemas, `dispatch`, `digest` | operator |
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

```bash
jq -r 'select(.kind=="evidence") | .evidence.summary' runs/hunt-*.jsonl
```

## Tools

The lead gets `expand` (retrieve a raw evidence payload) and the worker gets
`duckdb_query` — the query tool is deliberately not on the lead. The arch names
tool ids; the config says what they point at, and a role naming a tool the config
never declared fails at load.

The DuckDB tool is read-only, rejects anything that is not a single `SELECT`/
`WITH`, caps rows and wall time, and caches identical queries so parallel
workers chasing adjacent leads do not re-run them.

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
| `ai/digest.ts` | ledger → what the lead sees, with the salience floor and contrarian quota |
| `ai/llm.ts` | `input()`, `output_schema()`, `llm_output()`, and the two role implementations |
| `ai/limiter.ts` | RPM/TPM buckets, concurrency gate, jittered backoff |
| `ai/spec.ts` | the three YAML layers and their merge |
| `ai/lease.ts` | per-hunt lockfile so one process advances a ledger |
| `ai/inbox.ts` | the operator directive queue |
| `tools/duckdb.ts` | read-only SQL over the telemetry |

The dataset used by `frothly.yaml` is Splunk BOTSv3 converted to DuckDB
(1.94M events). Point `tools[].database` wherever yours lives; the DuckDB tests
skip when it is absent.
