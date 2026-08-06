# vigilhunt

An isolated, YAML-driven agent loop for hypothesis-driven threat hunting.

A deterministic controller owns the loop and all state. Two LLM roles sit behind
injectable ports: a **lead** that reads a ledger digest and emits one typed
decision, and a **worker** that turns a query intent into evidence. Everything
either role is told, must answer in, and may call is declared in one YAML file,
so a different workflow is a config change rather than a code change.

```
vigilhunt --prompt <prompt> --id <entity> --workflow <spec.yaml>
```

- `--prompt` — the question to hunt; may be used alone
- `--id` — seed entity (`10.0.0.1`, `host:web-01`); never alone
- `--workflow` — the spec; never alone

## Running it

```bash
npm install
npm run hunt -- --prompt "a host is beaconing outbound" --scripted --yes   # no LLM
BIFROST_URL=http://localhost:8080 \
  npm run hunt -- --workflow threat-hunt.yaml --id 192.168.70.186 --iterations 8
npm test
```

`--scripted` runs the whole controller with no model and no database, which is
how the loop mechanics are tested.

LLM traffic goes through [Bifrost](https://github.com/maximhq/bifrost) on its
OpenAI-format surface, so models are provider-prefixed (`openai/gpt-4o`) and the
gateway holds the provider keys.

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

## The spec

`threat-hunt.yaml` is the worked example: hypotheses, budgets, tools, and both
roles' prompts and JSON Schemas, all inline. The lead gets `expand` (retrieve a
raw evidence payload) and the worker gets `duckdb_query` — the query tool is
deliberately not on the lead.

The DuckDB tool is read-only, rejects anything that is not a single `SELECT`/
`WITH`, caps rows and wall time, and caches identical queries so parallel
workers chasing adjacent leads do not re-run them.

## Topology

Serial and swarm are the same loop with a different `runtime.dispatch`:

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
| `ai/spec.ts` | the YAML contract |
| `tools/duckdb.ts` | read-only SQL over the telemetry |

The dataset used by `threat-hunt.yaml` is Splunk BOTSv3 converted to DuckDB
(1.94M events). Point `tools[].database` wherever yours lives; the DuckDB tests
skip when it is absent.
