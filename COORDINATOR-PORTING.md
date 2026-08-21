# Porting the coordinator onto `services/agent` (feat/hunt-runnable-from-the-console)

This coordinator was built on the flat, file-and-CLI threat-hunt (`ai/*`, JSONL
ledgers in `runs/`, `vigilhunt` CLI). The service branch is different: Postgres
ledger, BullMQ job queue, Postgres directive queue, an HTTP `serve.ts`. The
coordinator's **logic transfers unchanged**; only its four adapters get rewritten
against that branch's existing seams. Nothing here is a redesign.

## What transfers as-is (the deep logic)

- The decision vocabulary: `START` / `STEER` / `RELATE` / `DROP`, plus the
  coordinator-authored `DEFER` (the cap outcome, never model-chosen).
- Two-tier dedup: deterministic entity-key match first, LLM semantic second.
- Idempotency on `alert_id`, serialization of the decide step, the concurrency
  cap with queued (never dropped) overflow.
- The prompt + schema for the LLM decider (`coordinator-llm.ts`).
- Every unit test — they run against the scripted provider and in-memory fakes,
  so they port with the logic.

## The four adapters to rewrite (the shallow plumbing)

The coordinator is built behind ports, so porting = new implementations of these,
not changes to `coordinator.ts`.

| Port (this repo) | Worktree adapter | Service-branch adapter |
|---|---|---|
| `HuntLauncher.launch` | spawn `vigilhunt --resume` (`coordinator-launcher.ts`) | **enqueue a `StartRequest` onto `RUN_QUEUE`** (BullMQ) via `contracts/job.ts`; `worker.ts` runs it |
| fold source for `fold()` | `readdir runs/*.jsonl` + `Ledger.open` | **query `LedgerRepository`** for runs whose status is active/parked/recent-terminal, build `HuntSummary[]` |
| STEER / RELATE writes | file `steer()` → `<ledger>.inbox.jsonl` | **`DirectiveRepository.enqueue(runId, directive)`** (implements `DirectiveQueue`) — a direct fit, already typed |
| `CoordinatorLog` | append-only JSONL | a Postgres table (or the coordinator's own run in the ledger) |
| `AlertQueue` | `FileAlertQueue` / in-memory | a BullMQ queue (or an HTTP POST route on `serve.ts`) |

## Where it lives

Add `services/agent/workflows/coordinator/` alongside `chat` / `compose` / `hunt`,
or run it as a small intake beside `worker.ts`. It consumes alerts, reads run
state through `LedgerRepository`, and emits `StartRequest` jobs + directives — it
never runs a hunt itself, exactly as here it only starts and steers.

## Seam-by-seam notes

- **START.** On this branch `startHunt`/`resumeHunt` are async + DB-backed and a
  hunt runs as a queued job. So `start()` becomes: assemble the spec
  (`buildSpec`/`assembleSpec` in `core/spec.ts`), enqueue a `StartRequest`
  (`run_kind: "hunt"`) — the worker picks it up. No process spawn.
- **Auto-approval.** `StartRequest` already carries the hypothesis-approval policy;
  set it to auto for the alert path (no human at the prompt), the same decision
  made here.
- **Fold / dedup.** The branch exposes `GET /runs/<id>/projection` and a
  `LedgerRepository`; fold reads run rows (status, seed entity, active
  hypotheses) rather than folding JSONL. Tier-1 entity-key match is unchanged
  (reuse the entity `key`/`parseEntity` from `core`/`workflows/hunt`).
- **STEER/RELATE.** Map straight onto `DirectiveRepository.enqueue`. The
  `coordinator` actor and one-time-note semantics carry over. Single-writer is
  still respected: the coordinator enqueues; the run's controller applies at its
  boundary.
- **DEFER / cap.** Count active runs from the ledger query; over the cap, hold the
  alert (a BullMQ delayed/retained job, or a pending table) instead of the
  in-memory buffer used here.
- **Idempotency.** `DirectiveRepository` is already idempotent on `directive_id`;
  give each alert a stable id and dedup START the same way (a unique job id on
  `RUN_QUEUE`, or a check against the coordinator log table).

## Reference implementation

The full worktree implementation (logic + tests) is on branch
`feat/hunt-coordinator`. Read it there for the exact decision flow, prompt,
schema, and the guardrail behavior the tests pin down, then re-home the four
adapters above.
