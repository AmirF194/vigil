# Coordinator — scope

A layer that sits **above** the hunts and decides what to do when a new alert comes in.

Today a person starts every hunt by hand with the CLI. The coordinator adds a
second, automated door: alerts arrive, and for each one it decides whether to
start a new hunt, feed an existing hunt, link related hunts, or do nothing.

Nothing about how a hunt works changes. The coordinator only ever *starts* hunts
and *drops notes into their inboxes* — it never reaches inside a running hunt.

## The one rule we keep

Each hunt owns its own ledger, and **only that hunt writes to it.** The
coordinator respects this: to influence a running hunt it appends a directive to
that hunt's inbox (the same mechanism `--steer` uses), which the hunt picks up at
its next step. No shared memory, no cross-hunt writes.

## What it is

A **long-running service** (daemon). It stays up and waits for alerts. When one
arrives, it wakes up a single LLM call to make a decision, then goes back to
waiting. The LLM keeps no memory between alerts — every time, it reads the alert
fresh and looks up the current state of the hunts.

## What an alert looks like

A structured record: a primary entity (IP, host, …), a rule/detection name, a
severity, a timestamp, and the raw fields. Some fields may be missing (the rule
name in particular) — the coordinator must cope with that.

Alerts arrive by being pushed onto a **queue**.

## What happens for each alert

Alerts are handled **one at a time** (serialized), so every decision sees a
consistent picture and two alerts can't race to start the same hunt.

1. **Look up current state.** Read the hunt files in `runs/` and build a short
   one-line summary of each hunt that is active, parked, or recently finished.
   (Derived fresh each time — no separate copy to fall out of date.)

2. **Check for duplicates, in two passes:**
   - **Exact:** does the alert's entity already match a running hunt? Cheap and
     certain.
   - **Fuzzy:** the LLM judges whether the alert is *related* to a hunt even when
     the entities differ (same campaign, etc.).

3. **Decide one action** from a fixed list:
   - `START` — a genuinely new hunt.
   - `STEER <hunt>` — feed this into an existing hunt (a duplicate or a lead).
   - `RELATE <hunts>` — leave the hunts separate but tell each about the other.
   - `DROP` — do nothing, **with a written reason.**

## How each action is carried out

- **STEER / RELATE / DROP** happen automatically — they're cheap and reversible.
  - `RELATE` = a **one-time note** dropped into each related hunt's inbox naming
    the sibling and the shared entity. Not an ongoing feed.
- **START** turns the alert into a hunt (entity as the seed, a prompt built from
  whatever the alert contains, and a playbook only if the rule name maps to one).
  Because no human is at the keyboard, the start-approval step **auto-approves** —
  but it's still recorded on the ledger so a person can review it later.
- Everything the coordinator writes is stamped with a **`coordinator`** actor, so
  the record clearly shows a machine did it — not a person, not a default.

## Its own record

The coordinator keeps its **own append-only log**: every alert in, and every
decision out. This is the only place a `DROP` is explained ("why did no hunt
start for this?"). A same-entity past drop is surfaced on the next matching alert;
otherwise the log is just for audit — we don't scan all past drops (no graph to
retrieve them well, and it would waste the LLM's context).

## Guardrails

- **Don't handle the same alert twice.** Each alert has a stable id; if the queue
  redelivers one after a crash, the coordinator's log shows it was already handled
  and skips it.
- **Cap concurrent hunts.** Over the limit, alerts **wait in the queue** — they're
  never dropped.

## How we'll test it (before real alerts exist)

The coordinator is real code; only the pieces around it are faked — the same way
the hunt loop is already tested.

- **Alerts:** a folder of example alert files + a feeder that pushes them onto an
  in-memory version of the queue. Lets us script storms, duplicates, repeats, and
  sparse alerts.
- **Hunt state to look up:** generate real ledgers with the existing `--scripted`
  mode (no LLM, no database). The coordinator reads them exactly as in production.
- **The decision LLM:** put it behind a port and inject a scripted version that
  returns canned decisions — so the whole coordinator runs deterministically with
  no model calls. (The queue is behind a port the same way: real transport later,
  in-memory fake for tests.)

Only the transport and the two model calls are mocked. Everything we're building
— the dedup, serialization, inbox nudges, audit log, idempotency, and cap — runs
for real under test.

## What we are NOT building (yet)

- No ongoing evidence-sharing bridge between hunts (only the one-time note).
- No global cost ceiling across hunts (just the concurrency cap).
- No graph-based retrieval of history.
- No changes to how a hunt itself runs.
