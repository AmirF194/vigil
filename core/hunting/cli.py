"""vigilhunt — the harness CLI.

Phase 1 is CLI-driven by design (a hunt review UI is Phase 4). This is the
walking-skeleton surface: start a hunt, advance it, and dump the Ledger. The
Hunt Lead is scripted here; #03 swaps in the real one behind the same port and
this file does not change.

Three ways in, all of which end up as one HuntSpec: a question, a spec file, or
a spec file aimed at a seed entity. ``start`` is implicit, so the common case
reads as one line.

    vigilhunt --prompt "a cloud credential is in use from new infrastructure"
    vigilhunt --prompt "..." --entity 203.0.113.9
    vigilhunt --spec docs/hunts/example.md --entity host:web-01
    vigilhunt show hunt-abc123
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

from core.hunting.controller import HuntController
from core.hunting.schema import (
    Decision,
    DecisionAction,
    EvidenceRecord,
    HuntSpec,
    HuntStatus,
)
from core.hunting.scripted import ScriptedDecisionProvider, ScriptedWorkerDispatcher
from core.hunting.spec_loader import HuntSpecError, build_hunt_spec
from core.hunting.uow import HuntUnitOfWork

# What the skeleton runs when no script is supplied: look, then stop.
DEFAULT_SCRIPT = [
    Decision(
        action=DecisionAction.INVESTIGATE,
        rationale="opening query against the seeded hypothesis",
        query_intent="establish a baseline for the hypothesis",
    ),
    Decision(action=DecisionAction.CONCLUDE, rationale="skeleton run complete"),
]


def _ensure_database() -> None:
    """Initialize the DB manager for this process.

    The API does this in its FastAPI startup hook and the ARQ worker does it in
    its own bootstrap; the CLI is a third process and has to do the same before
    any session is opened.
    """
    from database.connection import init_database

    init_database(echo=False, create_tables=True)


def _load_decisions(path: Optional[Path]) -> List[Decision]:
    if path is None:
        return list(DEFAULT_SCRIPT)
    raw = json.loads(path.read_text())
    return [Decision(**item) for item in raw]


def _load_evidence(path: Optional[Path]) -> List[EvidenceRecord]:
    if path is None:
        return []
    raw = json.loads(path.read_text())
    return [EvidenceRecord(**item) for item in raw]


def _confirm_hypotheses(spec: HuntSpec, assume_yes: bool) -> bool:
    """Hypothesis approval before any query runs.

    A hunt should not start querying on a premise nobody sanctioned. #09
    replaces this with the real checkpoint machinery; the beat exists from the
    first commit so the demo never opens with an unapproved autonomous run.
    """
    print(f"\nHunt: {spec.name}")
    for index, statement in enumerate(spec.hypotheses, start=1):
        print(f"  H{index}. {statement}")

    entity = spec.scope.get("entity")
    if entity:
        print(f"  target: {entity['type']} {entity['value']}")
    rest = {key: value for key, value in spec.scope.items() if key != "entity"}
    if rest:
        print(f"  scope: {json.dumps(rest)}")
    print(
        f"  budgets: {spec.budgets.max_iterations} iterations, "
        f"${spec.budgets.max_cost_usd:.2f}"
    )

    if assume_yes or not sys.stdin.isatty():
        return True
    return input("\nApprove and start this hunt? [y/N] ").strip().lower() in {
        "y",
        "yes",
    }


async def _run_start(args: argparse.Namespace) -> int:
    try:
        spec = build_hunt_spec(
            spec_path=args.spec, prompt=args.prompt, entity=args.entity
        )
    except HuntSpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not _confirm_hypotheses(spec, args.yes):
        print("aborted — no hunt created")
        return 1

    _ensure_database()

    with HuntUnitOfWork() as uow:
        hunt = uow.hunts.create_hunt(spec)
        hunt_id = hunt.hunt_id
        uow.commit()
    print(f"\ncreated {hunt_id}")

    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(_load_decisions(args.script)),
        dispatcher=ScriptedWorkerDispatcher(_load_evidence(args.evidence)),
    )

    result = None
    for _ in range(args.iterations):
        result = await controller.advance_iteration(hunt_id)
        print(
            f"  [{result.iteration}] {result.action.value:<12} "
            f"evidence+{result.evidence_appended}  ${result.cost_usd:.4f}  "
            f"{result.hunt_status.value}"
            + (f" ({result.hunt_outcome.value})" if result.hunt_outcome else "")
        )
        if result.hunt_status is HuntStatus.TERMINAL:
            break

    # Running out of --iterations looks identical to finishing unless we say
    # otherwise, and a hunt left mid-flight reads as a broken one.
    if result is not None and result.hunt_status is not HuntStatus.TERMINAL:
        print(
            "\nstill active — stopped at the --iterations limit, not at a "
            "verdict.\nstart a hunt with a higher --iterations to reach one."
        )

    return 0


def _run_show(args: argparse.Namespace) -> int:
    _ensure_database()
    with HuntUnitOfWork() as uow:
        hunt = uow.hunts.get_hunt(args.hunt_id)
        if hunt is None:
            print(f"error: no such hunt: {args.hunt_id}", file=sys.stderr)
            return 2

        print(f"{hunt.hunt_id}  {hunt.name}")
        print(
            f"  status     {hunt.status}"
            + (f" / {hunt.outcome}" if hunt.outcome else "")
        )
        print(f"  iterations {hunt.iteration}")
        print(f"  cost       ${hunt.cost_usd:.4f}")

        print("\n  hypotheses")
        for row in uow.hunts.get_hypotheses(hunt.hunt_id):
            print(f"    [{row.status:<12}] {row.statement}")

        evidence = uow.hunts.get_evidence(hunt.hunt_id)
        print(f"\n  hunt evidence ({len(evidence)})")
        for row in evidence:
            print(
                f"    {row.evidence_id}  {row.salience:<9} "
                f"{row.source_system}: {row.summary}"
            )

        print("\n  decisions")
        for row in uow.hunts.get_decisions(hunt.hunt_id):
            print(
                f"    [{row.iteration}] {row.action:<12} {row.model_id}"
                f" ${row.cost_usd:.4f}  {row.rationale}"
            )
    return 0


SUBCOMMANDS = frozenset({"start", "show"})


def _validate_entry(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """A hunt needs a question, and only two flags can supply one.

    ``--prompt`` is a question outright; a spec file declares its own. An
    entity is a target with nothing asked about it, so it never stands alone.
    """
    if not args.prompt and not args.spec:
        parser.error(
            "nothing to hunt: give --prompt, or --spec; --entity names a "
            "target but does not say what to look for"
        )


USAGE_EXAMPLES = """\
examples:
  vigilhunt --prompt "a cloud credential is in use from new infrastructure"
  vigilhunt --prompt "..." --entity 203.0.113.9
  vigilhunt --spec docs/hunts/example.md --entity host:web-01
  vigilhunt show hunt-abc123

`start` is implicit, so the verb is only needed for the other subcommands.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigilhunt",
        description="Run an agentic threat hunt against the Hunt Ledger.",
        epilog=USAGE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="create a hunt and advance it")
    start.add_argument("--prompt", help="the question to hunt: a hypothesis to test")
    start.add_argument(
        "--spec",
        "--workflow",
        dest="spec",
        type=Path,
        help="path to a HUNT.md spec (--workflow is an alias)",
    )
    start.add_argument(
        "--entity",
        "--id",
        dest="entity",
        help="seed entity, e.g. 203.0.113.9 or host:web-01 (--id is an alias)",
    )
    start.add_argument("--iterations", type=int, default=1)
    start.add_argument("--script", type=Path, help="JSON list of scripted decisions")
    start.add_argument("--evidence", type=Path, help="JSON list of evidence fixtures")
    start.add_argument("--yes", action="store_true", help="skip hypothesis approval")

    show = sub.add_parser("show", help="print Ledger state for a hunt")
    show.add_argument("hunt_id")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Starting a hunt is the overwhelmingly common case, so `start` is implicit
    # and the verb is only needed for the other subcommands.
    if argv and argv[0] not in SUBCOMMANDS and argv[0] not in {"-h", "--help"}:
        argv.insert(0, "start")

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "start":
        _validate_entry(args, parser)
        return asyncio.run(_run_start(args))
    return _run_show(args)


if __name__ == "__main__":
    raise SystemExit(main())
