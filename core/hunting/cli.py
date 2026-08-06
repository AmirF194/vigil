"""vigil-hunt — the harness CLI.

Phase 1 is CLI-driven by design (a hunt review UI is Phase 4). This is the
walking-skeleton surface: start a hunt from a spec, advance it, and dump the
Ledger. The Hunt Lead is scripted here; #03 swaps in the real one behind the
same port and this file does not change.

    python -m core.hunting.cli start --spec docs/hunts/example.md
    python -m core.hunting.cli show hunt-abc123
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

from core.hunting.controller import HuntController
from core.hunting.schema import Decision, DecisionAction, EvidenceRecord, HuntSpec
from core.hunting.scripted import ScriptedDecisionProvider, ScriptedWorkerDispatcher
from core.hunting.spec_loader import HuntSpecError, load_hunt_spec
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
    if spec.scope:
        print(f"  scope: {json.dumps(spec.scope)}")
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
        spec = load_hunt_spec(Path(args.spec))
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

    for _ in range(args.iterations):
        result = await controller.advance_iteration(hunt_id)
        print(
            f"  [{result.iteration}] {result.action.value:<12} "
            f"evidence+{result.evidence_appended}  ${result.cost_usd:.4f}  "
            f"{result.hunt_status.value}"
            + (f" ({result.hunt_outcome.value})" if result.hunt_outcome else "")
        )
        if result.hunt_status.value == "terminal":
            break

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vigil-hunt", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="create a hunt from a spec and advance it")
    start.add_argument("--spec", required=True, help="path to a HUNT.md spec")
    start.add_argument("--iterations", type=int, default=1)
    start.add_argument("--script", type=Path, help="JSON list of scripted decisions")
    start.add_argument("--evidence", type=Path, help="JSON list of evidence fixtures")
    start.add_argument("--yes", action="store_true", help="skip hypothesis approval")

    show = sub.add_parser("show", help="print Ledger state for a hunt")
    show.add_argument("hunt_id")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "start":
        return asyncio.run(_run_start(args))
    return _run_show(args)


if __name__ == "__main__":
    raise SystemExit(main())
