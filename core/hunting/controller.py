"""The hunt controller — deterministic owner of the loop and of all state.

One call to :meth:`HuntController.advance_iteration` is exactly one turn:
read the Ledger, ask the Hunt Lead for a single decision, apply it, and
persist. Nothing else mutates the Ledger, which is what makes the hunt
resumable (state is never in memory between turns) and replayable (every turn
leaves a decision snapshot).

Scope note for the walking skeleton: CONCLUDE terminates directly here. In the
finished design CONCLUDE is only a *recommendation* and the controller owns a
deterministic termination predicate that refuses to conclude while any
hypothesis is active — that lands with #08 and replaces
:meth:`_apply_conclude`.
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable, Optional

from core.hunting.digest import build_digest
from core.hunting.ports import DecisionProvider, WorkerDispatcher
from core.hunting.schema import (
    OUTCOME_PRECEDENCE,
    Decision,
    DecisionAction,
    DecisionResult,
    Digest,
    DispatchRequest,
    DispatchResult,
    HuntBudgets,
    HuntOutcome,
    HuntStatus,
    HypothesisStatus,
    IterationResult,
)
from core.hunting.uow import HuntUnitOfWork

logger = logging.getLogger(__name__)

DEFAULT_WORKER_AGENT_ID = "threat_hunter"


def _new_dispatch_id() -> str:
    return f"dsp-{uuid.uuid4().hex[:12]}"


class HuntNotFound(Exception):
    pass


class HuntAlreadyTerminal(Exception):
    pass


class HuntController:
    def __init__(
        self,
        decision_provider: DecisionProvider,
        dispatcher: Optional[WorkerDispatcher] = None,
        uow_factory: Optional[Callable[[], HuntUnitOfWork]] = None,
        dispatch_id_factory: Optional[Callable[[], str]] = None,
    ):
        self._provider = decision_provider
        self._dispatcher = dispatcher
        self._uow_factory = uow_factory or HuntUnitOfWork
        # Injectable so #02's watchdog can re-issue a stale dispatch under its
        # original id — reusing the id is what makes the retry idempotent.
        self._dispatch_id_factory = dispatch_id_factory or _new_dispatch_id

    async def advance_iteration(self, hunt_id: str) -> IterationResult:
        digest, iteration = self._read_phase(hunt_id)

        # The model call and the worker run happen with no transaction open:
        # both are network-bound, and holding a Postgres transaction across
        # them would pin a connection for the length of an LLM response.
        result = await self._provider.decide(digest)
        dispatch_result = await self._maybe_dispatch(
            hunt_id, iteration, result.decision
        )

        return self._write_phase(hunt_id, iteration, digest, result, dispatch_result)

    def _read_phase(self, hunt_id: str) -> tuple[Digest, int]:
        with self._uow_factory() as uow:
            hunt = uow.hunts.get_hunt(hunt_id)
            if hunt is None:
                raise HuntNotFound(hunt_id)
            if hunt.status == HuntStatus.TERMINAL.value:
                raise HuntAlreadyTerminal(
                    f"{hunt_id} already ended as {hunt.outcome!r}"
                )
            iteration = hunt.iteration + 1
            return build_digest(uow.hunts, hunt, iteration), iteration

    async def _maybe_dispatch(
        self, hunt_id: str, iteration: int, decision: Decision
    ) -> Optional[DispatchResult]:
        if decision.action is not DecisionAction.INVESTIGATE:
            return None
        if self._dispatcher is None:
            logger.info("INVESTIGATE with no dispatcher configured; recording only")
            return None

        request = DispatchRequest(
            dispatch_id=self._dispatch_id_factory(),
            hunt_id=hunt_id,
            agent_id=decision.worker_agent_id or DEFAULT_WORKER_AGENT_ID,
            query_intent=decision.query_intent or decision.rationale,
            target_hypothesis_id=decision.target_hypothesis_id,
        )

        # Committed *before* the worker runs. A crash mid-dispatch then leaves
        # a pending row for #02's watchdog to reap into a retry or a gap;
        # recording the dispatch only on return would leave no trace at all.
        with self._uow_factory() as uow:
            uow.hunts.begin_dispatch(request, iteration)
            uow.commit()

        try:
            return await self._dispatcher.dispatch(request)
        except Exception as exc:  # a failed worker is evidence about visibility
            logger.warning("dispatch %s failed: %s", request.dispatch_id, exc)
            return DispatchResult(
                dispatch_id=request.dispatch_id, failed=True, failure_reason=str(exc)
            )

    def _write_phase(
        self,
        hunt_id: str,
        iteration: int,
        digest: Digest,
        result: DecisionResult,
        dispatch_result: Optional[DispatchResult],
    ) -> IterationResult:
        with self._uow_factory() as uow:
            repo = uow.hunts
            hunt = repo.get_hunt(hunt_id)
            if hunt is None:
                raise HuntNotFound(hunt_id)
            if hunt.status == HuntStatus.TERMINAL.value:
                # The hunt ended while this iteration was in flight — a human
                # abort, or another mutator before the lease lands (#02). A
                # terminal outcome is final, so discard this turn rather than
                # reopen the hunt or relabel what it ended as.
                logger.warning(
                    "discarding iteration %s of %s: hunt ended as %s in flight "
                    "(%s, $%.4f)",
                    iteration,
                    hunt_id,
                    hunt.outcome,
                    result.decision.action.value,
                    result.cost_usd,
                )
                raise HuntAlreadyTerminal(
                    f"{hunt_id} ended as {hunt.outcome!r} during iteration {iteration}"
                )

            decision_row = repo.record_decision(hunt_id, iteration, digest, result)
            repo.advance_iteration(hunt)
            repo.add_cost(hunt, result.cost_usd)

            appended = 0
            if dispatch_result is not None:
                appended = self._persist_dispatch(
                    repo, hunt_id, iteration, result.decision, dispatch_result
                )

            note = ""
            if result.decision.action is DecisionAction.CONCLUDE:
                self._apply_conclude(repo, hunt)
            elif self._budget_exhausted(hunt):
                self._terminate(repo, hunt, HuntOutcome.BUDGET_TERMINATED)
                note = "iteration budget exhausted"

            outcome = HuntOutcome(hunt.outcome) if hunt.outcome else None
            iteration_result = IterationResult(
                hunt_id=hunt_id,
                iteration=iteration,
                action=result.decision.action,
                decision_id=decision_row.decision_id,
                cost_usd=result.cost_usd,
                evidence_appended=appended,
                hunt_status=HuntStatus(hunt.status),
                hunt_outcome=outcome,
                note=note,
            )
            uow.commit()
            return iteration_result

    def _persist_dispatch(
        self,
        repo,
        hunt_id: str,
        iteration: int,
        decision: Decision,
        dispatch_result: DispatchResult,
    ) -> int:
        dispatch = repo.get_dispatch(dispatch_result.dispatch_id)
        if dispatch is None:
            # The worker answered under an id we did not issue. Record it
            # rather than drop the evidence, but it is worth knowing about.
            logger.warning(
                "dispatch %s was not issued by this controller",
                dispatch_result.dispatch_id,
            )
            dispatch = repo.begin_dispatch(
                DispatchRequest(
                    dispatch_id=dispatch_result.dispatch_id,
                    hunt_id=hunt_id,
                    agent_id=decision.worker_agent_id or DEFAULT_WORKER_AGENT_ID,
                    query_intent=decision.query_intent or decision.rationale,
                    target_hypothesis_id=decision.target_hypothesis_id,
                ),
                iteration,
            )

        # Idempotency on dispatch_id: a retried dispatch re-delivers the same
        # evidence, and appending it twice would inflate corroboration counts.
        # #04 hardens this with the watchdog's retry path.
        if repo.evidence_ids_for_dispatch(dispatch_result.dispatch_id):
            repo.complete_dispatch(dispatch, failed=dispatch_result.failed)
            return 0

        appended = 0
        for record in dispatch_result.evidence:
            record.dispatch_id = dispatch_result.dispatch_id
            repo.append_evidence(hunt_id, record, iteration)
            appended += 1

        repo.complete_dispatch(
            dispatch,
            failed=dispatch_result.failed,
            failure_reason=dispatch_result.failure_reason,
        )
        return appended

    def _apply_conclude(self, repo, hunt) -> None:
        self._terminate(repo, hunt, HuntOutcome.COMPLETED)

    def _terminate(self, repo, hunt, outcome: HuntOutcome) -> None:
        """Close the hunt, coercing unresolved hypotheses to inconclusive.

        Never disproven: the hunt stopped looking, which is not the same as
        having cleared the hypothesis.

        An outcome already on the record is never downgraded — aborted >
        data_starved > budget_terminated > completed — so "we stopped early"
        cannot be overwritten by a later, gentler verdict.
        """
        recorded = HuntOutcome(hunt.outcome) if hunt.outcome else None
        if recorded is not None and (
            OUTCOME_PRECEDENCE[recorded] >= OUTCOME_PRECEDENCE[outcome]
        ):
            return

        for hypothesis in repo.get_active_hypotheses(hunt.hunt_id):
            repo.set_hypothesis_status(
                hypothesis,
                HypothesisStatus.INCONCLUSIVE,
                reason=f"hunt ended ({outcome.value}) with the hypothesis unresolved",
            )
        repo.set_status(hunt, HuntStatus.TERMINAL, outcome=outcome.value)

    def _budget_exhausted(self, hunt) -> bool:
        budgets = HuntBudgets(**(hunt.budgets or {}))
        return hunt.iteration >= budgets.max_iterations
