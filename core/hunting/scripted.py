"""Scripted implementations of the two ports.

These are how the controller is exercised without a live model or a live SIEM:
tests hand it a list of decisions and a bank of evidence and assert on the
resulting Ledger state. They are also the demo fallback — swapping the real
Hunt Lead for a scripted one changes nothing else in the loop.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from core.hunting.schema import (
    Decision,
    DecisionAction,
    DecisionResult,
    Digest,
    DispatchRequest,
    DispatchResult,
    EvidenceRecord,
)

SCRIPTED_MODEL_ID = "scripted"


class ScriptedDecisionProvider:
    """Replays a fixed decision sequence, then falls back to CONCLUDE.

    The fallback keeps a test from hanging when the script runs out: a hunt
    that outlives its script ends rather than looping.
    """

    def __init__(
        self,
        decisions: Iterable[Decision],
        cost_per_decision: float = 0.0,
        model_id: str = SCRIPTED_MODEL_ID,
    ):
        self._decisions: List[Decision] = list(decisions)
        self._cost = cost_per_decision
        self._model_id = model_id
        self.seen_digests: List[Digest] = []

    @property
    def exhausted(self) -> bool:
        return not self._decisions

    async def decide(self, digest: Digest) -> DecisionResult:
        self.seen_digests.append(digest)
        if self._decisions:
            decision = self._decisions.pop(0)
        else:
            decision = Decision(
                action=DecisionAction.CONCLUDE,
                rationale="scripted provider exhausted",
            )
        return DecisionResult(
            decision=decision, model_id=self._model_id, cost_usd=self._cost
        )


class ScriptedWorkerDispatcher:
    """Returns canned evidence, optionally keyed by the worker's agent id.

    ``fail_agent_ids`` forces the failure path so tool-failure handling can be
    tested without breaking a real integration.
    """

    def __init__(
        self,
        evidence: Optional[Iterable[EvidenceRecord]] = None,
        by_agent: Optional[Dict[str, List[EvidenceRecord]]] = None,
        fail_agent_ids: Optional[Iterable[str]] = None,
    ):
        self._evidence: List[EvidenceRecord] = list(evidence or [])
        self._by_agent = by_agent or {}
        self._fail = set(fail_agent_ids or [])
        self.requests: List[DispatchRequest] = []

    async def dispatch(self, request: DispatchRequest) -> DispatchResult:
        self.requests.append(request)

        if request.agent_id in self._fail:
            return DispatchResult(
                dispatch_id=request.dispatch_id,
                failed=True,
                failure_reason=f"scripted failure for {request.agent_id}",
            )

        records = self._by_agent.get(request.agent_id)
        if records is None:
            records = self._evidence
        return DispatchResult(
            dispatch_id=request.dispatch_id,
            evidence=[record.model_copy(deep=True) for record in records],
        )
