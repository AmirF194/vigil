"""Typed data access for the Hunt Ledger.

The only module that knows the Ledger is SQLAlchemy. Controller, CLI, and
(later) routers ask for hunts and evidence in domain terms; no query builder
and no raw SQL leaks past this file.

Methods flush but never commit — the transaction boundary belongs to
:class:`core.hunting.uow.HuntUnitOfWork`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.hunting.models import (
    HuntDecision,
    HuntDispatch,
    HuntEvidence,
    HuntEvidenceLink,
    HuntHypothesis,
    HuntOpenQuestion,
    HuntRecord,
)
from core.hunting.schema import (
    SCHEMA_VERSION,
    Decision,
    DecisionResult,
    Digest,
    DispatchRequest,
    EvidenceRecord,
    HuntSpec,
    HuntStatus,
    HypothesisStatus,
    LinkRelation,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class HuntRepository:
    def __init__(self, session: Session):
        self.session = session

    # ---- hunts ---------------------------------------------------------

    def create_hunt(
        self,
        spec: HuntSpec,
        status: HuntStatus = HuntStatus.ACTIVE,
        trigger_case_id: Optional[str] = None,
    ) -> HuntRecord:
        hunt = HuntRecord(
            hunt_id=_new_id("hunt"),
            name=spec.name,
            status=status.value,
            iteration=0,
            spec=spec.model_dump(mode="json"),
            budgets=spec.budgets.model_dump(mode="json"),
            cost_usd=0.0,
            trigger_case_id=trigger_case_id,
            schema_version=SCHEMA_VERSION,
        )
        self.session.add(hunt)
        self.session.flush()

        for statement in spec.hypotheses:
            self.add_hypothesis(hunt.hunt_id, statement)
        return hunt

    def get_hunt(self, hunt_id: str) -> Optional[HuntRecord]:
        return self.session.get(HuntRecord, hunt_id)

    def list_hunts(self, limit: int = 50) -> List[HuntRecord]:
        stmt = select(HuntRecord).order_by(HuntRecord.created_at.desc()).limit(limit)
        return list(self.session.scalars(stmt))

    def set_status(
        self,
        hunt: HuntRecord,
        status: HuntStatus,
        outcome: Optional[str] = None,
    ) -> None:
        hunt.status = status.value
        if outcome is not None:
            hunt.outcome = outcome
        if status is HuntStatus.TERMINAL:
            hunt.terminated_at = datetime.utcnow()
        self.session.flush()

    def advance_iteration(self, hunt: HuntRecord) -> int:
        hunt.iteration += 1
        self.session.flush()
        return hunt.iteration

    def add_cost(self, hunt: HuntRecord, cost_usd: float) -> None:
        hunt.cost_usd = (hunt.cost_usd or 0.0) + cost_usd
        self.session.flush()

    # ---- hypotheses ----------------------------------------------------

    def add_hypothesis(self, hunt_id: str, statement: str) -> HuntHypothesis:
        hypothesis = HuntHypothesis(
            hypothesis_id=_new_id("hyp"),
            hunt_id=hunt_id,
            statement=statement,
            status=HypothesisStatus.ACTIVE.value,
            evidence_strength={},
            schema_version=SCHEMA_VERSION,
        )
        self.session.add(hypothesis)
        self.session.flush()
        return hypothesis

    def get_hypotheses(self, hunt_id: str) -> List[HuntHypothesis]:
        stmt = (
            select(HuntHypothesis)
            .where(HuntHypothesis.hunt_id == hunt_id)
            .order_by(HuntHypothesis.created_at)
        )
        return list(self.session.scalars(stmt))

    def get_active_hypotheses(self, hunt_id: str) -> List[HuntHypothesis]:
        stmt = select(HuntHypothesis).where(
            HuntHypothesis.hunt_id == hunt_id,
            HuntHypothesis.status == HypothesisStatus.ACTIVE.value,
        )
        return list(self.session.scalars(stmt))

    def set_hypothesis_status(
        self,
        hypothesis: HuntHypothesis,
        status: HypothesisStatus,
        reason: Optional[str] = None,
    ) -> None:
        hypothesis.status = status.value
        if reason is not None:
            hypothesis.resolution_reason = reason
        hypothesis.resolved_at = datetime.utcnow()
        self.session.flush()

    # ---- open questions ------------------------------------------------

    def add_open_question(
        self,
        hunt_id: str,
        question: str,
        spawning_evidence_id: Optional[str] = None,
    ) -> HuntOpenQuestion:
        record = HuntOpenQuestion(
            question_id=_new_id("oq"),
            hunt_id=hunt_id,
            question=question,
            status="open",
            priority_features={},
            spawning_evidence_id=spawning_evidence_id,
            schema_version=SCHEMA_VERSION,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def get_open_questions(self, hunt_id: str) -> List[HuntOpenQuestion]:
        stmt = select(HuntOpenQuestion).where(
            HuntOpenQuestion.hunt_id == hunt_id,
            HuntOpenQuestion.status == "open",
        )
        return list(self.session.scalars(stmt))

    # ---- evidence ------------------------------------------------------

    def append_evidence(
        self, hunt_id: str, record: EvidenceRecord, iteration: int
    ) -> HuntEvidence:
        evidence = HuntEvidence(
            evidence_id=record.evidence_id or _new_id("ev"),
            hunt_id=hunt_id,
            dispatch_id=record.dispatch_id,
            iteration=iteration,
            source_system=record.source_system,
            summary=record.summary,
            payload=record.payload,
            salience=record.salience.value,
            why_notable=record.why_notable,
            provenance=record.provenance,
            attacker_influenceable=record.attacker_influenceable,
            instruction_like=record.instruction_like,
            captured_at=record.captured_at or datetime.utcnow(),
            schema_version=record.schema_version,
        )
        self.session.add(evidence)
        self.session.flush()
        return evidence

    def get_evidence(self, hunt_id: str, limit: int = 200) -> List[HuntEvidence]:
        stmt = (
            select(HuntEvidence)
            .where(HuntEvidence.hunt_id == hunt_id)
            .order_by(HuntEvidence.captured_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(stmt))

    def get_evidence_by_ids(
        self, hunt_id: str, evidence_ids: List[str]
    ) -> List[HuntEvidence]:
        if not evidence_ids:
            return []
        stmt = select(HuntEvidence).where(
            HuntEvidence.hunt_id == hunt_id,
            HuntEvidence.evidence_id.in_(evidence_ids),
        )
        return list(self.session.scalars(stmt))

    def evidence_ids_for_dispatch(self, dispatch_id: str) -> List[str]:
        stmt = select(HuntEvidence.evidence_id).where(
            HuntEvidence.dispatch_id == dispatch_id
        )
        return list(self.session.scalars(stmt))

    def link_evidence(
        self, evidence_id: str, hypothesis_id: str, relation: LinkRelation
    ) -> HuntEvidenceLink:
        link = HuntEvidenceLink(
            link_id=_new_id("lnk"),
            evidence_id=evidence_id,
            hypothesis_id=hypothesis_id,
            relation=relation.value,
        )
        self.session.add(link)
        self.session.flush()
        return link

    # ---- decisions -----------------------------------------------------

    def record_decision(
        self,
        hunt_id: str,
        iteration: int,
        digest: Digest,
        result: DecisionResult,
        rejected_attempts: Optional[List[dict]] = None,
    ) -> HuntDecision:
        """Write the audit spine row for one iteration.

        The digest is stored as presented so replay reconstructs the model's
        actual inputs; cost lands here rather than being derived later.
        """
        decision: Decision = result.decision
        row = HuntDecision(
            decision_id=_new_id("dec"),
            hunt_id=hunt_id,
            iteration=iteration,
            action=decision.action.value,
            rationale=decision.rationale,
            stated_confidence=decision.stated_confidence,
            evidence_citations=list(decision.evidence_citations),
            decision_payload=decision.model_dump(mode="json"),
            digest_presented=digest.model_dump(mode="json"),
            model_id=result.model_id,
            prompt_version=result.prompt_version,
            cost_usd=result.cost_usd,
            rejected_attempts=rejected_attempts or [],
            schema_version=SCHEMA_VERSION,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def get_decisions(self, hunt_id: str) -> List[HuntDecision]:
        stmt = (
            select(HuntDecision)
            .where(HuntDecision.hunt_id == hunt_id)
            .order_by(HuntDecision.iteration)
        )
        return list(self.session.scalars(stmt))

    # ---- dispatches ----------------------------------------------------

    def begin_dispatch(self, request: DispatchRequest, iteration: int) -> HuntDispatch:
        """Record a dispatch as pending, before the worker runs.

        Create-or-increment on ``dispatch_id``: a watchdog retry (#02) reuses
        the id deliberately, so the row counts attempts rather than either
        duplicating or losing the retry history.
        """
        row = self.session.get(HuntDispatch, request.dispatch_id)
        if row is None:
            row = HuntDispatch(
                dispatch_id=request.dispatch_id,
                hunt_id=request.hunt_id,
                iteration=iteration,
                agent_id=request.agent_id,
                status="pending",
                request=request.model_dump(mode="json"),
                attempts=1,
                schema_version=SCHEMA_VERSION,
            )
            self.session.add(row)
        else:
            row.attempts += 1
            row.status = "pending"
            row.failure_reason = None
            row.completed_at = None
        self.session.flush()
        return row

    def get_dispatch(self, dispatch_id: str) -> Optional[HuntDispatch]:
        return self.session.get(HuntDispatch, dispatch_id)

    def get_dispatches(self, hunt_id: str) -> List[HuntDispatch]:
        stmt = (
            select(HuntDispatch)
            .where(HuntDispatch.hunt_id == hunt_id)
            .order_by(HuntDispatch.created_at)
        )
        return list(self.session.scalars(stmt))

    def complete_dispatch(
        self,
        dispatch: HuntDispatch,
        failed: bool = False,
        failure_reason: str = "",
    ) -> None:
        dispatch.status = "failed" if failed else "complete"
        dispatch.failure_reason = failure_reason or None
        dispatch.completed_at = datetime.utcnow()
        self.session.flush()
