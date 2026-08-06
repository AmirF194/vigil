"""Hunt Ledger ORM models — the authoritative record of a hunt.

Self-contained by design: these tables are owned by the hunting domain and a
Hunt is never a Case subtype. The only links to Case are the two nullable
references on ``HuntRecord`` (what triggered the hunt, what it spawned), both
``ON DELETE SET NULL`` so case lifecycle can never delete hunt history.

Typed relational spine plus versioned JSONB for the payloads that will churn
through Phase 1; every JSONB column is paired with a ``schema_version``.

The DDL is mirrored in ``database/init/19_hunt_ledger.sql`` for the
docker-compose and Helm deploy paths — change both together.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base

# JSONB in production; plain JSON elsewhere so the controller's unit tests can
# build the real Ledger on in-memory SQLite instead of mocking the repository.
JsonDoc = JSON().with_variant(JSONB, "postgresql")


class HuntRecord(Base):
    __tablename__ = "hunts"

    hunt_id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    outcome: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    spec: Mapped[dict] = mapped_column(JsonDoc, nullable=False, default=dict)
    budgets: Mapped[dict] = mapped_column(JsonDoc, nullable=False, default=dict)
    cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Written by #02's ARQ iteration step; present from the first migration so
    # adding the lease is a behaviour change, not a schema change.
    lease_owner: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    trigger_case_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("cases.case_id", ondelete="SET NULL"), nullable=True
    )
    spawned_case_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("cases.case_id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    terminated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("ix_hunts_status", "status"),)


class HuntHypothesis(Base):
    __tablename__ = "hunt_hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(String, primary_key=True)
    hunt_id: Mapped[str] = mapped_column(
        String, ForeignKey("hunts.hunt_id", ondelete="CASCADE"), nullable=False
    )
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    # Controller-computed features behind the gating predicates (#07). Never
    # the model's self-reported confidence, which lives on the decision row.
    evidence_strength: Mapped[dict] = mapped_column(
        JsonDoc, nullable=False, default=dict
    )
    resolution_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("ix_hunt_hypotheses_hunt", "hunt_id", "status"),)


class HuntOpenQuestion(Base):
    """A thread worth pulling that is not yet a Hypothesis.

    The spec calls this a "lead"; the Ledger calls it an Open Question so the
    word cannot be confused with the Hunt Lead. #06 adds the priority
    features and turns this into a scored frontier.
    """

    __tablename__ = "hunt_open_questions"

    question_id: Mapped[str] = mapped_column(String, primary_key=True)
    hunt_id: Mapped[str] = mapped_column(
        String, ForeignKey("hunts.hunt_id", ondelete="CASCADE"), nullable=False
    )
    question: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    priority_features: Mapped[dict] = mapped_column(
        JsonDoc, nullable=False, default=dict
    )
    spawning_evidence_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("ix_hunt_open_questions_hunt", "hunt_id", "status"),)


class HuntEvidence(Base):
    """Append-only. Workers append; only the controller writes state elsewhere."""

    __tablename__ = "hunt_evidence"

    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    hunt_id: Mapped[str] = mapped_column(
        String, ForeignKey("hunts.hunt_id", ondelete="CASCADE"), nullable=False
    )
    dispatch_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    source_system: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JsonDoc, nullable=False, default=dict)

    salience: Mapped[str] = mapped_column(String, nullable=False, default="routine")
    why_notable: Mapped[str] = mapped_column(Text, nullable=False, default="")
    provenance: Mapped[str] = mapped_column(String, nullable=False, default="worker")
    # Set when the value could have been written by the adversary. #06 refuses
    # to let an ABANDON rest solely on evidence flagged here.
    attacker_influenceable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    instruction_like: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    captured_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_hunt_evidence_hunt", "hunt_id", "captured_at"),
        Index("ix_hunt_evidence_dispatch", "dispatch_id"),
    )


class HuntEvidenceLink(Base):
    """Which evidence supports or weakens which hypothesis.

    The ``weakens`` half is what makes the contrarian quota (#05) a query
    rather than new data.
    """

    __tablename__ = "hunt_evidence_links"

    link_id: Mapped[str] = mapped_column(String, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("hunt_evidence.evidence_id", ondelete="CASCADE"),
        nullable=False,
    )
    hypothesis_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("hunt_hypotheses.hypothesis_id", ondelete="CASCADE"),
        nullable=False,
    )
    relation: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    __table_args__ = (
        UniqueConstraint(
            "evidence_id", "hypothesis_id", "relation", name="uq_hunt_evidence_link"
        ),
        Index("ix_hunt_evidence_links_hypothesis", "hypothesis_id", "relation"),
    )


class HuntDecision(Base):
    """The audit spine: one row per iteration, written every iteration.

    ``digest_presented`` is stored verbatim so a replay shows what the Hunt
    Lead actually saw rather than what current state would render today.
    """

    __tablename__ = "hunt_decisions"

    decision_id: Mapped[str] = mapped_column(String, primary_key=True)
    hunt_id: Mapped[str] = mapped_column(
        String, ForeignKey("hunts.hunt_id", ondelete="CASCADE"), nullable=False
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False)

    action: Mapped[str] = mapped_column(String, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stated_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    evidence_citations: Mapped[list] = mapped_column(
        JsonDoc, nullable=False, default=list
    )
    decision_payload: Mapped[dict] = mapped_column(
        JsonDoc, nullable=False, default=dict
    )
    digest_presented: Mapped[dict] = mapped_column(
        JsonDoc, nullable=False, default=dict
    )

    model_id: Mapped[str] = mapped_column(String, nullable=False)
    prompt_version: Mapped[str] = mapped_column(String, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Populated when the controller rejected an emission before accepting one
    # (#03), so re-prompt behaviour is visible in the audit trail.
    rejected_attempts: Mapped[list] = mapped_column(
        JsonDoc, nullable=False, default=list
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("hunt_id", "iteration", name="uq_hunt_decision_iteration"),
        Index("ix_hunt_decisions_hunt", "hunt_id", "iteration"),
    )


class HuntDispatch(Base):
    """One unit of worker work. ``dispatch_id`` is the idempotency key."""

    __tablename__ = "hunt_dispatches"

    dispatch_id: Mapped[str] = mapped_column(String, primary_key=True)
    hunt_id: Mapped[str] = mapped_column(
        String, ForeignKey("hunts.hunt_id", ondelete="CASCADE"), nullable=False
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    agent_id: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    request: Mapped[dict] = mapped_column(JsonDoc, nullable=False, default=dict)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("ix_hunt_dispatches_hunt", "hunt_id", "status"),)
