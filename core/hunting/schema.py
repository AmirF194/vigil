"""Typed contracts for the hunt loop.

These types are the frozen seam between the deterministic controller and the
two things it does not own: the Hunt Lead (#03) and the workers (#04). They
are transport-neutral Pydantic models, so a scripted stub and a live LLM are
interchangeable to the controller.

``SCHEMA_VERSION`` is stamped on every persisted payload. Readers must
tolerate older versions rather than assume the current one.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

SCHEMA_VERSION = 1

# Bumped whenever the decision *prompt* changes, independently of the schema,
# so a replay can tell "the model saw different instructions" from "the model
# answered a different shape". #03 owns the first real value.
PROMPT_VERSION = "hunt-lead/v0-scripted"


class DecisionAction(str, Enum):
    """The closed Phase-1 decision vocabulary.

    Out of vocabulary by design: PARALLEL_SWEEP, MERGE_HYPOTHESES,
    SPLIT_HYPOTHESIS (Phase 2). The controller rejects anything not listed
    here; the Hunt Lead cannot widen its own action space.
    """

    INVESTIGATE = "INVESTIGATE"
    EXPAND = "EXPAND"
    PIVOT = "PIVOT"
    DEEPEN = "DEEPEN"
    ABANDON = "ABANDON"
    VALIDATE = "VALIDATE"
    CHECKPOINT = "CHECKPOINT"
    CONCLUDE = "CONCLUDE"
    HANDOFF_IR = "HANDOFF_IR"


# Actions whose rationale is only auditable if it points at the evidence it
# rests on. #03 enforces this; declared here so the rule has one home.
ACTIONS_REQUIRING_CITATION = frozenset(
    {DecisionAction.ABANDON, DecisionAction.VALIDATE, DecisionAction.PIVOT}
)


class HuntStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    PARKED = "parked"
    TERMINAL = "terminal"


class HuntOutcome(str, Enum):
    """Precedence when several could apply: aborted > data_starved >
    budget_terminated > completed (#08 owns the predicate)."""

    COMPLETED = "completed"
    BUDGET_TERMINATED = "budget_terminated"
    DATA_STARVED = "data_starved"
    ABORTED = "aborted"


# Higher wins. An outcome already on the record is never downgraded, so a
# late-arriving "completed" cannot relabel a hunt a human aborted.
OUTCOME_PRECEDENCE = {
    HuntOutcome.COMPLETED: 0,
    HuntOutcome.BUDGET_TERMINATED: 1,
    HuntOutcome.DATA_STARVED: 2,
    HuntOutcome.ABORTED: 3,
}


class HypothesisStatus(str, Enum):
    ACTIVE = "active"
    PROVEN = "proven"
    DISPROVEN = "disproven"
    INCONCLUSIVE = "inconclusive"
    PARKED = "parked"
    HANDED_OFF = "handed_off"


TERMINAL_HYPOTHESIS_STATUSES = frozenset(
    {
        HypothesisStatus.PROVEN,
        HypothesisStatus.DISPROVEN,
        HypothesisStatus.INCONCLUSIVE,
        HypothesisStatus.PARKED,
        HypothesisStatus.HANDED_OFF,
    }
)


class Salience(str, Enum):
    ROUTINE = "routine"
    NOTABLE = "notable"
    ANOMALOUS = "anomalous"


class LinkRelation(str, Enum):
    SUPPORTS = "supports"
    WEAKENS = "weakens"


class HuntBudgets(BaseModel):
    max_iterations: int = 20
    max_cost_usd: float = 25.0
    # Hard ceiling on extensions granted at the budget checkpoint (#08), so
    # "extend" can never become an unbounded loop.
    max_total_iterations: int = 60


class HuntSpec(BaseModel):
    """The declarative hunt request — the HUNT.md front matter, parsed.

    Phase 1 supports the hypothesis-driven entry adapter only.
    """

    name: str
    hypotheses: List[str] = Field(default_factory=list)
    scope: Dict[str, Any] = Field(default_factory=dict)
    attack_techniques: List[str] = Field(default_factory=list)
    data_domains: List[str] = Field(default_factory=list)
    budgets: HuntBudgets = Field(default_factory=HuntBudgets)
    # #09 makes these real; until then the controller treats every class as
    # auto-approved except the start-of-hunt approval the CLI performs.
    checkpoint_policy: Dict[str, str] = Field(default_factory=dict)
    worker_hints: Dict[str, Any] = Field(default_factory=dict)
    narrative: str = ""
    schema_version: int = SCHEMA_VERSION


class EvidenceRecord(BaseModel):
    """One Hunt Evidence record as a worker returns it.

    Hostile input by assumption: ``provenance`` records where the content came
    from and ``attacker_influenceable`` marks fields an adversary could have
    written, which #06 consults before allowing an ABANDON to rest on it.
    """

    evidence_id: Optional[str] = None
    dispatch_id: Optional[str] = None
    source_system: str
    summary: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    salience: Salience = Salience.ROUTINE
    why_notable: str = ""
    provenance: str = "worker"
    attacker_influenceable: bool = False
    instruction_like: bool = False
    captured_at: Optional[datetime] = None
    schema_version: int = SCHEMA_VERSION


class HypothesisView(BaseModel):
    hypothesis_id: str
    statement: str
    status: HypothesisStatus


class EvidenceView(BaseModel):
    """Evidence as the Hunt Lead sees it — summary only.

    The raw payload stays retrievable by id through EXPAND (#05) so digest
    compression can never be the only copy of a detail.
    """

    evidence_id: str
    source_system: str
    summary: str
    salience: Salience
    why_notable: str = ""
    provenance: str = "worker"
    instruction_like: bool = False


class Digest(BaseModel):
    """The lossy-by-design view of the Ledger handed to the Hunt Lead.

    Persisted verbatim on the decision row: replay must reconstruct exactly
    what the model saw, not re-derive it from current state.
    """

    hunt_id: str
    hunt_name: str
    iteration: int
    hypotheses: List[HypothesisView] = Field(default_factory=list)
    recent_evidence: List[EvidenceView] = Field(default_factory=list)
    open_questions: List[str] = Field(default_factory=list)
    budget_remaining: Dict[str, float] = Field(default_factory=dict)
    notes: List[str] = Field(default_factory=list)
    schema_version: int = SCHEMA_VERSION


class Decision(BaseModel):
    """Exactly one typed action, as emitted by the Hunt Lead."""

    action: DecisionAction
    rationale: str = ""
    # Recorded for offline calibration only. Nothing gates on it — gating uses
    # the controller-computed evidence_strength (#07).
    stated_confidence: Optional[float] = None
    evidence_citations: List[str] = Field(default_factory=list)
    target_hypothesis_id: Optional[str] = None
    target_question: Optional[str] = None
    worker_agent_id: Optional[str] = None
    query_intent: str = ""
    schema_version: int = SCHEMA_VERSION


class DecisionResult(BaseModel):
    """A decision plus the provenance the audit spine requires.

    The provider owns these values because only it knows which model answered
    and what it cost; the controller just persists them.
    """

    decision: Decision
    model_id: str
    prompt_version: str = PROMPT_VERSION
    cost_usd: float = 0.0


class DispatchRequest(BaseModel):
    dispatch_id: str
    hunt_id: str
    agent_id: str
    query_intent: str
    target_hypothesis_id: Optional[str] = None
    scope: Dict[str, Any] = Field(default_factory=dict)


class DispatchResult(BaseModel):
    dispatch_id: str
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    failed: bool = False
    failure_reason: str = ""


class IterationResult(BaseModel):
    """What one turn of the loop did — the CLI and #02's worker step read this."""

    hunt_id: str
    iteration: int
    action: DecisionAction
    decision_id: str
    cost_usd: float
    evidence_appended: int = 0
    hunt_status: HuntStatus
    hunt_outcome: Optional[HuntOutcome] = None
    note: str = ""
