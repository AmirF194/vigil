"""Controller tests driven entirely through the two ports.

No live LLM and no live SIEM: decisions and evidence are scripted, and the
assertions are on Ledger state and hunt outcome rather than on controller
internals. The Ledger itself is real — the ORM models and the repository run
against in-memory SQLite, so these cover the persistence path too.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.hunting.controller import HuntAlreadyTerminal, HuntController, HuntNotFound
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
    Decision,
    DecisionAction,
    DecisionResult,
    EvidenceRecord,
    HuntBudgets,
    HuntOutcome,
    HuntSpec,
    HuntStatus,
    HypothesisStatus,
    Salience,
)
from core.hunting.scripted import ScriptedDecisionProvider, ScriptedWorkerDispatcher
from core.hunting.uow import HuntUnitOfWork

pytestmark = pytest.mark.unit

LEDGER_TABLES = [
    HuntRecord.__table__,
    HuntHypothesis.__table__,
    HuntOpenQuestion.__table__,
    HuntEvidence.__table__,
    HuntEvidenceLink.__table__,
    HuntDecision.__table__,
    HuntDispatch.__table__,
]


@pytest.fixture
def uow_factory():
    engine = create_engine("sqlite://")
    # Only the Ledger tables: the rest of the metadata carries pgvector columns
    # SQLite cannot express, and the hunt tables do not depend on them.
    for table in LEDGER_TABLES:
        table.create(engine, checkfirst=True)
    factory = sessionmaker(bind=engine)

    def make_uow():
        return HuntUnitOfWork(session_factory=factory)

    return make_uow


def make_spec(**overrides) -> HuntSpec:
    defaults = dict(
        name="cloud credential compromise",
        hypotheses=[
            "A valid cloud credential is being used from unusual infrastructure"
        ],
        budgets=HuntBudgets(max_iterations=5, max_cost_usd=1.0),
    )
    defaults.update(overrides)
    return HuntSpec(**defaults)


def create_hunt(uow_factory, spec: HuntSpec = None) -> str:
    with uow_factory() as uow:
        hunt = uow.hunts.create_hunt(spec or make_spec())
        hunt_id = hunt.hunt_id
        uow.commit()
    return hunt_id


def evidence(summary="cloud console login from an unenrolled ASN", **overrides):
    defaults = dict(
        source_system="splunk:aws_cloudtrail",
        summary=summary,
        payload={"src_ip": "203.0.113.9", "event": "ConsoleLogin"},
        salience=Salience.ANOMALOUS,
        why_notable="first sighting of this ASN for the identity",
    )
    defaults.update(overrides)
    return EvidenceRecord(**defaults)


async def test_conclude_drives_the_hunt_terminal(uow_factory):
    hunt_id = create_hunt(uow_factory)
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.CONCLUDE, rationale="nothing further")]
        ),
        uow_factory=uow_factory,
    )

    result = await controller.advance_iteration(hunt_id)

    assert result.action is DecisionAction.CONCLUDE
    assert result.hunt_status is HuntStatus.TERMINAL
    assert result.hunt_outcome is HuntOutcome.COMPLETED

    with uow_factory() as uow:
        hunt = uow.hunts.get_hunt(hunt_id)
        assert hunt.status == HuntStatus.TERMINAL.value
        assert hunt.iteration == 1


async def test_every_iteration_writes_a_decision_snapshot(uow_factory):
    hunt_id = create_hunt(uow_factory)
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [
                Decision(
                    action=DecisionAction.INVESTIGATE,
                    rationale="baseline the identity",
                    stated_confidence=0.4,
                )
            ],
            cost_per_decision=0.021,
        ),
        uow_factory=uow_factory,
    )

    await controller.advance_iteration(hunt_id)

    with uow_factory() as uow:
        decisions = uow.hunts.get_decisions(hunt_id)
        assert len(decisions) == 1
        snapshot = decisions[0]
        assert snapshot.action == DecisionAction.INVESTIGATE.value
        assert snapshot.model_id == "scripted"
        assert snapshot.prompt_version
        assert snapshot.schema_version >= 1
        assert snapshot.cost_usd == pytest.approx(0.021)
        # stated_confidence is recorded for calibration but gates nothing.
        assert snapshot.stated_confidence == pytest.approx(0.4)
        # The digest is stored as presented, so replay shows the real inputs.
        assert snapshot.digest_presented["hunt_id"] == hunt_id
        assert snapshot.digest_presented["iteration"] == 1

        assert uow.hunts.get_hunt(hunt_id).cost_usd == pytest.approx(0.021)


async def test_investigate_appends_worker_evidence(uow_factory):
    hunt_id = create_hunt(uow_factory)
    dispatcher = ScriptedWorkerDispatcher([evidence()])
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [
                Decision(
                    action=DecisionAction.INVESTIGATE, query_intent="cloudtrail sweep"
                )
            ]
        ),
        dispatcher=dispatcher,
        uow_factory=uow_factory,
    )

    result = await controller.advance_iteration(hunt_id)

    assert result.evidence_appended == 1
    assert dispatcher.requests[0].query_intent == "cloudtrail sweep"

    with uow_factory() as uow:
        stored = uow.hunts.get_evidence(hunt_id)
        assert len(stored) == 1
        assert stored[0].source_system == "splunk:aws_cloudtrail"
        assert stored[0].dispatch_id is not None
        assert stored[0].payload["src_ip"] == "203.0.113.9"


async def test_terminating_marks_open_hypotheses_inconclusive_not_disproven(
    uow_factory,
):
    hunt_id = create_hunt(uow_factory)
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.CONCLUDE)]
        ),
        uow_factory=uow_factory,
    )

    await controller.advance_iteration(hunt_id)

    with uow_factory() as uow:
        statuses = [h.status for h in uow.hunts.get_hypotheses(hunt_id)]
        assert statuses == [HypothesisStatus.INCONCLUSIVE.value]
        assert HypothesisStatus.DISPROVEN.value not in statuses


async def test_hunt_resumes_from_the_persisted_ledger(uow_factory):
    """A fresh controller with no memory of prior turns continues the hunt."""
    hunt_id = create_hunt(uow_factory)

    first = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.INVESTIGATE)]
        ),
        dispatcher=ScriptedWorkerDispatcher([evidence()]),
        uow_factory=uow_factory,
    )
    await first.advance_iteration(hunt_id)

    resumed = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.CONCLUDE)]
        ),
        uow_factory=uow_factory,
    )
    result = await resumed.advance_iteration(hunt_id)

    assert result.iteration == 2
    assert result.hunt_status is HuntStatus.TERMINAL

    with uow_factory() as uow:
        iterations = [d.iteration for d in uow.hunts.get_decisions(hunt_id)]
        assert iterations == [1, 2]


async def test_resumed_iteration_sees_prior_evidence_in_its_digest(uow_factory):
    hunt_id = create_hunt(uow_factory)
    await HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.INVESTIGATE)]
        ),
        dispatcher=ScriptedWorkerDispatcher([evidence()]),
        uow_factory=uow_factory,
    ).advance_iteration(hunt_id)

    provider = ScriptedDecisionProvider([Decision(action=DecisionAction.CONCLUDE)])
    await HuntController(
        decision_provider=provider, uow_factory=uow_factory
    ).advance_iteration(hunt_id)

    digest = provider.seen_digests[0]
    assert digest.iteration == 2
    assert [e.summary for e in digest.recent_evidence] == [
        "cloud console login from an unenrolled ASN"
    ]


async def test_iteration_budget_terminates_the_hunt(uow_factory):
    hunt_id = create_hunt(uow_factory, make_spec(budgets=HuntBudgets(max_iterations=2)))
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [
                Decision(action=DecisionAction.INVESTIGATE),
                Decision(action=DecisionAction.INVESTIGATE),
            ]
        ),
        uow_factory=uow_factory,
    )

    await controller.advance_iteration(hunt_id)
    second = await controller.advance_iteration(hunt_id)

    assert second.hunt_outcome is HuntOutcome.BUDGET_TERMINATED
    with uow_factory() as uow:
        assert [h.status for h in uow.hunts.get_hypotheses(hunt_id)] == [
            HypothesisStatus.INCONCLUSIVE.value
        ]


async def test_a_terminal_hunt_refuses_to_advance(uow_factory):
    hunt_id = create_hunt(uow_factory)
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.CONCLUDE)]
        ),
        uow_factory=uow_factory,
    )
    await controller.advance_iteration(hunt_id)

    with pytest.raises(HuntAlreadyTerminal):
        await controller.advance_iteration(hunt_id)


async def test_unknown_hunt_raises(uow_factory):
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider([]), uow_factory=uow_factory
    )
    with pytest.raises(HuntNotFound):
        await controller.advance_iteration("hunt-does-not-exist")


async def test_worker_failure_is_recorded_on_the_dispatch(uow_factory):
    hunt_id = create_hunt(uow_factory)
    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [
                Decision(
                    action=DecisionAction.INVESTIGATE, worker_agent_id="network_analyst"
                )
            ]
        ),
        dispatcher=ScriptedWorkerDispatcher(fail_agent_ids=["network_analyst"]),
        uow_factory=uow_factory,
    )

    result = await controller.advance_iteration(hunt_id)

    assert result.evidence_appended == 0
    with uow_factory() as uow:
        dispatches = uow.hunts.get_dispatches(hunt_id)
        assert len(dispatches) == 1
        # Recorded as failed rather than silently skipped — #04 turns this into
        # a visibility gap.
        assert dispatches[0].status == "failed"
        assert dispatches[0].agent_id == "network_analyst"
        assert uow.hunts.get_evidence(hunt_id) == []


async def test_repeated_dispatch_id_does_not_duplicate_evidence(uow_factory):
    """Idempotency key: a retried dispatch must not inflate corroboration."""
    hunt_id = create_hunt(uow_factory)
    record = evidence()

    with uow_factory() as uow:
        record.dispatch_id = "dsp-fixed"
        uow.hunts.append_evidence(hunt_id, record, iteration=1)
        uow.commit()

    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [Decision(action=DecisionAction.INVESTIGATE)]
        ),
        dispatcher=ScriptedWorkerDispatcher([evidence()]),
        uow_factory=uow_factory,
        # The seam the watchdog uses to re-issue a dispatch under its original
        # id; pinning it here makes the retry path reproducible.
        dispatch_id_factory=lambda: "dsp-fixed",
    )

    result = await controller.advance_iteration(hunt_id)

    assert result.evidence_appended == 0
    with uow_factory() as uow:
        assert len(uow.hunts.get_evidence(hunt_id)) == 1
        # The re-issue is counted rather than duplicated or lost.
        assert uow.hunts.get_dispatch("dsp-fixed").attempts == 1


async def test_dispatch_is_pending_before_the_worker_runs(uow_factory):
    """A crash mid-dispatch must leave a row for the watchdog to reap."""
    hunt_id = create_hunt(uow_factory)
    seen = {}

    class CrashingDispatcher:
        async def dispatch(self, request):
            with uow_factory() as uow:
                row = uow.hunts.get_dispatch(request.dispatch_id)
                seen["status"] = row.status if row else None
                seen["agent_id"] = row.agent_id if row else None
            raise RuntimeError("worker died mid-query")

    controller = HuntController(
        decision_provider=ScriptedDecisionProvider(
            [
                Decision(
                    action=DecisionAction.INVESTIGATE, worker_agent_id="network_analyst"
                )
            ]
        ),
        dispatcher=CrashingDispatcher(),
        uow_factory=uow_factory,
    )

    await controller.advance_iteration(hunt_id)

    assert seen == {"status": "pending", "agent_id": "network_analyst"}
    with uow_factory() as uow:
        dispatches = uow.hunts.get_dispatches(hunt_id)
        assert [d.status for d in dispatches] == ["failed"]
        assert "worker died mid-query" in dispatches[0].failure_reason


async def test_an_abort_in_flight_is_not_relabelled_by_the_returning_iteration(
    uow_factory,
):
    """A terminal outcome is final: aborted must never become completed."""
    hunt_id = create_hunt(uow_factory)

    class AbortingProvider:
        """Stands in for a human aborting while the model call is in flight."""

        async def decide(self, digest):
            with uow_factory() as uow:
                uow.hunts.set_status(
                    uow.hunts.get_hunt(hunt_id),
                    HuntStatus.TERMINAL,
                    outcome=HuntOutcome.ABORTED.value,
                )
                uow.commit()
            return DecisionResult(
                decision=Decision(action=DecisionAction.CONCLUDE), model_id="scripted"
            )

    controller = HuntController(
        decision_provider=AbortingProvider(), uow_factory=uow_factory
    )

    with pytest.raises(HuntAlreadyTerminal):
        await controller.advance_iteration(hunt_id)

    with uow_factory() as uow:
        hunt = uow.hunts.get_hunt(hunt_id)
        assert hunt.outcome == HuntOutcome.ABORTED.value
        assert hunt.iteration == 0
        assert uow.hunts.get_decisions(hunt_id) == []
