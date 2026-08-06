"""Agentic threat-hunting harness — the Hunt Ledger and the hunt controller.

Deterministic Python owns the loop mechanics and all Ledger state; the Hunt
Lead (an orchestrator LLM, wired in #03) owns the judgment inside a single
iteration. The two meet at the ports in :mod:`core.hunting.ports`, which is
what makes the controller testable with no live LLM and no live SIEM.

A Hunt is not a Case subtype: the Ledger owns its own tables and links to Case
only through two nullable references on the hunt record.
"""

from core.hunting.ports import DecisionProvider, WorkerDispatcher
from core.hunting.schema import (
    SCHEMA_VERSION,
    Decision,
    DecisionAction,
    DecisionResult,
    Digest,
    DispatchRequest,
    EvidenceRecord,
    HuntSpec,
)

__all__ = [
    "SCHEMA_VERSION",
    "Decision",
    "DecisionAction",
    "DecisionProvider",
    "DecisionResult",
    "Digest",
    "DispatchRequest",
    "EvidenceRecord",
    "HuntSpec",
    "WorkerDispatcher",
]
