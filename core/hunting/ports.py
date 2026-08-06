"""The two injectable seams of the hunt controller.

Everything deterministic lives on the controller side of these Protocols;
everything that needs a live model or a live SIEM lives behind them. Tests
drive the whole loop by supplying scripted implementations, which is why the
controller can be covered end to end with no LLM and no Splunk.

Both are async: the real implementations are an LLM call (#03) and an agent
run (#04), and the ARQ iteration step (#02) is async too. The Ledger
repository is deliberately sync, matching the repo-wide sync SQLAlchemy layer.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.hunting.schema import DecisionResult, Digest, DispatchRequest, DispatchResult


@runtime_checkable
class DecisionProvider(Protocol):
    """The Hunt Lead: one digest in, exactly one typed decision out.

    Implementations must not touch the Ledger. Deciding is all they do; the
    controller applies, validates, and persists.
    """

    async def decide(self, digest: Digest) -> DecisionResult: ...


@runtime_checkable
class WorkerDispatcher(Protocol):
    """The evidence source: a dispatch in, Hunt Evidence out.

    Implementations append nothing themselves — they return records and the
    controller writes them, so workers can never mutate hypothesis, question,
    or budget state.

    Must be idempotent on ``dispatch_id``: #02's watchdog may retry a stale
    dispatch with the same id, and that must not duplicate evidence.
    """

    async def dispatch(self, request: DispatchRequest) -> DispatchResult: ...
