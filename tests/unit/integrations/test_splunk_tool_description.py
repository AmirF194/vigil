"""What the Splunk MCP tool tells a model about the deployment it is querying.

A description reading only "Execute SPL query" leaves an index and a time range to
be guessed, and a wrong guess comes back empty rather than wrong -- which reads as
"no evidence" and is really "no visibility". One hunt spent three iterations that
way against a 2018 dataset it kept querying with the -24h default.
"""

import asyncio
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load(monkeypatch, rows, service=object()):
    """Fresh module per test: the summary is cached for the process's lifetime."""
    spec = importlib.util.spec_from_file_location(
        "splunk_tool_under_test", ROOT / "core/integrations/splunk/tool.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class _Service:
        def search(self, query, earliest_time="-24h", max_count=1000):
            if rows is None:
                raise RuntimeError("splunk is unreachable")
            return rows

    monkeypatch.setattr(
        module, "get_splunk_service", lambda: (None if service is None else _Service())
    )
    return module


def _describe(module):
    tools = asyncio.run(module.handle_list_tools())
    return {tool.name: tool.description for tool in tools}


_ROWS = [
    {
        "index": "botsv3",
        "sourcetype": "stream:dns",
        "count": "218456",
        "earliest": "1534723200",
        "latest": "1534809600",
    },
    {
        "index": "botsv3",
        "sourcetype": "cisco:asa",
        "count": "80192",
        "earliest": "1534723200",
        "latest": "1534809600",
    },
]


def test_names_every_index_and_sourcetype_it_can_see(monkeypatch):
    described = _describe(_load(monkeypatch, _ROWS))["splunk_execute"]

    assert "index=botsv3 sourcetype=stream:dns" in described
    assert "count=218456" in described
    assert "cisco:asa" in described


# The date span is the part that was actually missing: everything else can be
# guessed from a hostname, and a window cannot.
def test_carries_the_date_span_and_says_why_it_matters(monkeypatch):
    described = _describe(_load(monkeypatch, _ROWS))["splunk_execute"]

    assert "2018-08-20" in described
    assert "-24h" in described
    assert "not an absence of evidence" in described


# nl_search takes no time range at all, so the same map is a warning rather than
# an instruction: it cannot act on it.
def test_warns_that_the_natural_language_tool_cannot_set_a_range(monkeypatch):
    described = _describe(_load(monkeypatch, _ROWS))["splunk_nl_search"]

    assert "Cannot express a time range" in described


@pytest.mark.parametrize("rows,service", [(None, object()), ([], object()), ([], None)])
def test_leaves_the_plain_description_when_it_cannot_look(monkeypatch, rows, service):
    """A server answering no tools is worse than one whose description is thin."""
    described = _describe(_load(monkeypatch, rows, service=service))

    assert described["splunk_execute"] == "Execute SPL query"
    assert len(described) == 5


def test_asks_splunk_once_however_often_the_tools_are_listed(monkeypatch):
    module = _load(monkeypatch, _ROWS)
    calls = {"n": 0}
    real = module.get_splunk_service

    def counted():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(module, "get_splunk_service", counted)
    _describe(module)
    _describe(module)

    assert calls["n"] == 1
