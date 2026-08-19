# The console's Threat Hunt card now drives the hypothesis loop, which reads a
# different playbook than the compose one: beliefs to test rather than steps.

from __future__ import annotations

import re

import pytest
import yaml

from core.workflows.playbook_resolver import (
    HUNT_CAPABILITIES,
    UnknownPlaybook,
    resolve,
    resolve_hunt,
)

pytestmark = pytest.mark.unit


@pytest.fixture()
def resolved():
    playbook, config = resolve_hunt("threat-hunt")
    return yaml.safe_load(playbook), yaml.safe_load(config)


class TestThePlaybookLayer:
    # The premise is something a person wrote in the definition, not something a
    # model inferred from a prompt -- which is what the null hypothesis guards.
    def test_carries_the_hypotheses_the_definition_states(self, resolved):
        playbook, _ = resolved
        stated = playbook["hypotheses"]
        assert all(isinstance(one, str) and one.strip() for one in stated)

    # Shipping none is the point: a default belief is a claim about somebody else's
    # estate, and the two that used to sit here described one intrusion pattern.
    def test_ships_no_belief_of_its_own(self, resolved):
        playbook, _ = resolved
        assert playbook["hypotheses"] == []

    # The vocabulary a citation is gated against, so it has to span what a hunt
    # over the declared domains could find rather than what one scenario expects.
    def test_declares_a_technique_vocabulary_wider_than_one_scenario(self, resolved):
        playbook, _ = resolved
        techniques = playbook["attack_techniques"]
        assert len(techniques) > 10
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", one) for one in techniques)

    def test_carries_the_sections_the_hunt_owns(self, resolved):
        playbook, _ = resolved
        for section in ("hypotheses", "attack_techniques", "data_domains"):
            assert section in playbook, f"the arch owns {section} and reads nothing"

    # phases belong to the other loop. A hunt decides what to do next from what
    # the evidence did to each belief, so a step order would say nothing.
    def test_states_no_phases(self, resolved):
        playbook, _ = resolved
        assert "phases" not in playbook


class TestTheConfigLayer:
    def test_binds_the_capabilities_the_arch_asks_for(self, resolved):
        _, config = resolved
        tools = config["tools"]
        provided = {one.get("provides") for one in tools if one.get("provides")}
        # Only what this deployment carries: one it has no tool for is dropped,
        # which is the point of binding rather than naming.
        assert provided
        assert provided <= set(HUNT_CAPABILITIES)

    # Local, because the answer is the run's own ledger. Declared remote it posts
    # to a backend that has never seen it and comes back "no such tool".
    def test_declares_expand_as_local(self, resolved):
        _, config = resolved
        expand = next(tool for tool in config["tools"] if tool["id"] == "expand")
        assert expand["kind"] == "local"

    def test_puts_the_null_hypothesis_on_the_board(self, resolved):
        _, config = resolved
        assert config["hypothesis_loop"] is True


class TestCapabilityBinding:
    # The registry flattens to {server}_{tool} and these servers prefix their own
    # names, so the reachable name doubles the prefix. Binding the flat guess is
    # what left every hunt without telemetry.
    def test_binds_a_server_tool_under_its_flattened_name(self):
        from core.workflows.playbook_resolver import _bound_capabilities

        catalogue = {
            "elastic_elastic_search_logs": {
                "description": "search logs",
                "input_schema": {"type": "object"},
            }
        }
        bound = _bound_capabilities(["telemetry_search"], catalogue)

        assert [tool["id"] for tool in bound] == ["elastic_elastic_search_logs"]
        assert bound[0]["provides"] == "telemetry_search"

    def test_prefers_the_first_candidate_the_deployment_carries(self):
        from core.workflows.playbook_resolver import _bound_capabilities

        catalogue = {
            "elastic_elastic_search_logs": {},
            "splunk-selfhosted_splunk_nl_search": {},
        }
        bound = _bound_capabilities(["telemetry_search"], catalogue)

        # splunk-selfhosted is declared first, so it wins over elastic.
        assert bound[0]["id"] == "splunk-selfhosted_splunk_nl_search"

    # Dropped rather than fatal: the hunt journals the drop as a visibility gap,
    # which is a better answer than refusing to run at all.
    def test_drops_a_capability_nothing_provides(self):
        from core.workflows.playbook_resolver import _bound_capabilities

        assert _bound_capabilities(["telemetry_search"], {}) == []

    def test_a_backend_tool_binds_under_its_bare_name(self):
        from core.workflows.playbook_resolver import _bound_capabilities

        bound = _bound_capabilities(["findings_search"], {"search_findings": {}})
        assert bound[0]["id"] == "search_findings"


class TestRefusals:
    # A hunt has no phases, so the compose guard would refuse every one of them
    # before the resolver was ever reached.
    def test_a_hunt_is_refused_for_nothing_to_test_not_for_no_phases(self):
        from core.workflows.workflows_service import (WorkflowDefinition,
                                                      _nothing_to_run)

        def _hunt(**extra):
            return WorkflowDefinition(
                workflow_id="h",
                metadata={"run_kind": "hunt", **extra},
                body="",
                file_path="",
            )

        assert _nothing_to_run(_hunt(hypotheses=["something to test"])) == ""
        assert _nothing_to_run(_hunt()) == "hypotheses"
        # The caller's belief counts: the shipped definition states none.
        assert _nothing_to_run(_hunt(), {"hypothesis": "a host beacons"}) == ""
        assert _nothing_to_run(_hunt(), {"hypothesis": "   \n  "}) == "hypotheses"
        assert _nothing_to_run(_hunt(), {"context": "no belief here"}) == "hypotheses"

    # The refusal moved to the run, where a person sees it. A definition declaring
    # none resolves fine -- that is the shipped case -- and execute_workflow is what
    # stops a run that has no belief from either source.
    def test_resolves_a_definition_that_ships_no_belief(self):
        class _Empty:
            metadata: dict = {}
            name = "x"
            description = ""
            use_case = ""
            trigger_examples: list = []
            body = ""

        class _Workflows:
            def get_workflow(self, _id):
                return _Empty()

        playbook, _ = resolve_hunt("threat-hunt", workflows=_Workflows())
        assert yaml.safe_load(playbook)["hypotheses"] == []

    def test_refuses_a_workflow_that_does_not_exist(self):
        with pytest.raises(UnknownPlaybook):
            resolve_hunt("no-such-workflow")


# The other four definitions are untouched: they still resolve to phases.
def test_a_compose_definition_still_resolves_to_phases():
    playbook, _ = resolve("incident-response")
    assert yaml.safe_load(playbook)["phases"]


# One number read as both a turn count and a call count ended a hunt three turns
# into a budget that said twenty-four, so the two ship as separate ceilings.
class TestTheTurnBudget:
    def _config(self):
        import yaml

        from core.workflows.playbook_resolver import resolve_hunt

        _, config = resolve_hunt("threat-hunt")
        return yaml.safe_load(config)

    def test_states_a_turn_count_apart_from_the_call_count(self):
        config = self._config()
        assert config["thresholds"]["max_iterations"] == 8
        assert config["budgets"]["max_calls"] > config["thresholds"]["max_iterations"]

    def test_leaves_the_calls_a_backstop_rather_than_the_binding_limit(self):
        from core.workflows.playbook_resolver import CALLS_PER_ITERATION

        config = self._config()
        assert (
            config["budgets"]["max_calls"]
            == config["thresholds"]["max_iterations"] * CALLS_PER_ITERATION
        )


# The console asks this before a run is started, so an operator learns the hunt
# will run without a SIEM while it still costs nothing -- the same fact the run
# journals as a deployment gap, moved to before the spend rather than after.
class TestTheCapabilityReport:
    def test_names_every_capability_the_arch_asks_for(self):
        from core.workflows.playbook_resolver import HUNT_CAPABILITIES, capability_report

        report = capability_report(None)
        assert sorted(report["bound"] + report["unbound"]) == sorted(HUNT_CAPABILITIES)

    def test_calls_telemetry_search_unbound_with_no_siem_connected(self):
        from core.workflows.playbook_resolver import capability_report

        assert "telemetry_search" in capability_report(None)["unbound"]

    def test_binds_what_the_backend_answers_for_itself(self):
        from core.workflows.playbook_resolver import capability_report

        # search_findings and the rest are this process's own tools, so they bind
        # in every deployment; a report that called them missing would be wrong.
        assert "findings_search" in capability_report(None)["bound"]

    def test_binds_telemetry_search_when_a_server_reports_the_tool(self):
        from core.workflows.playbook_resolver import capability_report

        class _Registry:
            def get_all_tools(self):
                return [
                    {
                        "name": "splunk-selfhosted_splunk_execute",
                        "description": "Execute SPL",
                        "input_schema": {},
                    }
                ]

        report = capability_report(_Registry())
        assert "telemetry_search" in report["bound"]
        assert "telemetry_search" not in report["unbound"]
