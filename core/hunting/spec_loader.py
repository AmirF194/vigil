"""Parses the declarative hunt spec (HUNT.md) into a :class:`HuntSpec`.

Format is YAML front matter followed by free-form markdown; the prose becomes
``narrative`` and is available to the Hunt Lead as scenario context. Phase 1
supports the hypothesis-driven entry adapter only — a spec with no hypotheses
is rejected here rather than starting a hunt with nothing to test.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml
from pydantic import ValidationError

from core.hunting.schema import HuntBudgets, HuntSpec


class HuntSpecError(ValueError):
    pass


# The spec is the document that authorizes an autonomous hunt, so an unknown
# key is a typo the author needs told about, not a field to drop silently: a
# misspelled ``budgets`` would otherwise hand the hunt the default budget.
# Validation is deliberately here and not on the models themselves — those are
# also the read path for persisted rows, which must tolerate older shapes.
KNOWN_SPEC_KEYS = frozenset(
    {
        "name",
        "hypotheses",
        "scope",
        "attack_techniques",
        "data_domains",
        "budgets",
        "checkpoint_policy",
        "worker_hints",
    }
)


def split_front_matter(text: str) -> Tuple[Dict[str, Any], str]:
    if not text.lstrip().startswith("---"):
        raise HuntSpecError("hunt spec must begin with a YAML front-matter block")

    stripped = text.lstrip()
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        raise HuntSpecError("unterminated YAML front matter (expected a closing ---)")

    front_matter = yaml.safe_load(parts[1]) or {}
    if not isinstance(front_matter, dict):
        raise HuntSpecError("front matter must be a mapping")
    return front_matter, parts[2].strip()


def parse_hunt_spec(text: str) -> HuntSpec:
    front_matter, narrative = split_front_matter(text)

    unknown = sorted(set(front_matter) - KNOWN_SPEC_KEYS)
    if unknown:
        raise HuntSpecError(
            f"unknown front-matter key(s): {', '.join(unknown)}; "
            f"expected any of {', '.join(sorted(KNOWN_SPEC_KEYS))}"
        )

    hypotheses = front_matter.get("hypotheses") or []
    if isinstance(hypotheses, str):
        hypotheses = [hypotheses]
    if not hypotheses:
        raise HuntSpecError(
            "spec declares no hypotheses; Phase 1 supports hypothesis-driven hunts only"
        )

    budgets = _parse_budgets(front_matter.get("budgets") or {})

    try:
        return HuntSpec(
            name=front_matter.get("name") or "unnamed hunt",
            hypotheses=[str(h) for h in hypotheses],
            scope=front_matter.get("scope") or {},
            attack_techniques=front_matter.get("attack_techniques") or [],
            data_domains=front_matter.get("data_domains") or [],
            budgets=budgets,
            checkpoint_policy=front_matter.get("checkpoint_policy") or {},
            worker_hints=front_matter.get("worker_hints") or {},
            narrative=narrative,
        )
    except ValidationError as exc:
        raise HuntSpecError(f"invalid hunt spec: {exc}") from exc


def _parse_budgets(raw: Any) -> HuntBudgets:
    if not isinstance(raw, dict):
        raise HuntSpecError(f"budgets must be a mapping, got {type(raw).__name__}")

    unknown = sorted(set(raw) - set(HuntBudgets.model_fields))
    if unknown:
        raise HuntSpecError(
            f"unknown budget key(s): {', '.join(unknown)}; "
            f"expected any of {', '.join(sorted(HuntBudgets.model_fields))}"
        )

    try:
        return HuntBudgets(**raw)
    except ValidationError as exc:
        raise HuntSpecError(f"invalid budgets block: {exc}") from exc


def load_hunt_spec(path: Path) -> HuntSpec:
    if not path.exists():
        raise HuntSpecError(f"no such hunt spec: {path}")
    return parse_hunt_spec(path.read_text())


def parse_entity(raw: str) -> Dict[str, str]:
    """A hunt's seed entity, as ``type:value`` or a bare value.

    Typed rather than assumed-an-IP: the same seed slot has to carry hosts,
    identities, and hashes as soon as the pivot lands (#06).
    """
    try:
        ipaddress.ip_address(raw)
        return {"type": "ip", "value": raw}
    except ValueError:
        pass

    kind, separator, value = raw.partition(":")
    if not separator:
        return {"type": "identifier", "value": raw}
    return {"type": kind, "value": value}


def build_hunt_spec(
    spec_path: Optional[Path] = None,
    prompt: Optional[str] = None,
    entity: Optional[str] = None,
) -> HuntSpec:
    """The one place the three entry forms converge on a :class:`HuntSpec`.

    A spec file is the base and the other two layer on top of it, so
    ``--spec X --prompt Y`` reads as "run X, and also chase Y" rather than
    one silently winning over the other. Phase 1 stays hypothesis-driven:
    a prompt becomes a hypothesis statement verbatim, because generating
    hypotheses from free text needs the Hunt Lead (#03).
    """
    spec = load_hunt_spec(spec_path) if spec_path is not None else HuntSpec(name="")

    hypotheses = list(spec.hypotheses)
    if prompt:
        hypotheses.append(prompt)
    if not hypotheses:
        raise HuntSpecError(
            "nothing to test: give --prompt, or a --spec that declares hypotheses"
        )

    scope = dict(spec.scope)
    if entity is not None:
        scope["entity"] = parse_entity(entity)

    name = spec.name
    if not name:
        name = prompt if prompt else f"hunt on {scope['entity']['value']}"
        if len(name) > 60:
            name = name[:57] + "..."

    return spec.model_copy(
        update={"name": name, "hypotheses": hypotheses, "scope": scope}
    )
