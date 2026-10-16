"""Per-rule unit cases: hand-written events that must / must not match.

Replay proves a rule fires on real attacks; unit cases pin down its edges:
evasion variants it must still catch, and look-alike benign activity it must
not. Each file in tests/rule_cases/ is named after the rule it tests:

    rule: <rule file stem>
    base: {Channel: ..., EventID: 1}     # merged into every event
    match:    [{name: ..., event: {...}}]
    no_match: [{name: ..., event: {...}}]

A key set to null in an event removes it from the base, so a case can switch
telemetry source (e.g. Sysmon Image -> Security NewProcessName).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from . import paths


@dataclass(frozen=True)
class Case:
    rule: str
    name: str
    event: dict
    should_match: bool
    file: Path


def _merge(base: dict, event: dict) -> dict:
    merged = dict(base)
    for key, value in event.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def load_cases(root: Path | None = None) -> list[Case]:
    cases: list[Case] = []
    for path in sorted((root or paths.RULE_CASES).glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if doc.get("rule") != path.stem:
            raise ValueError(f"{path}: 'rule' must equal the file name ({path.stem})")
        base = doc.get("base") or {}
        for key, expected in (("match", True), ("no_match", False)):
            for item in doc.get(key) or []:
                cases.append(Case(path.stem, item["name"], _merge(base, item["event"]), expected, path))
    return cases
