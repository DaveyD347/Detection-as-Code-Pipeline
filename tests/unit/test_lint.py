"""The lint gates catch the mistakes they claim to catch."""

from pathlib import Path

import pytest

from dac import paths
from dac.attack import Catalog
from dac.lint import lint
from dac.rules import load_rule, load_rules

CATALOG = Catalog.load(next(paths.ATTACK_DIR.glob("enterprise-attack-*.json")))

GOOD = """title: Test Rule For Lint
id: 11111111-2222-4333-8444-555555555555
status: experimental
description: A rule written only for the lint tests, long enough to satisfy the description length check here.
references: [https://example.com]
author: tests
date: 2026-10-16
tags: [attack.credential-access, attack.t1003.001]
logsource: {product: windows, category: process_creation}
detection:
  sel:
    CommandLine|contains: lsass
  condition: sel
falsepositives: [none]
level: high
"""

CASES = """rule: proc_creation_lint_rule
match: [{name: m, event: {Channel: Microsoft-Windows-Sysmon/Operational, EventID: 1, CommandLine: lsass}}]
no_match: [{name: n, event: {Channel: Microsoft-Windows-Sysmon/Operational, EventID: 1, CommandLine: x}}]
"""


def run(tmp_path: Path, text: str, folder="credential_access", stem="proc_creation_lint_rule", cases=True):
    rule_dir = tmp_path / "rules" / folder
    rule_dir.mkdir(parents=True)
    (rule_dir / f"{stem}.yml").write_text(text)
    case_dir = tmp_path / "cases"
    case_dir.mkdir()
    if cases:
        (case_dir / f"{stem}.yml").write_text(CASES.replace("proc_creation_lint_rule", stem))
    rf = load_rule(rule_dir / f"{stem}.yml")
    return [(i.check, i.message) for i in lint([rf], CATALOG, [], case_dir)]


def test_clean_rule_passes(tmp_path):
    assert run(tmp_path, GOOD) == []


def test_repository_rules_are_clean():
    from dac.datasets import load_manifest

    errors = [str(i) for i in lint(load_rules(), CATALOG, load_manifest()) if i.level == "error"]
    assert errors == []


def test_revoked_technique_suggests_replacement(tmp_path):
    text = GOOD.replace(
        "attack.credential-access, attack.t1003.001", "attack.defense-impairment, attack.t1562.002"
    )
    issues = run(tmp_path, text, folder="defense_impairment")
    assert any("revoked" in m and "t1685.001" in m for _, m in issues)


def test_unknown_technique_and_tactic(tmp_path):
    issues = run(
        tmp_path,
        GOOD.replace("attack.t1003.001", "attack.t9999").replace("credential-access", "defense-evasion"),
    )
    messages = " ".join(m for _, m in issues)
    assert "T9999 does not exist" in messages
    assert "unknown tactic 'attack.defense-evasion'" in messages


def test_tactic_must_match_technique(tmp_path):
    issues = run(
        tmp_path, GOOD.replace("attack.credential-access", "attack.credential-access, attack.impact")
    )
    assert ("attack", "tactic 'impact' does not belong to any tagged technique") in issues


def test_folder_and_prefix(tmp_path):
    issues = run(tmp_path, GOOD, folder="persistence", stem="lint_rule")
    checks = {c for c, _ in issues}
    assert "layout" in checks
    assert any("should start with 'proc_creation_'" in m for _, m in issues)


def test_missing_cases(tmp_path):
    assert any(c == "tests" for c, _ in run(tmp_path, GOOD, cases=False))


def test_test_status_needs_dataset_evidence(tmp_path):
    issues = run(tmp_path, GOOD.replace("status: experimental", "status: test"))
    assert any(c == "evidence" for c, _ in issues)


@pytest.mark.parametrize("regex", [r"'\\sfoo'", r"'^foo.*'", r"'(?i)foo'"])
def test_non_portable_regex(tmp_path, regex):
    text = GOOD.replace("CommandLine|contains: lsass", f"CommandLine|re: {regex}")
    assert any(c == "portability" for c, _ in run(tmp_path, text))


def test_metadata(tmp_path):
    text = GOOD.replace("falsepositives: [none]\n", "").replace(
        "description: A rule written only for the lint tests, long enough to satisfy the description length check here.",
        "description: Detects bad things.",
    )
    messages = " ".join(m for _, m in run(tmp_path, text))
    assert "falsepositives" in messages and "description too short" in messages
