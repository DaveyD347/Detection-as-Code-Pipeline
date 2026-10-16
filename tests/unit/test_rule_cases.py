"""Every rule against its hand-written true/false positive cases."""

from functools import cache

import pytest

from dac.cases import load_cases
from dac.engine import CompiledRule
from dac.rules import load_rules

RULES = {r.stem: r for r in load_rules()}
CASES = load_cases()


@cache
def compiled(stem: str) -> CompiledRule:
    return CompiledRule(RULES[stem].rule)


@pytest.mark.parametrize(
    "case", CASES, ids=[f"{c.rule}::{'TP' if c.should_match else 'TN'}::{c.name}" for c in CASES]
)
def test_case(case):
    assert case.rule in RULES, f"case file for unknown rule {case.rule}"
    assert compiled(case.rule).matches(case.event) is case.should_match


@pytest.mark.parametrize("stem", sorted(RULES))
def test_every_rule_has_both_kinds_of_case(stem):
    kinds = {c.should_match for c in CASES if c.rule == stem}
    assert kinds == {True, False}, f"{stem} needs at least one match and one no_match case"
