"""A small, strict Sigma evaluator for replaying rules against raw events.

Why not just ship rules to a SIEM and look? Because a detection pipeline needs
a fast, deterministic, offline answer to "does this rule fire on this event?"
on every pull request. pySigma already parses a rule into a condition tree with
all modifiers applied (`|contains`, `|windash`, `|all`, `|re`, `|cidr`, ...);
this module compiles that tree into plain Python predicates.

Semantics follow the Sigma specification and pySigma's backends:
  * string matching is case-insensitive unless the value is `|cased`
  * `*` and `?` are wildcards; everything else is literal
  * `|re` is an unanchored search, honouring the `i`, `m` and `s` sub-modifiers
  * keywords (values without a field) are substring searches over every value
  * a missing field never matches, except for `null` and `|exists: false`

Anything the engine cannot evaluate faithfully (placeholders, query
expressions, correlation rules) raises `UnsupportedRule` instead of guessing.
"""

from __future__ import annotations

import ipaddress
import operator
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

Event = Mapping[str, Any]
Predicate = Callable[[Event, Mapping[str, str]], bool]
_MISSING = object()


class UnsupportedRule(Exception):
    """The rule uses a construct the replay engine refuses to approximate."""


# --------------------------------------------------------------------------- #
# Logsources
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Source:
    match: tuple[tuple[str, Any], ...]
    fields: Mapping[str, str]

    def accepts(self, event: Event) -> bool:
        for key, expected in self.match:
            actual = event.get(key, _MISSING)
            if actual is _MISSING:
                return False
            if isinstance(expected, str):
                if str(actual).lower() != expected.lower():
                    return False
            elif str(actual) != str(expected):
                return False
        return True


@cache
def _logsource_map() -> dict:
    text = resources.files("dac").joinpath("data/logsources.yml").read_text("utf-8")
    return yaml.safe_load(text)


def sources_for(rule: SigmaRule) -> list[Source]:
    ls = rule.logsource
    product = (ls.product or "").lower()
    table = _logsource_map().get(product)
    if table is None:
        raise UnsupportedRule(f"no replay mapping for product {ls.product!r}")
    if ls.category:
        entries = table.get("categories", {}).get(ls.category.lower())
        kind, name = "category", ls.category
    elif ls.service:
        entries = table.get("services", {}).get(ls.service.lower())
        kind, name = "service", ls.service
    else:
        raise UnsupportedRule("logsource needs a category or service for replay")
    if not entries:
        raise UnsupportedRule(f"no replay mapping for {product} {kind} {name!r}")
    return [Source(match=tuple(e["match"].items()), fields=e.get("fields", {})) for e in entries]


# --------------------------------------------------------------------------- #
# Value matchers
# --------------------------------------------------------------------------- #


def _plain(value: SigmaString) -> str:
    """The literal text of a wildcard-free SigmaString (to_plain() re-escapes)."""
    return "".join(p for p in value.iter_parts() if isinstance(p, str))


def _check_placeholders(value: SigmaString) -> None:
    if value.contains_placeholder():
        raise UnsupportedRule(f"unexpanded placeholder in {value!r}")


def _sigma_string_regex(value: SigmaString, cased: bool) -> re.Pattern:
    parts = []
    for part in value.iter_parts():
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:  # Placeholder
            raise UnsupportedRule(f"unexpanded placeholder in {value!r}")
    flags = re.DOTALL | (0 if cased else re.IGNORECASE)
    return re.compile("".join(parts), flags)


def _as_values(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [v for v in raw if v is not None]
    return [raw]


def _to_number(raw: Any) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return raw
    try:
        return float(str(raw).strip())
    except ValueError:
        return None


_COMPARE = {
    CompareOperators.LT: operator.lt,
    CompareOperators.LTE: operator.le,
    CompareOperators.GT: operator.gt,
    CompareOperators.GTE: operator.ge,
}


def compile_value(value: Any) -> Callable[[list[Any]], bool]:
    """Compile a Sigma value into a predicate over a field's (list of) values."""
    if isinstance(value, SigmaExpansion):
        options = [compile_value(v) for v in value.values]
        return lambda vals: any(o(vals) for o in options)

    if isinstance(value, SigmaString):  # includes SigmaCasedString
        _check_placeholders(value)
        cased = isinstance(value, SigmaCasedString)
        if not value.contains_special():
            plain = _plain(value)
            if cased:
                return lambda vals: any(str(v) == plain for v in vals)
            folded = plain.casefold()
            return lambda vals: any(str(v).casefold() == folded for v in vals)
        pattern = _sigma_string_regex(value, cased)
        return lambda vals: any(pattern.fullmatch(str(v)) for v in vals)

    if isinstance(value, SigmaRegularExpression):
        raw = getattr(value.regexp, "original", None) or str(value.regexp)
        flags = 0
        if SigmaRegularExpressionFlag.IGNORECASE in value.flags:
            flags |= re.IGNORECASE
        if SigmaRegularExpressionFlag.MULTILINE in value.flags:
            flags |= re.MULTILINE
        if SigmaRegularExpressionFlag.DOTALL in value.flags:
            flags |= re.DOTALL
        pattern = re.compile(raw, flags)
        return lambda vals: any(pattern.search(str(v)) for v in vals)

    if isinstance(value, SigmaBool):
        want = value.boolean

        def is_bool(vals: list[Any]) -> bool:
            for v in vals:
                if isinstance(v, bool):
                    if v is want:
                        return True
                elif str(v).strip().lower() == str(want).lower():
                    return True
            return False

        return is_bool

    if isinstance(value, SigmaNumber):
        want = value.number
        return lambda vals: any(_to_number(v) == want for v in vals)

    if isinstance(value, SigmaCompareExpression):
        op, bound = _COMPARE[value.op], value.number.number

        def compare(vals: list[Any]) -> bool:
            for v in vals:
                n = _to_number(v)
                if n is not None and op(n, bound):
                    return True
            return False

        return compare

    if isinstance(value, SigmaCIDRExpression):
        network = value.network

        def in_cidr(vals: list[Any]) -> bool:
            for v in vals:
                try:
                    if ipaddress.ip_address(str(v).strip()) in network:
                        return True
                except ValueError:
                    continue
            return False

        return in_cidr

    raise UnsupportedRule(f"value type {type(value).__name__} is not supported by replay")


# --------------------------------------------------------------------------- #
# Condition tree
# --------------------------------------------------------------------------- #


def _lookup(event: Event, field: str, fieldmap: Mapping[str, str]) -> Any:
    return event.get(fieldmap.get(field, field), _MISSING)


def _compile_field(node: ConditionFieldEqualsValueExpression) -> Predicate:
    field, value = node.field, node.value

    if isinstance(value, SigmaNull):

        def is_null(event: Event, fm: Mapping[str, str]) -> bool:
            raw = _lookup(event, field, fm)
            return raw is _MISSING or raw is None or raw == ""

        return is_null

    if isinstance(value, SigmaExists):
        want = value.exists

        def exists(event: Event, fm: Mapping[str, str]) -> bool:
            raw = _lookup(event, field, fm)
            return (raw is not _MISSING and raw is not None) == want

        return exists

    if isinstance(value, SigmaFieldReference):
        other = value.field
        if value.starts_with or value.ends_with:
            raise UnsupportedRule("fieldref with startswith/endswith is not supported")

        def same(event: Event, fm: Mapping[str, str]) -> bool:
            a, b = _lookup(event, field, fm), _lookup(event, other, fm)
            if a is _MISSING or b is _MISSING:
                return False
            return str(a).casefold() == str(b).casefold()

        return same

    matcher = compile_value(value)

    def field_match(event: Event, fm: Mapping[str, str]) -> bool:
        raw = _lookup(event, field, fm)
        if raw is _MISSING:
            return False
        return matcher(_as_values(raw))

    return field_match


def _compile_keyword(node: ConditionValueExpression) -> Predicate:
    value = node.value
    if isinstance(value, SigmaString) and not value.contains_special():
        _check_placeholders(value)
        needle = _plain(value).casefold()

        def contains(event: Event, fm: Mapping[str, str]) -> bool:
            return any(needle in str(v).casefold() for raw in event.values() for v in _as_values(raw))

        return contains

    matcher = compile_value(value)
    return lambda event, fm: any(matcher(_as_values(raw)) for raw in event.values())


def compile_condition(node: Any) -> Predicate:
    if isinstance(node, ConditionAND):
        children = [compile_condition(a) for a in node.args]
        return lambda e, fm: all(c(e, fm) for c in children)
    if isinstance(node, ConditionOR):
        children = [compile_condition(a) for a in node.args]
        return lambda e, fm: any(c(e, fm) for c in children)
    if isinstance(node, ConditionNOT):
        (child,) = [compile_condition(a) for a in node.args]
        return lambda e, fm: not child(e, fm)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_field(node)
    if isinstance(node, ConditionValueExpression):
        return _compile_keyword(node)
    raise UnsupportedRule(f"condition node {type(node).__name__} is not supported")


# --------------------------------------------------------------------------- #
# Compiled rule
# --------------------------------------------------------------------------- #


class CompiledRule:
    def __init__(self, rule: SigmaRule):
        if not hasattr(rule, "detection") or rule.detection is None:
            raise UnsupportedRule("only detection rules can be replayed")
        self.rule = rule
        self.id = str(rule.id)
        self.title = rule.title
        self.sources = sources_for(rule)
        conditions = [compile_condition(c.parsed) for c in rule.detection.parsed_condition]
        self._predicate: Predicate = (
            conditions[0] if len(conditions) == 1 else (lambda e, fm: any(c(e, fm) for c in conditions))
        )

    def matches(self, event: Event) -> bool:
        for source in self.sources:
            if source.accepts(event) and self._predicate(event, source.fields):
                return True
        return False

    def filter(self, events: Iterable[Event]) -> Iterable[Event]:
        return (e for e in events if self.matches(e))


def compile_rule(rule: SigmaRule | str) -> CompiledRule:
    if isinstance(rule, str):
        rule = SigmaRule.from_yaml(rule)
    return CompiledRule(rule)
