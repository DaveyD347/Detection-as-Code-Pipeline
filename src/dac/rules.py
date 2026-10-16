"""Load the rule corpus from disk."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

import yaml
from sigma.rule import SigmaRule

from . import paths


@dataclass
class RuleFile:
    path: Path
    raw: dict
    rule: SigmaRule

    @property
    def id(self) -> str:
        return str(self.rule.id)

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def rel(self) -> str:
        try:
            return self.path.relative_to(paths.ROOT).as_posix()
        except ValueError:
            return self.path.as_posix()

    @cached_property
    def tags(self) -> list[str]:
        return [str(t) for t in (self.raw.get("tags") or [])]


def load_rule(path: Path) -> RuleFile:
    text = path.read_text(encoding="utf-8")
    return RuleFile(path=path, raw=yaml.safe_load(text), rule=SigmaRule.from_yaml(text))


def rule_paths(root: Path | None = None) -> list[Path]:
    return sorted((root or paths.RULES).rglob("*.yml"))


def load_rules(root: Path | None = None) -> list[RuleFile]:
    return [load_rule(p) for p in rule_paths(root)]
