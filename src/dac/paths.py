"""Repository layout. Every command resolves paths from the repo root."""

from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    env = os.environ.get("DAC_ROOT")
    if env:
        return Path(env).resolve()
    here = Path.cwd().resolve()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "rules").is_dir():
            return candidate
    return here


ROOT = repo_root()
RULES = ROOT / "rules"
RULE_CASES = ROOT / "tests" / "rule_cases"
DATASETS = ROOT / "datasets" / "manifest.yml"
ATTACK_DIR = ROOT / "attack"
BUILD = ROOT / "build"
CACHE = Path(os.environ.get("DAC_CACHE", ROOT / ".cache" / "datasets"))
