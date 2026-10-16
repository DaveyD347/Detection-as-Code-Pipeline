"""Replay every rule over every dataset and compare against expectations."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .datasets import Dataset, fetch_all, iter_events
from .engine import CompiledRule, UnsupportedRule
from .rules import RuleFile


@dataclass
class Finding:
    level: str  # "error" | "warning"
    dataset: str
    rule: str
    message: str


@dataclass
class ReplayResult:
    datasets: list[Dataset]
    rules: list[RuleFile]
    hits: dict[str, dict[str, int]]  # dataset id -> rule stem -> count
    samples: dict[tuple[str, str], dict]  # (dataset, rule) -> first matching event
    events: dict[str, int]  # dataset id -> event count
    unsupported: dict[str, str]  # rule stem -> reason
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.level == "error" for f in self.findings)

    def validated_rules(self) -> set[str]:
        """Rules with at least one expected, observed hit on real attack data."""
        out = set()
        for d in self.datasets:
            for stem, minimum in d.expect.items():
                if self.hits.get(d.id, {}).get(stem, 0) >= max(minimum, 1):
                    out.add(stem)
        return out


def run(rules: list[RuleFile], datasets: list[Dataset], cache: Path | None = None) -> ReplayResult:
    compiled: dict[str, CompiledRule] = {}
    unsupported: dict[str, str] = {}
    for rf in rules:
        try:
            compiled[rf.stem] = CompiledRule(rf.rule)
        except UnsupportedRule as exc:
            unsupported[rf.stem] = str(exc)

    files = fetch_all(datasets, cache)
    hits: dict[str, dict[str, int]] = {}
    samples: dict[tuple[str, str], dict] = {}
    events: dict[str, int] = {}

    for ds in datasets:
        counts: dict[str, int] = defaultdict(int)
        n = 0
        for event in iter_events(files[ds.id]):
            n += 1
            for stem, cr in compiled.items():
                if cr.matches(event):
                    counts[stem] += 1
                    samples.setdefault((ds.id, stem), event)
        hits[ds.id] = dict(counts)
        events[ds.id] = n

    result = ReplayResult(datasets, rules, hits, samples, events, unsupported)
    result.findings = evaluate(result)
    return result


def evaluate(result: ReplayResult) -> list[Finding]:
    stems = {r.stem for r in result.rules}
    findings: list[Finding] = []
    for ds in result.datasets:
        observed = result.hits.get(ds.id, {})
        if result.events.get(ds.id, 0) == 0:
            findings.append(Finding("error", ds.id, "-", "dataset contains no parseable events"))
        for stem, minimum in ds.expect.items():
            if stem not in stems:
                findings.append(Finding("error", ds.id, stem, "expected rule does not exist"))
            elif stem in result.unsupported:
                findings.append(Finding("error", ds.id, stem, f"cannot replay: {result.unsupported[stem]}"))
            elif observed.get(stem, 0) < max(minimum, 1):
                findings.append(
                    Finding(
                        "error",
                        ds.id,
                        stem,
                        f"missed: expected >= {max(minimum, 1)} hit(s), got {observed.get(stem, 0)}",
                    )
                )
        for stem, count in observed.items():
            if stem in ds.expect:
                continue
            if stem in ds.known_fp:
                findings.append(
                    Finding("warning", ds.id, stem, f"known false positive x{count}: {ds.known_fp[stem]}")
                )
            else:
                findings.append(
                    Finding(
                        "error",
                        ds.id,
                        stem,
                        f"unexpected hit x{count} (true positive? add to expect; noise? fix the rule)",
                    )
                )
        for stem in ds.known_fp:
            if stem not in observed:
                findings.append(Finding("warning", ds.id, stem, "known_fp entry no longer fires; remove it"))
    return findings


def write_reports(result: ReplayResult, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "datasets": [
            {
                "id": d.id,
                "url": d.url,
                "events": result.events.get(d.id, 0),
                "expect": d.expect,
                "hits": result.hits.get(d.id, {}),
            }
            for d in result.datasets
        ],
        "unsupported": result.unsupported,
        "validated_rules": sorted(result.validated_rules()),
        "findings": [f.__dict__ for f in result.findings],
        "ok": result.ok,
    }
    json_path = out_dir / "replay.json"
    json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    total_events = sum(result.events.values())
    lines = [
        "## Replay against attack datasets",
        "",
        f"{len(result.rules)} rules x {len(result.datasets)} datasets "
        f"({total_events:,} events). "
        f"{len(result.validated_rules())} rules validated on real attack telemetry.",
        "",
        "| Dataset | Events | Expected rules | Result |",
        "|---|---:|---|---|",
    ]
    by_ds = defaultdict(list)
    for f in result.findings:
        by_ds[f.dataset].append(f)
    for d in result.datasets:
        errs = [f for f in by_ds[d.id] if f.level == "error"]
        warns = [f for f in by_ds[d.id] if f.level == "warning"]
        status = "❌ " + "; ".join(f"`{f.rule}` {f.message}" for f in errs) if errs else "✅"
        if warns and not errs:
            status += " ⚠️ " + "; ".join(f"`{f.rule}` {f.message}" for f in warns)
        expected = (
            ", ".join(f"`{s}` ({result.hits.get(d.id, {}).get(s, 0)})" for s in d.expect)
            or "_none (noise baseline)_"
        )
        lines.append(f"| [{d.id}]({d.url}) | {result.events.get(d.id, 0):,} | {expected} | {status} |")
    if result.unsupported:
        lines += ["", "Rules the replay engine cannot evaluate:", ""]
        lines += [f"- `{s}`: {r}" for s, r in sorted(result.unsupported.items())]
    md_path = out_dir / "replay.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path
