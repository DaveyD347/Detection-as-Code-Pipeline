"""Convert Sigma rules into deployable Splunk, Elastic and Sentinel content.

Output goes to `queries/` and is committed, so every pull request shows the
SPL / Lucene / KQL diff a rule change produces. CI regenerates it and fails if
the committed copy is stale.

Each target is a list of conversion profiles (backend + processing pipeline)
tried in order; the first that converts wins. Rules no profile can express are
reported, and must be acknowledged in `config/conversion.yml` with a reason.
A conversion that starts working again fails the build until the entry is
removed, so the list of gaps can't silently rot.

Converted queries also go through cheap semantic checks. pySigma is good but
not infallible: during development one pipeline turned a `contains` +
`endswith` pair into `endswith "...\\command*"`, where KQL treats the `*` as
a literal character and the query can never match.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline

from .attack import Catalog, technique_ids
from .rules import RuleFile


@dataclass(frozen=True)
class Profile:
    name: str
    make_backend: Callable[[], object]
    applies: Callable[[RuleFile], bool] = lambda rf: True


@dataclass(frozen=True)
class Target:
    name: str
    extension: str
    profiles: tuple[Profile, ...]
    checks: tuple[tuple[re.Pattern, str], ...] = ()


def _is_service(*services: str) -> Callable[[RuleFile], bool]:
    return lambda rf: (rf.rule.logsource.service or "").lower() in services


def _is_category(rf: RuleFile) -> bool:
    return bool(rf.rule.logsource.category)


KQL_LITERAL_WILDCARD = (
    re.compile(r'\b(?:endswith|startswith|contains|has|=~|==)\s+@?"[^"]*(?<!\\)\*[^"]*"'),
    "a '*' inside a KQL string operator is a literal character, not a wildcard",
)
SYSMON_REGISTRY_DATA = (
    re.compile(r'"(?:DWORD|QWORD) \(0x'),
    "Sysmon's 'DWORD (0x...)' registry data format compared against a non-Sysmon schema",
)
VALUE_NAME_IN_KEY = (
    re.compile(r'RegistryKey\s+\S+\s+@?"[^"]*\\\\\(Default\)"'),
    "registry value name compared against RegistryKey (Defender splits key and value name)",
)

TARGETS: dict[str, Target] = {
    "splunk": Target(
        "splunk",
        ".spl",
        (Profile("splunk_windows", lambda: SplunkBackend(splunk_windows_pipeline())),),
    ),
    "elastic": Target(
        "elastic",
        ".lucene",
        (Profile("ecs_windows", lambda: LuceneBackend(ecs_windows())),),
    ),
    "sentinel": Target(
        "sentinel",
        ".kql",
        (
            # Endpoint telemetry: Defender XDR advanced-hunting tables, which
            # Sentinel ingests through the Microsoft Defender XDR connector.
            Profile("microsoft_xdr", lambda: KustoBackend(microsoft_xdr_pipeline()), _is_category),
            # Windows Security channel: SecurityEvent via AMA / Windows Security Events.
            Profile(
                "azure_monitor_securityevent",
                lambda: KustoBackend(azure_monitor_pipeline(query_table="SecurityEvent")),
                _is_service("security"),
            ),
        ),
        (KQL_LITERAL_WILDCARD, SYSMON_REGISTRY_DATA, VALUE_NAME_IN_KEY),
    ),
}


@dataclass
class Conversion:
    rule: str
    target: str
    profile: str | None
    query: str | None
    error: str | None = None


def convert_rule(rf: RuleFile, target: Target) -> Conversion:
    errors = []
    for profile in target.profiles:
        if not profile.applies(rf):
            continue
        try:
            # Pipelines mutate the rule object in place, so every attempt needs
            # a freshly parsed copy.
            collection = SigmaCollection.from_yaml(rf.path.read_text(encoding="utf-8"))
            queries = profile.make_backend().convert(collection)
        except Exception as exc:  # noqa: BLE001 - backends raise many types
            errors.append(f"{profile.name}: {type(exc).__name__}: {str(exc).splitlines()[0]}")
            continue
        query = "\n".join(str(q) for q in queries).strip()
        failed = [msg for pattern, msg in target.checks if pattern.search(query)]
        if failed:
            errors.append(f"{profile.name}: converted, but failed semantic check: {'; '.join(failed)}")
            continue
        if target.name == "splunk":
            query = f"`{splunk_macro(rf)}` {query}"
        return Conversion(rf.stem, target.name, profile.name, query)
    reason = "; ".join(errors) or "no conversion profile applies to this logsource"
    return Conversion(rf.stem, target.name, None, None, reason)


def splunk_macro(rf: RuleFile) -> str:
    """Every SPL query starts with a data-source macro (e.g. `dac_windows_process_creation`).

    The Sigma backends emit field conditions only; which index and sourcetype
    hold Sysmon or 4688 data is site-specific. Macros keep that in one place.
    """
    ls = rf.rule.logsource
    return f"dac_{ls.product or 'any'}_{ls.category or ls.service or 'any'}".lower()


SPLUNK_MACRO_DEFAULTS = {
    "process_creation": "((sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR (source=XmlWinEventLog:Security EventCode=4688))",
    "process_access": "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10",
    "file_event": "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11",
    "registry_add": "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=12",
    "registry_set": "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=13",
    "wmi_event": "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode IN (19,20,21)",
    "security": "source=XmlWinEventLog:Security",
    "system": "source=XmlWinEventLog:System",
}


def splunk_macros(rules: list[RuleFile]) -> str:
    out = ["# Data-source macros used by savedsearches.conf. Adjust to your indexes.", ""]
    for name in sorted({splunk_macro(rf) for rf in rules}):
        key = name.split("_", 2)[-1]
        out += [
            f"[{name}]",
            f"definition = (index=* {SPLUNK_MACRO_DEFAULTS.get(key, '')})".replace(" )", ")"),
            "",
        ]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Deployable bundles
# --------------------------------------------------------------------------- #

SEVERITY_RISK = {"informational": 21, "low": 21, "medium": 47, "high": 73, "critical": 99}
SENTINEL_SEVERITY = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",
}
# Sentinel's tactic enum predates ATT&CK v20's split of Defense Evasion into
# Stealth and Defense Impairment; map both to the closest value it accepts.
SENTINEL_TACTIC = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "ResourceDevelopment",
    "initial-access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "PrivilegeEscalation",
    "stealth": "DefenseEvasion",
    "defense-impairment": "DefenseEvasion",
    "credential-access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral-movement": "LateralMovement",
    "collection": "Collection",
    "command-and-control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _techniques(rf: RuleFile, catalog: Catalog):
    return [t for t in (catalog.resolve(tid) for tid in technique_ids(rf.tags)) if t]


def _one_line(text: str) -> str:
    return " ".join(str(text).split())


def splunk_savedsearch(rf: RuleFile, query: str, catalog: Catalog) -> str:
    raw = rf.raw
    annotations = {"mitre_attack": [t.id for t in _techniques(rf, catalog)]}
    lines = [
        f"[DaC - {rf.rule.title}]",
        f"search = {query}",
        f"description = {_one_line(raw['description'])}",
        "enableSched = 1",
        "cron_schedule = */10 * * * *",
        "dispatch.earliest_time = -15m@m",
        "dispatch.latest_time = -5m@m",
        f"alert.severity = {['informational', 'low', 'medium', 'high', 'critical'].index(raw['level']) + 1}",
        "action.correlationsearch.enabled = 1",
        f"action.correlationsearch.label = {rf.rule.title}",
        f"action.correlationsearch.annotations = {json.dumps(annotations)}",
        f"action.notable.param.rule_description = {_one_line(raw['description'])}",
        "action.notable.param.security_domain = endpoint",
        f"action.notable.param.severity = {raw['level']}",
        f"# sigma id: {rf.id}",
    ]
    return "\n".join(lines) + "\n"


def elastic_rule(rf: RuleFile, query: str, catalog: Catalog) -> dict:
    raw = rf.raw
    tactics = {t.shortname: t for t in catalog.tactics}
    threat = []
    for tech in _techniques(rf, catalog):
        parent = catalog.resolve(tech.parent) if tech.is_subtechnique else tech
        for tac in tech.tactics:
            entry = {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": tactics[tac].id,
                    "name": tactics[tac].name,
                    "reference": f"https://attack.mitre.org/tactics/{tactics[tac].id}/",
                },
                "technique": [{"id": parent.id, "name": parent.name, "reference": parent.url}],
            }
            if tech.is_subtechnique:
                entry["technique"][0]["subtechnique"] = [
                    {"id": tech.id, "name": tech.name, "reference": tech.url}
                ]
            threat.append(entry)
    return {
        "rule_id": rf.id,
        "name": rf.rule.title,
        "description": _one_line(raw["description"]),
        "type": "query",
        "language": "lucene",
        "query": query,
        "index": ["logs-*", "winlogbeat-*"],
        "severity": "critical"
        if raw["level"] == "critical"
        else {"informational": "low"}.get(raw["level"], raw["level"]),
        "risk_score": SEVERITY_RISK[raw["level"]],
        "false_positives": [str(f) for f in raw.get("falsepositives", [])],
        "references": [str(r) for r in raw.get("references", [])],
        "author": [str(raw.get("author", ""))],
        "threat": threat,
        "tags": ["detection-as-code", *(t.id for t in _techniques(rf, catalog))],
        "interval": "5m",
        "from": "now-6m",
        "enabled": False,
        "version": 1,
    }


def sentinel_rule(rf: RuleFile, query: str, catalog: Catalog) -> dict:
    raw = rf.raw
    techs = _techniques(rf, catalog)
    tactics = sorted({SENTINEL_TACTIC[tac] for t in techs for tac in t.tactics})
    return {
        "id": rf.id,
        "name": rf.rule.title,
        "description": _one_line(raw["description"]),
        "severity": SENTINEL_SEVERITY[raw["level"]],
        "kind": "Scheduled",
        "queryFrequency": "PT10M",
        "queryPeriod": "PT15M",
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "tactics": tactics,
        "relevantTechniques": sorted({t.id.split(".")[0] for t in techs}),
        "query": query,
        "version": "1.0.0",
        "status": "Available" if raw.get("status") in ("test", "stable") else "Experimental",
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


@dataclass
class ConvertResult:
    conversions: list[Conversion]
    known_gaps: dict[str, dict[str, str]]
    problems: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems


def load_known_gaps(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {t: dict(v or {}) for t, v in (raw.get("known_gaps") or {}).items()}


def convert_all(
    rules: list[RuleFile], known_gaps: dict[str, dict[str, str]], targets: list[str] | None = None
) -> ConvertResult:
    conversions, problems = [], []
    for name in targets or list(TARGETS):
        target = TARGETS[name]
        gaps = known_gaps.get(name, {})
        for rf in rules:
            c = convert_rule(rf, target)
            conversions.append(c)
            if c.error and rf.stem not in gaps:
                problems.append(f"{name}: {rf.stem} failed to convert: {c.error}")
            if not c.error and rf.stem in gaps:
                problems.append(f"{name}: {rf.stem} converts now; remove it from known_gaps")
        for stem in sorted(set(gaps) - {r.stem for r in rules}):
            problems.append(f"{name}: known_gaps lists unknown rule {stem}")
    return ConvertResult(conversions, known_gaps, problems)


def render(result: ConvertResult, rules: list[RuleFile], catalog: Catalog) -> dict[str, str]:
    """Every output file as {relative path: content}. Deterministic."""
    files: dict[str, str] = {}
    by_stem = {r.stem: r for r in rules}
    saved, ndjson, sentinel = [], [], []
    for c in sorted(result.conversions, key=lambda c: (c.target, c.rule)):
        if not c.query:
            continue
        rf = by_stem[c.rule]
        ext = TARGETS[c.target].extension
        header = ""
        if c.target == "sentinel":
            header = f"// {rf.rule.title}\n// sigma: {rf.rel} | profile: {c.profile}\n"
        if c.target == "splunk":
            header = f"```{rf.rule.title} | sigma: {rf.rel}```\n"
        files[f"{c.target}/{c.rule}{ext}"] = header + c.query + "\n"
        if c.target == "splunk":
            saved.append(splunk_savedsearch(rf, " ".join(c.query.split("\n")), catalog))
        elif c.target == "elastic":
            ndjson.append(json.dumps(elastic_rule(rf, c.query, catalog), sort_keys=True))
        elif c.target == "sentinel":
            sentinel.append(sentinel_rule(rf, c.query, catalog))
    if saved:
        files["splunk/savedsearches.conf"] = "\n".join(saved)
        files["splunk/macros.conf"] = splunk_macros(rules)
    if ndjson:
        files["elastic/detection_rules.ndjson"] = "\n".join(ndjson) + "\n"
    if sentinel:
        files["sentinel/analytics_rules.yaml"] = yaml.dump(
            {"rules": sentinel}, Dumper=_BlockDumper, sort_keys=False, width=1000, allow_unicode=True
        )
    files["README.md"] = matrix_markdown(result, rules)
    return files


class _BlockDumper(yaml.SafeDumper):
    """Write multi-line strings (KQL) as readable literal blocks."""


_BlockDumper.add_representer(
    str,
    lambda dumper, data: dumper.represent_scalar(
        "tag:yaml.org,2002:str", data, style="|" if "\n" in data else None
    ),
)


def matrix_markdown(result: ConvertResult, rules: list[RuleFile]) -> str:
    targets = list(dict.fromkeys(c.target for c in result.conversions))
    cell = {(c.rule, c.target): c for c in result.conversions}
    lines = [
        "# Generated queries",
        "",
        "Generated by `dac convert` from the Sigma rules in `rules/`. Do not edit by hand:",
        "CI regenerates this folder and fails if it differs from what is committed.",
        "",
        "| Rule | " + " | ".join(targets) + " |",
        "|---|" + "---|" * len(targets),
    ]
    for rf in sorted(rules, key=lambda r: r.stem):
        row = []
        for t in targets:
            c = cell.get((rf.stem, t))
            if c is None:
                row.append("")
            elif c.query:
                row.append(f"[✅ {c.profile}]({t}/{rf.stem}{TARGETS[t].extension})")
            else:
                reason = result.known_gaps.get(t, {}).get(rf.stem, "conversion failed")
                row.append(f"⚪ {reason}")
        lines.append(f"| `{rf.stem}` | " + " | ".join(row) + " |")
    total = len(rules)
    lines += ["", "| Target | Rules converted |", "|---|---:|"]
    for t in targets:
        n = sum(1 for c in result.conversions if c.target == t and c.query)
        lines.append(f"| {t} | {n}/{total} |")
    return "\n".join(lines) + "\n"


def write(files: dict[str, str], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for old in out.rglob("*"):
        if old.is_file() and old.relative_to(out).as_posix() not in files:
            old.unlink()
    for rel, content in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def stale(files: dict[str, str], out: Path) -> list[str]:
    """Paths whose committed content differs from a fresh render."""
    diffs = []
    existing = (
        {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()} if out.exists() else set()
    )
    for rel, content in files.items():
        p = out / rel
        if not p.exists() or p.read_text(encoding="utf-8") != content:
            diffs.append(rel)
    diffs += sorted(existing - set(files))
    return diffs
