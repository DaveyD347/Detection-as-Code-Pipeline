"""Quality gates every rule must pass before it can merge.

pySigma's structural validators catch malformed rules. These checks encode
the pipeline's own contract on top of that:

  * metadata a SOC analyst needs at 3 a.m. (description, false positives, refs)
  * ATT&CK tags that exist in the pinned ATT&CK release (revoked IDs fail with
    their replacement), and tactic tags consistent with the techniques
  * file naming and folder placement that match the logsource and tactic
  * a replayable logsource, unit cases, and - for `test`/`stable` rules -
    evidence on at least one real attack dataset
  * query portability: constructs that change meaning between SIEM dialects
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

from .attack import Catalog, tactic_tags, technique_ids
from .cases import load_cases
from .datasets import Dataset
from .engine import CompiledRule, UnsupportedRule
from .rules import RuleFile

REQUIRED = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "references",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
)
STATUSES = {"experimental", "test", "stable"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
NEEDS_EVIDENCE = {"test", "stable"}

# pySigma validators that fetch tag vocabularies over the network at runtime.
# ATT&CK tags are validated offline against the pinned catalog instead.
NETWORKED_VALIDATORS = {
    "attacktag",
    "d3_fendtag",
    "namespace_tag",
    "cartag",
    "cvetag",
    "stptag",
    "detection_tag",
    "tlptag",
    "tlpv1_tag",
    "tlpv2_tag",
}

PREFIX_BY_CATEGORY = {
    "process_creation": "proc_creation_",
    "process_access": "proc_access_",
    "file_event": "file_event_",
    "registry_add": "registry_add_",
    "registry_set": "registry_set_",
    "registry_delete": "registry_delete_",
    "registry_event": "registry_event_",
    "network_connection": "net_connection_",
    "image_load": "image_load_",
    "create_remote_thread": "create_remote_thread_",
    "wmi_event": "wmi_event_",
    "dns_query": "dns_query_",
    "pipe_created": "pipe_created_",
    "ps_script": "posh_ps_",
}
PREFIX_BY_SERVICE = {"security": "win_security_", "system": "win_system_"}

# Regex features that Lucene (Elastic) does not support or treats differently.
LUCENE_UNSAFE = [
    (re.compile(r"\\[sSdDwWbB]"), r"shorthand classes like \s, \d, \w, \b"),
    (re.compile(r"\(\?"), "lookarounds / inline flags"),
    (re.compile(r"^\^|(?<!\\)\$$"), "^/$ anchors (Lucene regex is always anchored)"),
]


@dataclass
class Issue:
    level: str  # error | warning
    rule: str
    check: str
    message: str

    def __str__(self) -> str:
        return f"{self.level.upper():7} {self.rule}: [{self.check}] {self.message}"


def _detection_values(node, path=()):
    """Yield (field-with-modifiers, value) pairs from a raw detection dict."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "condition":
                continue
            yield from _detection_values(v, path + (k,))
    elif isinstance(node, list):
        for item in node:
            yield from _detection_values(item, path)
    else:
        yield (path[-1] if path else ""), node


def lint(
    rules: list[RuleFile], catalog: Catalog, datasets: list[Dataset], cases_root: Path | None = None
) -> list[Issue]:
    issues: list[Issue] = []

    def add(level, rf, check, msg):
        issues.append(Issue(level, rf.rel if rf else "-", check, msg))

    # pySigma structural validators
    selected = [v for k, v in core_validators.items() if k not in NETWORKED_VALIDATORS]
    collection = SigmaCollection([rf.rule for rf in rules])
    by_rule = {id(rf.rule): rf for rf in rules}
    for issue in SigmaValidator(selected).validate_rules(collection):
        for r in issue.rules:
            add("error", by_rule.get(id(r)), "pysigma", f"{type(issue).__name__}: {issue.description}")

    ids = Counter(rf.id for rf in rules)
    titles = Counter(rf.rule.title for rf in rules)
    cases = load_cases(cases_root)
    case_kinds: dict[str, set[bool]] = {}
    for c in cases:
        case_kinds.setdefault(c.rule, set()).add(c.should_match)
    evidence = {stem for d in datasets for stem in d.expect}
    stems = {rf.stem for rf in rules}

    for rf in rules:
        raw = rf.raw
        # --- metadata -------------------------------------------------------
        for key in REQUIRED:
            if not raw.get(key):
                add("error", rf, "metadata", f"missing or empty '{key}'")
        try:
            uuid.UUID(str(raw.get("id")))
        except ValueError:
            add("error", rf, "metadata", "id is not a UUID")
        if ids[rf.id] > 1:
            add("error", rf, "metadata", f"duplicate id {rf.id}")
        if titles[rf.rule.title] > 1:
            add("error", rf, "metadata", f"duplicate title {rf.rule.title!r}")
        if raw.get("status") not in STATUSES:
            add("error", rf, "metadata", f"status must be one of {sorted(STATUSES)}")
        if raw.get("level") not in LEVELS:
            add("error", rf, "metadata", f"level must be one of {sorted(LEVELS)}")
        if len(str(raw.get("description", "")).split()) < 15:
            add("error", rf, "metadata", "description too short to explain the detection logic")

        # --- ATT&CK ---------------------------------------------------------
        techniques = technique_ids(rf.tags)
        tactics = tactic_tags(rf.tags)
        if not techniques:
            add("error", rf, "attack", "no ATT&CK technique tag (attack.tXXXX)")
        technique_tactics: set[str] = set()
        for tid in techniques:
            if tid in catalog.revoked:
                repl = catalog.revoked[tid]
                hint = f"; use attack.{repl.lower()}" if repl else ""
                add("error", rf, "attack", f"{tid} is revoked in ATT&CK v{catalog.version}{hint}")
            elif tid in catalog.deprecated:
                add("error", rf, "attack", f"{tid} is deprecated in ATT&CK v{catalog.version}")
            elif (t := catalog.resolve(tid)) is None:
                add("error", rf, "attack", f"{tid} does not exist in ATT&CK v{catalog.version}")
            else:
                technique_tactics.update(t.tactics)
                if "Windows" not in t.platforms and (rf.rule.logsource.product or "") == "windows":
                    add("warning", rf, "attack", f"{tid} does not list Windows as a platform")
        if not tactics:
            add("error", rf, "attack", "no ATT&CK tactic tag (e.g. attack.credential-access)")
        for tac in tactics:
            if tac not in catalog.tactic_shortnames:
                add("error", rf, "attack", f"unknown tactic 'attack.{tac}' in ATT&CK v{catalog.version}")
            elif technique_tactics and tac not in technique_tactics:
                add("error", rf, "attack", f"tactic '{tac}' does not belong to any tagged technique")
        folder = rf.path.parent.name.replace("_", "-")
        if technique_tactics and folder not in tactics:
            add(
                "error",
                rf,
                "layout",
                f"folder '{rf.path.parent.name}' is not one of the rule's tactics {tactics}",
            )

        # --- naming ---------------------------------------------------------
        ls = rf.rule.logsource
        prefix = PREFIX_BY_CATEGORY.get(ls.category or "") or PREFIX_BY_SERVICE.get(ls.service or "")
        if prefix and not rf.stem.startswith(prefix):
            add("error", rf, "layout", f"file name should start with '{prefix}'")

        # --- testability ----------------------------------------------------
        try:
            CompiledRule(rf.rule)
        except UnsupportedRule as exc:
            add("error", rf, "replay", f"rule cannot be replayed: {exc}")
        if case_kinds.get(rf.stem) != {True, False}:
            add("error", rf, "tests", f"tests/rule_cases/{rf.stem}.yml needs match and no_match cases")
        if raw.get("status") in NEEDS_EVIDENCE and rf.stem not in evidence:
            add(
                "error",
                rf,
                "evidence",
                f"status '{raw.get('status')}' requires a replay expectation in datasets/manifest.yml "
                "(or downgrade to experimental)",
            )

        # --- portability ----------------------------------------------------
        for key, value in _detection_values(raw.get("detection", {})):
            mods = str(key).split("|")[1:]
            if "re" in mods:
                for pattern, what in LUCENE_UNSAFE:
                    if pattern.search(str(value)):
                        add("error", rf, "portability", f"regex uses {what}: {value!r}")
                if not (str(value).startswith(".*") and str(value).endswith(".*")):
                    add(
                        "warning",
                        rf,
                        "portability",
                        "regex is not wrapped in .* - Lucene/ES|QL match the whole value, PCRE/RE2 search",
                    )
            elif isinstance(value, str) and re.search(r"(?<!\\)\?", value):
                add(
                    "warning",
                    rf,
                    "portability",
                    f"'?' wildcard in {value!r} becomes '*' in Splunk (broader match)",
                )

    for c in sorted(set(case_kinds) - stems):
        issues.append(
            Issue("error", f"tests/rule_cases/{c}.yml", "tests", "case file for a rule that does not exist")
        )
    for d in datasets:
        for stem in list(d.expect) + list(d.known_fp):
            if stem not in stems:
                issues.append(
                    Issue(
                        "error",
                        "datasets/manifest.yml",
                        "evidence",
                        f"dataset '{d.id}' references unknown rule '{stem}'",
                    )
                )
        for tid in d.attack:
            if catalog.resolve(tid) is None:
                issues.append(
                    Issue(
                        "error",
                        "datasets/manifest.yml",
                        "attack",
                        f"dataset '{d.id}' is tagged with unknown technique {tid}",
                    )
                )
    return issues
