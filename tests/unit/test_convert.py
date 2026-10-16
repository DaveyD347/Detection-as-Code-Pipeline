"""Conversion: semantic checks catch broken output, and the gap list stays honest."""

from dac import paths
from dac.convert import (
    KQL_LITERAL_WILDCARD,
    SYSMON_REGISTRY_DATA,
    TARGETS,
    VALUE_NAME_IN_KEY,
    convert_all,
    convert_rule,
    load_known_gaps,
)
from dac.rules import load_rules

RULES = {r.stem: r for r in load_rules()}


def test_semantic_checks_flag_real_pysigma_output():
    # Both strings are verbatim pySigma output seen while building this repo.
    bad_wildcard = 'DeviceRegistryEvents\n| where RegistryKey endswith "\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*"'
    bad_dword = 'DeviceRegistryEvents\n| where RegistryKey endswith "\\\\Services\\\\EventLog\\\\Start" and RegistryValueData =~ "DWORD (0x00000004)"'
    bad_value = 'DeviceRegistryEvents\n| where RegistryKey endswith "\\\\ms-settings\\\\shell\\\\open\\\\command\\\\(Default)"'
    assert KQL_LITERAL_WILDCARD[0].search(bad_wildcard)
    assert SYSMON_REGISTRY_DATA[0].search(bad_dword)
    assert VALUE_NAME_IN_KEY[0].search(bad_value)
    good = 'DeviceProcessEvents\n| where FolderPath endswith "\\\\mshta.exe" and ProcessCommandLine contains "vbscript:"'
    assert not any(p.search(good) for p, _ in TARGETS["sentinel"].checks)


def test_corpus_converts_with_only_documented_gaps():
    result = convert_all(list(RULES.values()), load_known_gaps(paths.ROOT / "config" / "conversion.yml"))
    assert result.problems == []


def test_splunk_queries_are_scoped_by_data_source_macro():
    c = convert_rule(RULES["proc_creation_mshta_inline_script"], TARGETS["splunk"])
    assert c.query.startswith("`dac_windows_process_creation` ")


def test_pipelines_do_not_leak_between_targets():
    # pySigma pipelines mutate rules in place; converting for one target must
    # not rename fields for the next.
    rf = RULES["proc_creation_mshta_inline_script"]
    elastic = convert_rule(rf, TARGETS["elastic"]).query
    splunk = convert_rule(rf, TARGETS["splunk"]).query
    assert "process.command_line" in elastic
    assert "CommandLine" in splunk and "process.command_line" not in splunk
