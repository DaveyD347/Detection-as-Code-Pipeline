"""Semantics of the replay engine, independent of the rule corpus."""

import pytest

from dac.engine import UnsupportedRule, compile_rule

SYSMON_1 = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}


def rule(detection: str, logsource: str = "category: process_creation") -> str:
    return f"""
title: test
id: 00000000-0000-4000-8000-000000000000
logsource:
  product: windows
  {logsource}
detection:
{detection}
"""


def ev(**fields):
    return {**SYSMON_1, **fields}


def test_plain_string_is_exact_and_case_insensitive():
    r = compile_rule(rule("  s:\n    Image: C:\\Windows\\cmd.exe\n  condition: s"))
    assert r.matches(ev(Image="c:\\windows\\CMD.EXE"))
    assert not r.matches(ev(Image="C:\\Windows\\cmd.exe.bak"))


def test_cased_modifier():
    r = compile_rule(rule("  s:\n    CommandLine|cased: Invoke-Mimikatz\n  condition: s"))
    assert r.matches(ev(CommandLine="Invoke-Mimikatz"))
    assert not r.matches(ev(CommandLine="invoke-mimikatz"))


@pytest.mark.parametrize(
    "modifier,value,yes,no",
    [
        ("contains", "evil", "an EVIL thing", "good"),
        ("startswith", "C:\\Temp", "c:\\temp\\x.exe", "D:\\temp\\x.exe"),
        ("endswith", "\\lsass.exe", "C:\\Windows\\System32\\LSASS.EXE", "lsass.exe.mui"),
    ],
)
def test_string_modifiers(modifier, value, yes, no):
    r = compile_rule(rule(f"  s:\n    F|{modifier}: '{value}'\n  condition: s"))
    assert r.matches(ev(F=yes))
    assert not r.matches(ev(F=no))


def test_wildcards_and_escaping():
    r = compile_rule(rule("  s:\n    F: 'a?c*'\n  condition: s"))
    assert r.matches(ev(F="abcdef"))
    assert not r.matches(ev(F="ac"))
    literal = compile_rule(rule("  s:\n    F: 'a\\*b'\n  condition: s"))
    assert literal.matches(ev(F="a*b"))
    assert not literal.matches(ev(F="axxb"))


def test_regex_metacharacters_in_plain_strings_are_literal():
    r = compile_rule(rule("  s:\n    F|contains: '(x.y)+'\n  condition: s"))
    assert r.matches(ev(F="pre(x.y)+post"))
    assert not r.matches(ev(F="xay"))


def test_list_values_are_or_and_all_is_and():
    any_of = compile_rule(rule("  s:\n    F|contains: [a1, b2]\n  condition: s"))
    all_of = compile_rule(rule("  s:\n    F|contains|all: [a1, b2]\n  condition: s"))
    assert any_of.matches(ev(F="xx b2"))
    assert not all_of.matches(ev(F="xx b2"))
    assert all_of.matches(ev(F="b2 a1"))


def test_windash_expands_dash_variants():
    r = compile_rule(rule("  s:\n    F|contains|windash: ' -enc '\n  condition: s"))
    for flag in ("-enc", "/enc", "\u2013enc", "\u2014enc"):
        assert r.matches(ev(F=f"powershell {flag} AAAA"))


def test_regex_is_unanchored_search_with_flags():
    r = compile_rule(rule("  s:\n    F|re: 'ab+c'\n  condition: s"))
    assert r.matches(ev(F="xxabbbcxx"))
    assert not r.matches(ev(F="ABC"))
    ri = compile_rule(rule("  s:\n    F|re|i: 'ab+c'\n  condition: s"))
    assert ri.matches(ev(F="ABC"))


def test_numbers_and_comparisons():
    r = compile_rule(rule("  s:\n    Port: 4444\n  condition: s"))
    assert r.matches(ev(Port=4444))
    assert r.matches(ev(Port="4444"))
    gt = compile_rule(rule("  s:\n    Size|gte: 100\n  condition: s"))
    assert gt.matches(ev(Size="150"))
    assert not gt.matches(ev(Size=99))
    assert not gt.matches(ev(Size="n/a"))


def test_cidr():
    r = compile_rule(rule("  s:\n    DestinationIp|cidr: 10.0.0.0/8\n  condition: s"))
    assert r.matches(ev(DestinationIp="10.20.30.40"))
    assert not r.matches(ev(DestinationIp="192.168.1.1"))
    assert not r.matches(ev(DestinationIp="not-an-ip"))


def test_null_exists_and_missing_fields():
    null = compile_rule(rule("  s:\n    F: null\n  condition: s"))
    assert null.matches(ev()) and null.matches(ev(F="")) and not null.matches(ev(F="x"))
    exists = compile_rule(rule("  s:\n    F|exists: true\n  condition: s"))
    assert exists.matches(ev(F="")) and not exists.matches(ev())
    absent = compile_rule(rule("  s:\n    F: x\n  f:\n    G: y\n  condition: s and not f"))
    assert absent.matches(ev(F="x")), "a missing field must not make a NOT filter fail"


def test_fieldref():
    r = compile_rule(rule("  s:\n    ParentImage|fieldref: Image\n  condition: s"))
    assert r.matches(ev(Image="C:\\a.exe", ParentImage="c:\\A.EXE"))
    assert not r.matches(ev(Image="C:\\a.exe", ParentImage="C:\\b.exe"))


def test_keywords_search_all_values():
    r = compile_rule(rule("  keywords:\n    - mimikatz\n  condition: keywords"))
    assert r.matches(ev(Message="Started MimiKatz.exe"))
    assert not r.matches(ev(Message="nothing here"))


def test_conditions_one_of_all_of_not():
    det = """  sel_a:
    A: 1
  sel_b:
    B: 1
  filter:
    C: 1
  condition: 1 of sel_* and not filter"""
    r = compile_rule(rule(det))
    assert r.matches(ev(A=1)) and r.matches(ev(B=1))
    assert not r.matches(ev(A=1, C=1))
    r_all = compile_rule(rule(det.replace("1 of sel_*", "all of sel_*")))
    assert r_all.matches(ev(A=1, B=1)) and not r_all.matches(ev(A=1))


def test_list_of_maps_is_or():
    r = compile_rule(rule("  s:\n    - A: 1\n    - B: 2\n  condition: s"))
    assert r.matches(ev(A=1)) and r.matches(ev(B=2)) and not r.matches(ev(A=2))


def test_event_list_values_match_any_element():
    r = compile_rule(rule("  s:\n    Tags: b\n  condition: s"))
    assert r.matches(ev(Tags=["a", "b"]))


def test_logsource_routing_and_field_mapping():
    r = compile_rule(rule("  s:\n    Image|endswith: '\\cmd.exe'\n  condition: s"))
    sysmon_other_id = {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 3,
        "Image": "C:\\cmd.exe",
    }
    security_4688 = {"Channel": "security", "EventID": "4688", "NewProcessName": "C:\\Windows\\cmd.exe"}
    assert not r.matches(sysmon_other_id)
    assert r.matches(security_4688), "channel match is case-insensitive and 4688 fields are mapped"


def test_service_logsource():
    r = compile_rule(rule("  s:\n    EventID: 1102\n  condition: s", "service: security"))
    assert r.matches({"Channel": "Security", "EventID": 1102})
    assert not r.matches({"Channel": "System", "EventID": 1102})


def test_unknown_logsource_is_refused():
    with pytest.raises(UnsupportedRule):
        compile_rule(rule("  s:\n    A: 1\n  condition: s", "category: something_new"))


def test_placeholders_are_refused():
    with pytest.raises(UnsupportedRule):
        compile_rule(rule("  s:\n    User|expand: '%admins%'\n  condition: s"))
