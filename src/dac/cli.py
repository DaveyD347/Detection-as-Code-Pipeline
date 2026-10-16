"""`dac` command line: lint, replay, convert, coverage, attack sync."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import paths


def _catalog():
    from .attack import Catalog

    files = sorted(paths.ATTACK_DIR.glob("enterprise-attack-*.json"))
    if len(files) != 1:
        sys.exit(f"expected exactly one pinned ATT&CK catalog in {paths.ATTACK_DIR}, found {len(files)}")
    return Catalog.load(files[0])


def _summary(markdown: str) -> None:
    """Append to the GitHub Actions job summary when running in CI."""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def cmd_lint(args) -> int:
    from .datasets import load_manifest
    from .lint import lint
    from .rules import load_rules

    rules = load_rules()
    issues = lint(rules, _catalog(), load_manifest())
    for issue in sorted(issues, key=lambda i: (i.level != "error", i.rule)):
        print(issue)
    errors = sum(1 for i in issues if i.level == "error")
    warnings = len(issues) - errors
    print(f"\n{len(rules)} rules linted: {errors} error(s), {warnings} warning(s)")
    _summary(
        f"### Lint\n{len(rules)} rules: {errors} error(s), {warnings} warning(s)\n"
        + "".join(f"- `{i}`\n" for i in issues)
    )
    return 1 if errors or (args.strict and warnings) else 0


def cmd_replay(args) -> int:
    from .datasets import load_manifest
    from .replay import run, write_reports
    from .rules import load_rules

    datasets = load_manifest()
    if args.dataset:
        datasets = [d for d in datasets if d.id in set(args.dataset)]
    result = run(load_rules(), datasets)
    _, md = write_reports(result, Path(args.out))
    for f in result.findings:
        print(f"{f.level.upper():7} {f.dataset}: {f.rule}: {f.message}")
    total = sum(result.events.values())
    print(
        f"\nReplayed {len(result.rules)} rules over {len(datasets)} datasets ({total:,} events); "
        f"{len(result.validated_rules())} rules validated. Report: {md}"
    )
    _summary(md.read_text(encoding="utf-8"))
    return 0 if result.ok else 1


def cmd_convert(args) -> int:
    from .convert import convert_all, load_known_gaps, render, stale, write
    from .rules import load_rules

    rules = load_rules()
    result = convert_all(rules, load_known_gaps(paths.ROOT / "config" / "conversion.yml"))
    files = render(result, rules, _catalog())
    out = Path(args.out)
    for p in result.problems:
        print(f"ERROR   {p}")
    if args.check:
        diffs = stale(files, out)
        for d in diffs:
            print(f"ERROR   {out / d} is out of date; run `dac convert` and commit the result")
        _summary(files["README.md"])
        return 1 if diffs or result.problems else 0
    write(files, out)
    print(f"Wrote {len(files)} files to {out}")
    _summary(files["README.md"])
    return 1 if result.problems else 0


def cmd_coverage(args) -> int:
    from .convert import convert_all, load_known_gaps
    from .coverage import build, navigator_layer, write_site
    from .rules import load_rules

    rules = load_rules()
    catalog = _catalog()
    replay_path = Path(args.replay)
    replay = json.loads(replay_path.read_text()) if replay_path.exists() else None
    if replay is None:
        print(f"warning: {replay_path} not found; run `dac replay` first for validation status")
    conv = convert_all(rules, load_known_gaps(paths.ROOT / "config" / "conversion.yml"))
    conversion = {(c.rule, c.target): bool(c.query) for c in conv.conversions}
    data = build(rules, catalog, replay, conversion)
    index = write_site(data, navigator_layer(data, catalog), Path(args.out), args.repo_url)
    s = data["stats"]
    print(
        f"{s['techniques_covered']} techniques covered ({s['techniques_validated']} validated) "
        f"across {s['tactics_covered']} tactics. Site: {index}"
    )
    return 0


def cmd_attack_sync(args) -> int:
    from .attack import sync

    out = paths.ATTACK_DIR / f"enterprise-attack-{args.version}.json"
    sync(args.version, args.ref, args.sha256, out)
    print(f"Wrote {out}. Remove the previous catalog and run `dac lint` to see what the new release breaks.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dac", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("lint", help="validate rule metadata, ATT&CK tags, layout and portability")
    p.add_argument("--strict", action="store_true", help="treat warnings as errors")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("replay", help="replay all rules over the attack datasets")
    p.add_argument("--out", default=str(paths.BUILD), help="report directory")
    p.add_argument("--dataset", action="append", help="only replay this dataset id (repeatable)")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("convert", help="convert rules to Splunk, Elastic and Sentinel")
    p.add_argument("--out", default=str(paths.ROOT / "queries"))
    p.add_argument("--check", action="store_true", help="fail if committed queries are stale")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("coverage", help="build the ATT&CK heatmap site and Navigator layer")
    p.add_argument("--replay", default=str(paths.BUILD / "replay.json"))
    p.add_argument("--out", default=str(paths.BUILD / "site"))
    p.add_argument("--repo-url", default=os.environ.get("DAC_REPO_URL", ""))
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("attack-sync", help="pin a new ATT&CK release")
    p.add_argument("--version", required=True, help="e.g. 20.0")
    p.add_argument("--ref", required=True, help="mitre-attack/attack-stix-data commit SHA")
    p.add_argument("--sha256", help="expected SHA-256 of the STIX bundle")
    p.set_defaults(func=cmd_attack_sync)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
