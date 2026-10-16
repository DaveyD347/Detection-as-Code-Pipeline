"""ATT&CK coverage: Navigator layer + a static heatmap site.

Coverage is graded, not binary. A technique counts as *validated* only when a
rule for it fired on a real attack dataset during replay; a rule that exists
but has never seen attack telemetry is shown as *untested*. That keeps the
heatmap honest: it is easy to tag a rule with a technique, much harder to
prove it detects it.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .attack import Catalog, technique_ids
from .rules import RuleFile

VALIDATED, UNTESTED = 2, 1


@dataclass
class RuleInfo:
    stem: str
    id: str
    title: str
    level: str
    status: str
    path: str
    techniques: list[str]
    validated: bool
    datasets: list[str]
    targets: dict[str, bool]


def build(
    rules: list[RuleFile],
    catalog: Catalog,
    replay: dict | None,
    conversion: dict[tuple[str, str], bool] | None,
) -> dict:
    validated = set((replay or {}).get("validated_rules", []))
    datasets_by_rule: dict[str, list[str]] = {}
    for d in (replay or {}).get("datasets", []):
        for stem, n in d.get("hits", {}).items():
            if stem in d.get("expect", {}) and n > 0:
                datasets_by_rule.setdefault(stem, []).append(d["id"])
    targets = sorted({t for (_, t) in (conversion or {})})

    infos: list[RuleInfo] = []
    for rf in sorted(rules, key=lambda r: r.stem):
        infos.append(
            RuleInfo(
                stem=rf.stem,
                id=rf.id,
                title=rf.rule.title,
                level=rf.raw.get("level", ""),
                status=rf.raw.get("status", ""),
                path=rf.rel,
                techniques=[t for t in technique_ids(rf.tags) if catalog.resolve(t)],
                validated=rf.stem in validated,
                datasets=sorted(datasets_by_rule.get(rf.stem, [])),
                targets={t: bool((conversion or {}).get((rf.stem, t))) for t in targets},
            )
        )

    score: dict[str, int] = {}
    rules_for: dict[str, list[str]] = {}
    for info in infos:
        for tid in info.techniques:
            rules_for.setdefault(tid, []).append(info.stem)
            score[tid] = max(score.get(tid, 0), VALIDATED if info.validated else UNTESTED)

    matrix = []
    for tactic in catalog.tactics:
        parents = [
            t for t in catalog.techniques.values() if tactic.shortname in t.tactics and not t.is_subtechnique
        ]
        cells = []
        for p in sorted(parents, key=lambda t: t.name):
            subs = [
                s
                for s in catalog.techniques.values()
                if s.parent == p.id and s.is_subtechnique and tactic.shortname in s.tactics
            ]
            cells.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "url": p.url,
                    "windows": "Windows" in p.platforms,
                    "score": score.get(p.id, 0),
                    "rules": rules_for.get(p.id, []),
                    "subs": [
                        {
                            "id": s.id,
                            "name": s.name,
                            "url": s.url,
                            "score": score.get(s.id, 0),
                            "rules": rules_for.get(s.id, []),
                            "windows": "Windows" in s.platforms,
                        }
                        for s in sorted(subs, key=lambda s: s.id)
                    ],
                }
            )
        matrix.append(
            {"id": tactic.id, "shortname": tactic.shortname, "name": tactic.name, "techniques": cells}
        )

    covered = {tid for tid in score}
    windows_ids = {t.id for t in catalog.techniques.values() if "Windows" in t.platforms}
    return {
        "attack_version": catalog.version,
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "stats": {
            "rules": len(infos),
            "validated_rules": sum(1 for i in infos if i.validated),
            "techniques_covered": len(covered),
            "techniques_validated": sum(1 for t in covered if score[t] == VALIDATED),
            "windows_techniques": len(windows_ids),
            "tactics_covered": sum(
                1
                for col in matrix
                if any(c["score"] or any(s["score"] for s in c["subs"]) for c in col["techniques"])
            ),
            "datasets": len((replay or {}).get("datasets", [])),
            "events": sum(d.get("events", 0) for d in (replay or {}).get("datasets", [])),
            "targets": {t: sum(1 for i in infos if i.targets.get(t)) for t in targets},
        },
        "matrix": matrix,
        "rules": [i.__dict__ for i in infos],
        "datasets": (replay or {}).get("datasets", []),
    }


def navigator_layer(data: dict, catalog: Catalog) -> dict:
    """ATT&CK Navigator layer (format 4.5); open it at https://mitre-attack.github.io/attack-navigator/."""
    techniques = []
    for col in data["matrix"]:
        for cell in col["techniques"]:
            for item in [cell, *cell["subs"]]:
                if not item["score"]:
                    continue
                techniques.append(
                    {
                        "techniqueID": item["id"],
                        "tactic": col["shortname"],
                        "score": item["score"],
                        "comment": "Rules: " + ", ".join(item["rules"]),
                        "enabled": True,
                        "showSubtechniques": True,
                    }
                )
    return {
        "name": "Detection-as-Code coverage",
        "versions": {"attack": catalog.version.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "2 = rule validated on replayed attack data, 1 = rule exists, not yet validated.",
        "filters": {"platforms": ["Windows"]},
        "gradient": {"colors": ["#ffffff", "#9fd8d0", "#0f8b7d"], "minValue": 0, "maxValue": 2},
        "legendItems": [
            {"label": "Validated on attack data", "color": "#0f8b7d"},
            {"label": "Rule exists, untested", "color": "#9fd8d0"},
        ],
        "techniques": sorted(techniques, key=lambda t: (t["techniqueID"], t["tactic"])),
    }


def write_site(data: dict, layer: dict, out: Path, repo_url: str = "") -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "coverage.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    (out / "navigator-layer.json").write_text(json.dumps(layer, indent=1) + "\n", encoding="utf-8")
    page = TEMPLATE.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))
    page = page.replace("__REPO__", html.escape(repo_url, quote=True))
    index = out / "index.html"
    index.write_text(page, encoding="utf-8")
    return index


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ATT&amp;CK Detection Coverage</title>
<style>
:root {
  --bg: #f7f8fa; --panel: #ffffff; --ink: #14181f; --muted: #5d6675; --line: #e3e6eb;
  --none: #eef0f3; --none-ink: #8a93a1; --untested: #cdeee9; --untested-ink: #0d5d54;
  --valid: #0f8b7d; --valid-ink: #ffffff; --accent: #0f8b7d; --chip: #eef0f3;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0e1116; --panel: #161b22; --ink: #e6e9ee; --muted: #9aa4b2; --line: #262d37;
    --none: #1b2129; --none-ink: #5f6976; --untested: #17423d; --untested-ink: #9fe3d8;
    --valid: #1fb5a3; --valid-ink: #04211d; --accent: #2cc9b6; --chip: #1f2630;
  }
}
:root[data-theme="dark"] {
  --bg: #0e1116; --panel: #161b22; --ink: #e6e9ee; --muted: #9aa4b2; --line: #262d37;
  --none: #1b2129; --none-ink: #5f6976; --untested: #17423d; --untested-ink: #9fe3d8;
  --valid: #1fb5a3; --valid-ink: #04211d; --accent: #2cc9b6; --chip: #1f2630;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: var(--accent); }
header, main { max-width: 1500px; margin: 0 auto; padding: 0 16px; }
header { padding-top: 28px; }
h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 16px; margin: 32px 0 12px; }
.sub { color: var(--muted); margin: 0 0 20px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.stat b { display: block; font-size: 22px; font-variant-numeric: tabular-nums; }
.stat span { color: var(--muted); font-size: 12px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 14px; align-items: center; margin: 22px 0 10px; }
.legend { display: flex; gap: 12px; flex-wrap: wrap; color: var(--muted); font-size: 12px; }
.sw { display: inline-block; width: 12px; height: 12px; border-radius: 3px; vertical-align: -2px; margin-right: 5px; }
label.tg { font-size: 12px; color: var(--muted); display: flex; gap: 6px; align-items: center; cursor: pointer; }
.matrix { display: grid; grid-auto-flow: column; grid-auto-columns: minmax(150px, 1fr); gap: 6px;
  overflow-x: auto; padding-bottom: 8px; }
.col h3 { font-size: 12px; margin: 0 0 6px; padding: 8px; background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; position: sticky; top: 0; }
.col h3 small { display: block; color: var(--muted); font-weight: 400; }
.cell { display: block; width: 100%; text-align: left; border: 0; border-radius: 6px; padding: 6px 7px; margin-bottom: 4px;
  font: inherit; font-size: 11.5px; line-height: 1.3; cursor: pointer; background: var(--none); color: var(--none-ink); }
.cell[data-s="1"] { background: var(--untested); color: var(--untested-ink); }
.cell[data-s="2"] { background: var(--valid); color: var(--valid-ink); font-weight: 600; }
.cell:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.cell .tid { opacity: .75; font-size: 10.5px; display: block; font-weight: 400; }
.hide-uncovered .cell[data-s="0"] { display: none; }
.hide-nonwin .cell[data-w="0"] { display: none; }
#detail { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; margin-top: 12px; min-height: 54px; }
#detail .empty { color: var(--muted); }
.chip { display: inline-block; background: var(--chip); border-radius: 999px; padding: 1px 8px; font-size: 12px; margin: 2px 4px 2px 0; }
.chip.ok { background: var(--valid); color: var(--valid-ink); }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; font-size: 13px; }
th { font-size: 12px; color: var(--muted); font-weight: 600; }
.tw { overflow-x: auto; }
.yes { color: var(--accent); font-weight: 600; }
.no { color: var(--none-ink); }
footer { color: var(--muted); font-size: 12px; padding: 32px 16px; max-width: 1500px; margin: 0 auto; }
</style>
</head>
<body>
<header>
  <h1>ATT&amp;CK Detection Coverage</h1>
  <p class="sub" id="sub"></p>
  <div class="stats" id="stats"></div>
</header>
<main>
  <div class="toolbar">
    <div class="legend">
      <span><i class="sw" style="background:var(--valid)"></i>Validated on replayed attack data</span>
      <span><i class="sw" style="background:var(--untested)"></i>Rule exists, not yet validated</span>
      <span><i class="sw" style="background:var(--none)"></i>No coverage</span>
    </div>
    <label class="tg"><input type="checkbox" id="onlyCovered"> Covered techniques only</label>
    <label class="tg"><input type="checkbox" id="onlyWin" checked> Windows techniques only</label>
  </div>
  <div class="matrix" id="matrix"></div>
  <div id="detail"><span class="empty">Select a technique to see the rules and datasets behind it.</span></div>

  <h2>Rules</h2>
  <div class="tw"><table id="rules"></table></div>

  <h2>Replayed attack datasets</h2>
  <div class="tw"><table id="datasets"></table></div>
</main>
<footer>Generated <span id="gen"></span> from <a href="__REPO__">the rule repository</a>.
  Download the <a href="navigator-layer.json">ATT&amp;CK Navigator layer</a> or the raw <a href="coverage.json">coverage data</a>.</footer>
<script>
const D = __DATA__;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const rulesByStem = Object.fromEntries(D.rules.map((r) => [r.stem, r]));
const s = D.stats;
$("sub").textContent = `MITRE ATT&CK Enterprise v${D.attack_version}. Every rule is replayed against public attack recordings on each commit.`;
$("gen").textContent = D.generated;
const targetStats = Object.entries(s.targets).map(([t, n]) => [`${n}/${s.rules}`, `rules convert to ${t}`]);
$("stats").innerHTML = [
  [s.rules, "detection rules"],
  [`${s.validated_rules}/${s.rules}`, "validated on attack data"],
  [s.techniques_covered, "techniques & sub-techniques covered"],
  [s.tactics_covered, "of 15 tactics covered"],
  [s.datasets, "attack datasets replayed"],
  [s.events.toLocaleString(), "events replayed per run"],
  ...targetStats,
].map(([v, l]) => `<div class="stat"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join("");

function bestScore(c) { return Math.max(c.score, ...c.subs.map((x) => x.score), 0); }
$("matrix").innerHTML = D.matrix.map((col) => {
  const covered = col.techniques.filter((c) => bestScore(c) > 0).length;
  const cells = col.techniques
    .slice().sort((a, b) => bestScore(b) - bestScore(a) || a.name.localeCompare(b.name))
    .map((c) => {
      const subs = c.subs.filter((x) => x.score > 0).length;
      const note = subs ? ` · ${subs}/${c.subs.length} sub` : "";
      return `<button class="cell" data-s="${bestScore(c)}" data-w="${c.windows ? 1 : 0}" data-t="${esc(col.shortname)}" data-id="${esc(c.id)}">${esc(c.name)}<span class="tid">${esc(c.id)}${note}</span></button>`;
    }).join("");
  return `<div class="col"><h3>${esc(col.name)}<small>${covered}/${col.techniques.length} techniques</small></h3>${cells}</div>`;
}).join("");

const m = $("matrix");
const sync = () => {
  m.classList.toggle("hide-uncovered", $("onlyCovered").checked);
  m.classList.toggle("hide-nonwin", $("onlyWin").checked);
};
$("onlyCovered").addEventListener("change", sync);
$("onlyWin").addEventListener("change", sync);
sync();

m.addEventListener("click", (e) => {
  const b = e.target.closest(".cell"); if (!b) return;
  const col = D.matrix.find((c) => c.shortname === b.dataset.t);
  const c = col.techniques.find((t) => t.id === b.dataset.id);
  const items = [c, ...c.subs].filter((x) => x.rules.length);
  const body = items.length ? items.map((x) => `<p><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.id)} ${esc(x.name)}</a><br>` +
      x.rules.map((st) => { const r = rulesByStem[st];
        return `<span class="chip ${r.validated ? "ok" : ""}">${esc(r.title)}${r.validated ? " ✓" : ""}</span>`; }).join("") + "</p>").join("")
    : `<p class="empty">No rule covers ${esc(c.id)} ${esc(c.name)} yet.</p>`;
  $("detail").innerHTML = `<b>${esc(col.name)}</b> › ${esc(c.name)}` + body;
});

const targets = Object.keys(s.targets);
$("rules").innerHTML = `<thead><tr><th>Rule</th><th>Level</th><th>Techniques</th><th>Validated on</th>${targets.map((t) => `<th>${esc(t)}</th>`).join("")}</tr></thead><tbody>` +
  D.rules.map((r) => `<tr><td><a href="__REPO__/blob/main/${esc(r.path)}">${esc(r.title)}</a></td><td>${esc(r.level)}</td>` +
    `<td>${r.techniques.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</td>` +
    `<td>${r.datasets.length ? r.datasets.map((d) => `<span class="chip ok">${esc(d)}</span>`).join("") : '<span class="no">not yet</span>'}</td>` +
    targets.map((t) => `<td class="${r.targets[t] ? "yes" : "no"}">${r.targets[t] ? "✓" : "–"}</td>`).join("") + "</tr>").join("") + "</tbody>";

$("datasets").innerHTML = `<thead><tr><th>Dataset</th><th>Events</th><th>Rules that fired</th></tr></thead><tbody>` +
  D.datasets.map((d) => `<tr><td><a href="${esc(d.url)}">${esc(d.id)}</a></td><td>${d.events.toLocaleString()}</td>` +
    `<td>${Object.entries(d.hits).map(([st, n]) => `<span class="chip ok">${esc(rulesByStem[st] ? rulesByStem[st].title : st)} ×${n}</span>`).join("") || '<span class="no">none (noise baseline)</span>'}</td></tr>`).join("") + "</tbody>";
</script>
</body>
</html>
"""
