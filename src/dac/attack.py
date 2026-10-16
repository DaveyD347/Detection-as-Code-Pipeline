"""MITRE ATT&CK catalog: sync from STIX, load, and resolve rule tags.

The full Enterprise STIX bundle is ~55 MB. We never ship it; `dac attack sync`
downloads a pinned version once, verifies its SHA-256, and writes a compact
catalog (techniques, tactics, matrix order, revocations) that is committed to
the repo. Everything else (linting, coverage) runs offline from that file, so
a CI run is reproducible and a new ATT&CK release is an explicit, reviewable
diff rather than something that silently changes under the rules.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "{ref}/enterprise-attack/enterprise-attack-{version}.json"
)

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
GROUP_OR_SOFTWARE_TAG = re.compile(r"^attack\.[gs]\d{4}$", re.IGNORECASE)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    url: str

    @property
    def parent(self) -> str:
        return self.id.split(".")[0]

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.id


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str


@dataclass
class Catalog:
    version: str
    techniques: dict[str, Technique]
    tactics: list[Tactic]  # in matrix (kill-chain) order
    revoked: dict[str, str | None] = field(default_factory=dict)  # old id -> replacement
    deprecated: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: Path) -> Catalog:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            version=raw["version"],
            techniques={
                t["id"]: Technique(
                    id=t["id"],
                    name=t["name"],
                    tactics=tuple(t["tactics"]),
                    platforms=tuple(t["platforms"]),
                    url=t["url"],
                )
                for t in raw["techniques"]
            },
            tactics=[Tactic(**t) for t in raw["tactics"]],
            revoked=dict(raw["revoked"]),
            deprecated=set(raw["deprecated"]),
        )

    @property
    def tactic_shortnames(self) -> set[str]:
        return {t.shortname for t in self.tactics}

    def resolve(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.upper())


def technique_ids(tags) -> list[str]:
    """Technique IDs (upper-case) from a rule's tags, in order, de-duplicated."""
    out: list[str] = []
    for tag in tags:
        m = TECHNIQUE_TAG.match(str(tag))
        if m and m.group(1).upper() not in out:
            out.append(m.group(1).upper())
    return out


def tactic_tags(tags) -> list[str]:
    out = []
    for tag in tags:
        s = str(tag)
        if not s.lower().startswith("attack."):
            continue
        if TECHNIQUE_TAG.match(s) or GROUP_OR_SOFTWARE_TAG.match(s):
            continue
        out.append(s.split(".", 1)[1].lower().replace("_", "-"))
    return out


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def build_catalog(bundle: dict, version: str, source: dict) -> dict:
    """Reduce a STIX 2.1 Enterprise bundle to the compact catalog format."""
    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}

    tactics_by_ref = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic" and not o.get("revoked")}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    tactics = [
        {
            "id": _external_id(tactics_by_ref[ref]),
            "shortname": tactics_by_ref[ref]["x_mitre_shortname"],
            "name": tactics_by_ref[ref]["name"],
        }
        for ref in matrix["tactic_refs"]
    ]

    revoked_by = {
        r["source_ref"]: r["target_ref"]
        for r in objects
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by"
    }

    techniques, revoked, deprecated = [], {}, []
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        tid = _external_id(o)
        if not tid:
            continue
        if o.get("revoked"):
            target = by_stix_id.get(revoked_by.get(o["id"], ""))
            revoked[tid] = _external_id(target) if target else None
            continue
        if o.get("x_mitre_deprecated"):
            deprecated.append(tid)
            continue
        techniques.append(
            {
                "id": tid,
                "name": o["name"],
                "tactics": [
                    p["phase_name"]
                    for p in o.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": sorted(o.get("x_mitre_platforms", [])),
                "url": _url(o),
            }
        )

    techniques.sort(key=lambda t: [int(p) for p in t["id"][1:].split(".")])
    return {
        "version": version,
        "source": source,
        "tactics": tactics,
        "techniques": techniques,
        "revoked": dict(sorted(revoked.items())),
        "deprecated": sorted(deprecated),
    }


def sync(version: str, ref: str, sha256: str | None, out: Path) -> Path:
    url = STIX_URL.format(ref=ref, version=version)
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - pinned https URL
        payload = resp.read()
    digest = hashlib.sha256(payload).hexdigest()
    if sha256 and digest != sha256:
        raise ValueError(f"SHA-256 mismatch for {url}: expected {sha256}, got {digest}")
    catalog = build_catalog(json.loads(payload), version, {"url": url, "sha256": digest})
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, indent=1) + "\n", encoding="utf-8")
    return out
