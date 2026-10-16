"""Public attack datasets: manifest, pinned download, integrity check, parsing.

Datasets are never committed. Each manifest entry pins an immutable URL (a
git commit, not a branch) and a SHA-256. A download that does not match the
hash is rejected, so a compromised or force-pushed upstream cannot change what
the tests see, and the cache can be shared safely between CI runs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import urllib.request
import zipfile
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import paths


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    homepage: str
    license: str
    base_url: str


@dataclass
class Dataset:
    id: str
    source: Source
    path: str
    sha256: str
    description: str
    attack: list[str] = field(default_factory=list)
    expect: dict[str, int] = field(default_factory=dict)
    known_fp: dict[str, str] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return self.source.base_url.rstrip("/") + "/" + self.path.lstrip("/")

    def cache_path(self, cache: Path | None = None) -> Path:
        return (cache or paths.CACHE) / f"{self.sha256}{Path(self.path).suffix}"


def load_manifest(path: Path | None = None) -> list[Dataset]:
    raw = yaml.safe_load((path or paths.DATASETS).read_text(encoding="utf-8"))
    sources = {sid: Source(id=sid, **{k: v for k, v in s.items()}) for sid, s in raw["sources"].items()}
    datasets = []
    for d in raw["datasets"]:
        datasets.append(
            Dataset(
                id=d["id"],
                source=sources[d["source"]],
                path=d["path"],
                sha256=d["sha256"].lower(),
                description=d.get("description", "").strip(),
                attack=[str(t).upper() for t in d.get("attack", [])],
                expect={str(k): int(v) for k, v in (d.get("expect") or {}).items()},
                known_fp={str(k): str(v) for k, v in (d.get("known_fp") or {}).items()},
            )
        )
    ids = [d.id for d in datasets]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate dataset ids in manifest: {sorted(dupes)}")
    return datasets


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(dataset: Dataset, cache: Path | None = None) -> Path:
    """Return a verified local copy, downloading it if needed."""
    target = dataset.cache_path(cache)
    if target.exists():
        if _sha256(target) == dataset.sha256:
            return target
        target.unlink()  # corrupted or tampered cache entry
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(dataset.url, timeout=120) as resp:  # noqa: S310 - pinned https URL
        payload = resp.read()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != dataset.sha256:
        raise ValueError(
            f"{dataset.id}: SHA-256 mismatch for {dataset.url}\n"
            f"  expected {dataset.sha256}\n  received {digest}"
        )
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".part")
    with os.fdopen(fd, "wb") as fh:
        fh.write(payload)
    os.replace(tmp, target)
    return target


def fetch_all(datasets: list[Dataset], cache: Path | None = None, workers: int = 8) -> dict[str, Path]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda d: (d.id, fetch(d, cache)), datasets)
        return dict(results)


def _parse_lines(data: bytes) -> Iterator[dict]:
    for line in io.BytesIO(data):
        line = line.strip()
        if not line or line[:1] != b"{":
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            yield event


def iter_events(path: Path) -> Iterator[dict]:
    """Yield events from a .zip of JSON-lines files, or a bare .json/.jsonl file."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for member in zf.infolist():
                if member.is_dir() or not member.filename.lower().endswith((".json", ".jsonl")):
                    continue
                yield from _parse_lines(zf.read(member))
    else:
        yield from _parse_lines(path.read_bytes())
