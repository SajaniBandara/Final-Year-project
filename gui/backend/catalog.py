"""Filesystem index of the runs in ``results_routing/``.

Metadata only -- this module never opens a CSV. Scanning stays cheap so the
Offline Analytics tab can rebuild its run picker on demand, and
:mod:`gui.backend.parser` is called lazily for whichever run the user selects.

Filename grammar, from ``write_security_metrics_csv()`` in
``scratch/routing.cc`` (~line 117879)::

    MOBIGUARD_Attack<id>_<pct>[_d<delay>ms]_seed<seed>[_<run_tag>].csv

``<id>`` is ``active_attack_variant + 1``, with the benign baseline (-1) folded
into ``Attack0``. The ``_d<delay>ms`` group is present only when
``attack_delay_ms`` was set (Selective Time Delay, attacks 1-2); ``_<run_tag>``
only for ablation runs that pass ``g_run_tag``.

Both shapes are present in ``results_routing/`` today: 36 files without the
delay group and 12 with it, covering attacks 1-8 x {0,20,40,60,80,100} at seed 1.

Staleness
---------
``results_routing/`` is gitignored (``*.csv``), so the copy beside this repo is
refreshed by hand from the HPC. :attr:`RunFile.modified` is carried through to
the API for exactly that reason -- the plan calls for staleness to be visible in
the UI rather than assumed away.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

#: Repository root, from ``gui/backend/catalog.py``.
REPO_ROOT = Path(__file__).resolve().parents[2]

#: Default location of the metrics CSVs. Override with ``MOBIGUARD_RESULTS_DIR``
#: to point the GUI at a different copy without editing code.
DEFAULT_RESULTS_DIR = REPO_ROOT / "results_routing"

METRICS_FILENAME_RE = re.compile(
    r"^MOBIGUARD_Attack(?P<attack>\d+)"
    r"_(?P<pct>\d+)"
    r"(?:_d(?P<delay>\d+)ms)?"
    r"_seed(?P<seed>\d+)"
    r"(?:_(?P<tag>.+))?"
    r"\.csv$"
)


@dataclass(frozen=True, order=True)
class RunFile:
    """One metrics CSV, identified without being read.

    Attributes:
        attack_id: 0 for the benign baseline, 1-8 for the attack variants.
        attack_percentage: Fraction of malicious nodes, 0-100.
        delay_ms: Injected delay for attacks 1-2; ``None`` when absent.
        seed: ``--sim_seed`` the run used.
        tag: Ablation run tag, or ``None``.
        path: Absolute path to the CSV.
        size_bytes: File size, for a cheap "did this run produce anything" check.
        modified: Last-modified time, UTC, surfaced so stale copies are visible.
    """

    # Ordered fields first so sorting groups the picker the way the UI shows it.
    attack_id: int
    attack_percentage: int
    seed: int
    delay_ms: int | None
    tag: str | None
    run_id: str
    path: Path
    size_bytes: int
    modified: datetime

    @property
    def is_baseline(self) -> bool:
        """True for the benign baseline (``Attack0``), which has no attackers."""
        return self.attack_id == 0

    @property
    def label(self) -> str:
        """Short human label for the run picker, e.g. ``Attack 3 @ 40% (seed 1)``."""
        head = "Baseline" if self.is_baseline else f"Attack {self.attack_id}"
        parts = [f"{head} @ {self.attack_percentage}%"]
        if self.delay_ms is not None:
            parts.append(f"{self.delay_ms}ms")
        parts.append(f"seed {self.seed}")
        if self.tag:
            parts.append(self.tag)
        return f"{parts[0]} ({', '.join(parts[1:])})"

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable form for the ``/api/catalog`` response."""
        return {
            "id": self.run_id,
            "label": self.label,
            "attack": self.attack_id,
            "pct": self.attack_percentage,
            "delay_ms": self.delay_ms,
            "seed": self.seed,
            "tag": self.tag,
            "size_bytes": self.size_bytes,
            "modified": self.modified.isoformat(),
        }


def parse_metrics_filename(name: str) -> dict[str, object] | None:
    """Parse a metrics-CSV filename into its parts.

    Returns ``None`` if ``name`` is not a MOBIGUARD metrics CSV -- the results
    directory also holds ``bc_*``, ``crypto_timing_log_*``, ``tcam_*`` and
    ``fade_results_*`` files, which this index deliberately ignores.
    """
    match = METRICS_FILENAME_RE.match(name)
    if match is None:
        return None
    delay = match.group("delay")
    return {
        "attack_id": int(match.group("attack")),
        "attack_percentage": int(match.group("pct")),
        "delay_ms": int(delay) if delay is not None else None,
        "seed": int(match.group("seed")),
        "tag": match.group("tag"),
    }


class Catalog:
    """An immutable snapshot of the metrics CSVs in one results directory."""

    def __init__(self, runs: Iterable[RunFile], results_dir: Path) -> None:
        self._runs: list[RunFile] = sorted(runs)
        self._by_id: dict[str, RunFile] = {r.run_id: r for r in self._runs}
        self.results_dir = results_dir

    # --- construction -------------------------------------------------------

    @classmethod
    def scan(cls, results_dir: str | os.PathLike[str] | None = None) -> "Catalog":
        """Index every metrics CSV in ``results_dir``.

        Args:
            results_dir: Defaults to ``$MOBIGUARD_RESULTS_DIR`` if set, else
                :data:`DEFAULT_RESULTS_DIR`.

        Raises:
            FileNotFoundError: if the directory does not exist. Failing loudly
                here beats an empty run picker that looks like "no results yet".
        """
        base = Path(results_dir or os.environ.get("MOBIGUARD_RESULTS_DIR") or DEFAULT_RESULTS_DIR)
        if not base.is_dir():
            raise FileNotFoundError(
                f"results directory not found: {base}. Set MOBIGUARD_RESULTS_DIR "
                f"or copy the CSVs from the HPC into {DEFAULT_RESULTS_DIR}."
            )

        runs: list[RunFile] = []
        for entry in base.iterdir():
            if not entry.is_file():
                continue
            parts = parse_metrics_filename(entry.name)
            if parts is None:
                continue
            stat = entry.stat()
            runs.append(
                RunFile(
                    attack_id=int(parts["attack_id"]),
                    attack_percentage=int(parts["attack_percentage"]),
                    seed=int(parts["seed"]),
                    delay_ms=parts["delay_ms"],  # type: ignore[arg-type]
                    tag=parts["tag"],  # type: ignore[arg-type]
                    run_id=entry.stem,
                    path=entry.resolve(),
                    size_bytes=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                )
            )
        return cls(runs, base)

    # --- access -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._runs)

    def __iter__(self) -> Iterator[RunFile]:
        return iter(self._runs)

    @property
    def runs(self) -> list[RunFile]:
        """All indexed runs, sorted by attack, percentage, then seed."""
        return list(self._runs)

    def get(self, run_id: str) -> RunFile:
        """Look up one run by id.

        Raises:
            KeyError: if no such run is indexed.
        """
        try:
            return self._by_id[run_id]
        except KeyError:
            raise KeyError(f"unknown run id: {run_id!r}") from None

    def filter(
        self,
        *,
        attack_id: int | None = None,
        attack_percentage: int | None = None,
        seed: int | None = None,
        delay_ms: int | None = None,
        seeds: Iterable[int] | None = None,
        tag: str | None = None,
    ) -> list[RunFile]:
        """Select runs matching every supplied criterion.

        ``tag`` is matched exactly, including ``None`` for untagged runs, so an
        ablation sweep cannot leak into a headline result by accident. Omit the
        argument entirely to match any tag.
        """
        allowed_seeds = set(seeds) if seeds is not None else None
        selected = self._runs
        if attack_id is not None:
            selected = [r for r in selected if r.attack_id == attack_id]
        if attack_percentage is not None:
            selected = [r for r in selected if r.attack_percentage == attack_percentage]
        if seed is not None:
            selected = [r for r in selected if r.seed == seed]
        if allowed_seeds is not None:
            selected = [r for r in selected if r.seed in allowed_seeds]
        if delay_ms is not None:
            selected = [r for r in selected if r.delay_ms == delay_ms]
        if tag is not None:
            selected = [r for r in selected if r.tag == tag]
        return selected

    # --- axis helpers for the run picker ------------------------------------

    def attack_ids(self) -> list[int]:
        """Distinct attack ids present, ascending."""
        return sorted({r.attack_id for r in self._runs})

    def percentages(self, attack_id: int | None = None) -> list[int]:
        """Distinct attack percentages present, ascending."""
        runs = self.filter(attack_id=attack_id) if attack_id is not None else self._runs
        return sorted({r.attack_percentage for r in runs})

    def seeds(self, attack_id: int | None = None) -> list[int]:
        """Distinct seeds present, ascending."""
        runs = self.filter(attack_id=attack_id) if attack_id is not None else self._runs
        return sorted({r.seed for r in runs})

    def newest_modified(self) -> datetime | None:
        """Most recent mtime across all indexed runs, for the staleness banner."""
        if not self._runs:
            return None
        return max(r.modified for r in self._runs)
