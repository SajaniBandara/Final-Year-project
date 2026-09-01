"""Drain bc_detection_log_* sidecars into the snapshot as they arrive, then
delete them from results_routing/.

Built for exactly your situation: more ``bc_detection_log_*.csv`` files
(the ~600MB-each ML-DSA-87-signed accusation logs, see
:mod:`gui.backend.export_snapshot`) are still being copied in from the HPC,
and results_routing/ cannot hold all of them at once. Rather than waiting for
the whole batch and running out of disk first, this drains it continuously:

For every run that currently has a *complete* ``bc_detection_log_*.csv``:
  1. Skip it if the snapshot already has a map.json newer than the CSV
     (nothing changed since the last drain pass).
  2. Skip it if the CSV was modified within the last ``--settle`` seconds --
     an in-progress copy. (A transfer tool writing to a ``.download`` temp
     name and renaming on completion, as yours does, already protects
     against reading a half-written file; this is a second guard in case a
     future copy method writes the final name directly.)
  3. Export that run's map scene into the snapshot (same computation
     ``export_snapshot --map-runs`` does), and its summary/series too if this
     is a run the snapshot has not seen before.
  4. Verify the export landed on disk, THEN delete the source CSV.

Nothing is deleted before its export is confirmed written. ``--dry-run`` shows
what would happen without touching any file. ``--watch N`` re-scans every N
seconds so you can leave it running while the HPC copy continues; without it,
one pass runs and it exits.

Usage::

    python -m gui.backend.drain_detection_logs --snapshot gui/snapshots/demo
    python -m gui.backend.drain_detection_logs --snapshot gui/snapshots/demo --dry-run
    python -m gui.backend.drain_detection_logs --snapshot gui/snapshots/demo --watch 60

Only ``bc_detection_log_*.csv`` sidecars are touched. ``MOBIGUARD_Attack*.csv``
(the metrics files everything else is indexed from) are never deleted here --
see the "no, don't delete those" conversation this script came out of; they
are ~40MB total and load-bearing for the catalog itself.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from datetime import datetime, timezone

from . import mapview
from .catalog import DEFAULT_RESULTS_DIR, RunFile, parse_metrics_filename
from .export_snapshot import _kib, _write
from .service import ResultsService, ServiceError


def _run_needs_onboarding(snapshot_dir: Path, run_id: str) -> bool:
    """True if this run has never been exported at all (new since the last full export)."""
    return not (snapshot_dir / "runs" / run_id / "summary.json").is_file()


def drain_once(
    snapshot_dir: Path,
    *,
    results_dir: str | None = None,
    settle_s: float = 30.0,
    dry_run: bool = False,
) -> int:
    """One pass over the catalog. Returns the number of runs drained."""
    service = ResultsService(results_dir)
    service.refresh()  # pick up files copied in since the process started
    drained = 0
    now = time.time()

    for run_file in service.catalog:
        detection_path = mapview.sidecar(run_file, "detection")
        if detection_path is None:
            continue  # no complete bc_detection_log_*.csv for this run (yet)

        run_dir = snapshot_dir / "runs" / run_file.run_id
        map_path = run_dir / "map.json"
        csv_mtime = detection_path.stat().st_mtime

        if map_path.is_file() and map_path.stat().st_mtime >= csv_mtime:
            continue  # already drained since this CSV last changed

        if now - csv_mtime < settle_s:
            print(f"  [wait]  {detection_path.name}: modified {now - csv_mtime:.0f}s ago, "
                  f"< --settle {settle_s:g}s -- possibly still copying")
            continue

        print(f"  [drain] {run_file.run_id}  ({detection_path.stat().st_size / 1_048_576:.1f} MiB)")
        if dry_run:
            drained += 1
            continue

        try:
            if _run_needs_onboarding(snapshot_dir, run_file.run_id):
                summary = service.run_summary(run_file.run_id)
                _write(run_dir / "summary.json", summary)
                series = service.run_series(run_file.run_id)
                _write(run_dir / "series.json", series)
                print(f"          + onboarded (summary/series were missing for this run)")

            scene = service.map_scene(run_file.run_id)
            size = _write(map_path, scene)
        except ServiceError as exc:
            print(f"          [skip] export failed, CSV left in place: {exc}")
            continue

        if not map_path.is_file() or map_path.stat().st_size == 0:
            print(f"          [skip] map.json did not land on disk, CSV left in place")
            continue

        freed = detection_path.stat().st_size
        detection_path.unlink()
        print(f"          map.json {_kib(size)} written, {freed / 1_048_576:.1f} MiB freed")
        drained += 1

    return drained


def _orphan_run_file(detection_path: Path, results_dir: Path) -> RunFile | None:
    """A RunFile stub for a bc_detection_log_ with no matching metrics CSV.

    ``bc_detection_log_<stem>.csv`` shares its stem's grammar with
    ``MOBIGUARD_<stem>.csv`` (``catalog.METRICS_FILENAME_RE``), so the same
    parser reads attack/pct/delay/seed/tag straight off the detection log's
    own filename. The stub's ``.path`` points at the (nonexistent)
    ``MOBIGUARD_`` name only so :func:`gui.backend.mapview.sidecar` -- which
    derives the sidecar filename it looks for from ``run_file.path.stem``,
    never opens ``run_file.path`` itself -- reconstructs exactly this
    detection log's real path and finds it.
    """
    stem = detection_path.name[len("bc_detection_log_"):-len(".csv")]
    parts = parse_metrics_filename(f"MOBIGUARD_{stem}.csv")
    if parts is None:
        return None
    return RunFile(
        attack_id=parts["attack_id"],
        attack_percentage=parts["attack_percentage"],
        seed=parts["seed"],
        delay_ms=parts["delay_ms"],
        tag=parts["tag"],
        run_id=f"MOBIGUARD_{stem}",
        path=results_dir / f"MOBIGUARD_{stem}.csv",
        size_bytes=0,
        modified=datetime.fromtimestamp(detection_path.stat().st_mtime, tz=timezone.utc),
    )


def export_orphans_once(
    snapshot_dir: Path,
    *,
    results_dir: str | None = None,
    settle_s: float = 30.0,
    dry_run: bool = False,
) -> int:
    """Export map.json for bc_detection_log_ files with no metrics CSV partner.

    These never appear in the catalog (built from MOBIGUARD_Attack*.csv), so
    :func:`drain_once` can never see them and their disk space never gets
    reclaimed. This exports what can be recovered from the detection log and
    the mobility trace alone -- real topology, movement and accusations, just
    no confusion-matrix/PEM data since that lives only in the missing metrics
    CSV -- into ``<snapshot>/orphans/<run_id>/map.json``. It deliberately
    never deletes the source CSV: unlike a catalogued run, there is no
    metrics file whose presence would make "the JSON is a safe substitute"
    an easy call, so that decision is left to whoever reads the output.
    """
    base = Path(results_dir or DEFAULT_RESULTS_DIR)
    exported = 0
    now = time.time()

    for detection_path in sorted(base.glob("bc_detection_log_*.csv")):
        stem = detection_path.name[len("bc_detection_log_"):-len(".csv")]
        if (base / f"MOBIGUARD_{stem}.csv").is_file():
            continue  # not an orphan -- drain_once already owns this one

        run_file = _orphan_run_file(detection_path, base)
        if run_file is None:
            print(f"  [skip] {detection_path.name}: filename doesn't parse as an attack/pct/seed stem")
            continue

        out_path = snapshot_dir / "orphans" / run_file.run_id / "map.json"
        mtime = detection_path.stat().st_mtime
        if out_path.is_file() and out_path.stat().st_mtime >= mtime:
            continue  # already exported since this CSV last changed

        if now - mtime < settle_s:
            print(f"  [wait]  {detection_path.name}: modified {now - mtime:.0f}s ago, < --settle {settle_s:g}s")
            continue

        size_mib = detection_path.stat().st_size / 1_048_576
        print(f"  [export] {run_file.run_id}  ({size_mib:.1f} MiB, orphan -- no metrics CSV)")
        if dry_run:
            exported += 1
            continue

        try:
            result = mapview.scene(run_file)
        except mapview.MapError as exc:
            print(f"           [skip] export failed: {exc}")
            continue
        result["notes"] = [
            "Orphan export: this run has no MOBIGUARD_Attack*.csv metrics file, "
            "only its bc_detection_log_. Confusion-matrix/PEM data is "
            "unavailable; topology, movement and accusations are real."
        ] + list(result.get("notes") or [])
        size = _write(out_path, result)
        print(f"           map.json {_kib(size)} written -- source CSV left in place, not deleted")
        exported += 1

    return exported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", required=True, type=Path, help="Existing snapshot directory (from export_snapshot).")
    parser.add_argument("--results-dir", default=None, help="Source results_routing/ dir; defaults to $MOBIGUARD_RESULTS_DIR.")
    parser.add_argument("--settle", type=float, default=30.0, help="Seconds a CSV must sit untouched before it's treated as complete (default 30).")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be exported/deleted without touching any file.")
    parser.add_argument("--watch", type=float, default=None, metavar="SECONDS", help="Re-scan every N seconds instead of exiting after one pass.")
    parser.add_argument(
        "--orphans", action="store_true",
        help="Also export bc_detection_log_ files with no matching MOBIGUARD_Attack*.csv "
             "to <snapshot>/orphans/<id>/map.json. Export-only: never deletes the source "
             "CSV, since there is no metrics file to make that safe to decide automatically.",
    )
    args = parser.parse_args(argv)

    if not (args.snapshot / "index.json").is_file():
        parser.error(f"{args.snapshot} has no index.json -- run export_snapshot first")

    total = 0
    orphan_total = 0
    while True:
        print(f"--- scanning {args.results_dir or '(default results dir)'} ---")
        total += drain_once(
            args.snapshot, results_dir=args.results_dir, settle_s=args.settle, dry_run=args.dry_run
        )
        if args.orphans:
            orphan_total += export_orphans_once(
                args.snapshot, results_dir=args.results_dir, settle_s=args.settle, dry_run=args.dry_run
            )
        if args.watch is None:
            break
        print(f"({total} drained, {orphan_total} orphans exported so far) sleeping {args.watch:g}s ... Ctrl+C to stop")
        time.sleep(args.watch)

    verb = "would be drained" if args.dry_run else "drained"
    print(f"\n{total} run(s) {verb}.")
    if args.orphans:
        overb = "would be exported" if args.dry_run else "exported (source CSVs left in place)"
        print(f"{orphan_total} orphan run(s) {overb}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
