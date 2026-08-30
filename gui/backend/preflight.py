"""Environment check: will the GUI actually work here, and which tabs will fill?

Run before starting the server, and especially after moving to a different
machine::

    python -m gui.backend.preflight

Each of the seven tabs is fed by a different family of files, and every one of
them can be individually absent. Without this, a missing dataset shows up as an
empty panel mid-demo with no indication of *why* -- so this reports, per tab,
whether its data is present and what to run if it is not.

Exit status is 0 when the server can start and at least one panel has data, 1
otherwise, so it is usable as a gate in a script.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto, lstm, tcam, verification
from .catalog import DEFAULT_RESULTS_DIR, Catalog
from .service import FIGURES_DIR, STALE_AFTER

OK, WARN, FAIL = "OK", "WARN", "FAIL"

GLYPH = {OK: "[ok]  ", WARN: "[warn]", FAIL: "[FAIL]"}


@dataclass
class Check:
    """One preflight line."""

    name: str
    status: str
    detail: str
    fix: str | None = None


@dataclass
class Report:
    """The full preflight result."""

    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str, fix: str | None = None) -> None:
        self.checks.append(Check(name, status, detail, fix))

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warned(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]

    def render(self) -> str:
        width = max((len(c.name) for c in self.checks), default=0)
        lines = []
        for check in self.checks:
            lines.append(f"  {GLYPH[check.status]} {check.name.ljust(width)}  {check.detail}")
            if check.fix and check.status != OK:
                lines.append(f"          {'':{width}}  -> {check.fix}")
        return "\n".join(lines)


def _check_runtime(report: Report) -> None:
    version = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info >= (3, 10):
        report.add("python", OK, f"{version}")
    else:
        report.add(
            "python", FAIL, f"{version} -- the backend uses 3.10+ syntax (X | Y unions)",
            "use a Python 3.10 or newer interpreter",
        )

    for module in ("fastapi", "uvicorn"):
        try:
            __import__(module)
            report.add(module, OK, "importable")
        except ImportError:
            report.add(
                module, FAIL, "not installed -- the server cannot start",
                "python -m pip install -r gui/requirements.txt",
            )


def _check_results(report: Report, results_dir: Path | None) -> Catalog | None:
    configured = os.environ.get("MOBIGUARD_RESULTS_DIR")
    base = results_dir or Path(configured or DEFAULT_RESULTS_DIR)

    report.add(
        "results dir",
        OK if base.is_dir() else WARN,
        f"{base}" + ("" if configured else "  (default; set MOBIGUARD_RESULTS_DIR to override)"),
        "copy the CSVs from the HPC, or set MOBIGUARD_RESULTS_DIR to where they live",
    )
    if not base.is_dir():
        return None

    try:
        catalog = Catalog.scan(base)
    except FileNotFoundError:
        return None

    if not len(catalog):
        report.add(
            "metrics CSVs", WARN, "none found -- Offline Analytics and Live PEM will be empty",
            "copy MOBIGUARD_Attack*_*_seed*.csv from the HPC results_routing/",
        )
        return catalog

    newest = catalog.newest_modified()
    age = datetime.now(timezone.utc) - newest if newest else None
    stale = bool(age and age > STALE_AFTER)
    report.add(
        "metrics CSVs",
        WARN if stale else OK,
        f"{len(catalog)} runs | attacks {catalog.attack_ids()} | seeds {catalog.seeds()}"
        + (f" | newest {age.days}d old" if age else ""),
        "refresh from the HPC -- charts may not reflect the current simulator" if stale else None,
    )

    seeds = catalog.seeds()
    if len(seeds) < 2:
        report.add(
            "confidence intervals", WARN,
            f"only seed {seeds[0] if seeds else '?'} present -- every sweep reads n=1, no CI",
            "copy seeds 2-5 from the HPC to get error bars",
        )
    else:
        report.add("confidence intervals", OK, f"{len(seeds)} seeds -- CIs available")

    return catalog


def _check_panels(report: Report, results_dir: Path | None) -> int:
    """Per-tab data availability. Returns how many panels have data."""
    populated = 0

    # detector_windows.csv is the only source of the paper's M1 (see
    # docs/WHICH_MCC_TO_REPORT.md); its absence is why the GUI can currently
    # only show the per-node diagnostic.
    base = results_dir or Path(os.environ.get("MOBIGUARD_RESULTS_DIR") or DEFAULT_RESULTS_DIR)
    windows = list(base.glob("detector_windows_*.csv")) if base.is_dir() else []
    report.add(
        "paper M1 (detector_windows)",
        OK if windows else WARN,
        f"{len(windows)} files" if windows else "absent -- only the per-node diagnostic can be shown",
        "run with --enable_detector_windows=1 --simTime=90, then copy detector_windows_*.csv",
    )

    tcam_files = tcam.scan(results_dir)
    report.add(
        "tab: TCAM Grid", OK if tcam_files else WARN,
        f"{len(tcam_files)} occupancy logs" if tcam_files else "no tcam_occupancy_*.csv",
        "copy tcam_occupancy_*.csv from the HPC",
    )
    populated += bool(tcam_files)

    crypto_files = crypto.scan(results_dir)
    report.add(
        "tab: Crypto Overhead", OK if crypto_files else WARN,
        f"{len(crypto_files)} timing logs" if crypto_files else "no crypto_timing_log_*.csv",
        "copy crypto_timing_log_*.csv from the HPC",
    )
    populated += bool(crypto_files)

    evaluation = lstm.load_evaluation()
    report.add(
        "tab: Federated LSTM", OK if evaluation else WARN,
        f"{len(evaluation['variants'])} variants (git-tracked, independent of results_routing)"
        if evaluation else "lstm_pipeline/evaluation_results.json missing",
        "run lstm_pipeline/src/pipeline.py",
    )
    populated += bool(evaluation)

    audit = verification.read_audit()
    if audit["available"]:
        counts = audit.get("counts_reported") or audit["counts_parsed"]
        failing = counts["FAIL"]
        report.add(
            "tab: Verification",
            OK if failing == 0 else WARN,
            f"{counts['PASS']} pass, {failing} fail"
            + ("" if failing == 0 else " -- the equation audit does not currently pass"),
            "see docs/GUI_IMPLEMENTATION_PLAN.md section 7, finding E" if failing else None,
        )
    else:
        report.add(
            "tab: Verification", WARN, "equation_audit.log not generated",
            "python scripts/audit_equations.py --no-color > docs/task8_verification/equation_audit.log"
            "  (or press Re-run audit in the tab)",
        )
    populated += bool(audit["available"])

    functional = verification.read_functional()
    report.add(
        "  functional verification", OK if functional["available"] else WARN,
        "log present" if functional["available"] else "not generated (needs a finished sweep)",
        functional.get("command") if not functional["available"] else None,
    )

    figures = list(FIGURES_DIR.rglob("*.png")) if FIGURES_DIR.is_dir() else []
    report.add(
        "tab: Thesis Figures", OK if figures else WARN,
        f"{len(figures)} PNGs under output/" if figures else "no PNGs under output/",
    )
    populated += bool(figures)

    return populated


def run(results_dir: Path | None = None) -> tuple[Report, bool]:
    """Build the report. Returns ``(report, ok_to_start)``."""
    report = Report()
    _check_runtime(report)
    catalog = _check_results(report, results_dir)
    populated = _check_panels(report, results_dir)

    if catalog and len(catalog):
        populated += 2  # Offline Analytics and Live PEM Monitor share the metrics CSVs

    can_start = not report.failed
    return report, can_start and populated > 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--results-dir", type=Path, default=None,
        help="results_routing/ to check (default: $MOBIGUARD_RESULTS_DIR, else the repo copy)",
    )
    args = parser.parse_args(argv)

    report, ok = run(args.results_dir)

    print("MOBIGUARD demo GUI -- preflight\n")
    print(report.render())
    print()

    if report.failed:
        print(
            f"{len(report.failed)} blocking problem(s): the server cannot start. "
            "Fix these first."
        )
    elif report.warned:
        print(
            f"Server will start. {len(report.warned)} warning(s) -- "
            "those tabs will be empty or incomplete."
        )
    else:
        print("All checks passed.")

    print("\n  python -m uvicorn gui.backend.app:app   # then open http://127.0.0.1:8000/")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
