"""Schema-aware decoder for the per-cycle MOBIGUARD metrics CSVs.

Handles the five hazards documented in ``docs/GUI_IMPLEMENTATION_PLAN.md`` §3,
each verified against the files currently in ``results_routing/``:

1. **Two row widths.** 52 fields normally, 61 for attacks 3/4/0 -- and the extra
   block is inserted mid-row, not appended. :mod:`gui.backend.schema` owns the
   layout; this module asserts the actual field count against it and raises
   :class:`SchemaError` rather than reading shifted columns.

2. **Two header formats coexist on disk.** Runs before 2026-08-21 wrote a 4-line
   header (6 lines for TCAM variants); newer runs write a single line. Both are
   present right now. We skip every ``#``-prefixed line and index positionally.
   ``csv.DictReader`` is unusable here: it would take the first header line's 7
   names and silently mis-key rows carrying 52.

3. **Space-padded fields** -- rows read ``1, 66.6667, 24.4179, ...``.

4. **``ios::app``**: re-running the same config appends to the existing file
   instead of truncating it, so one file can hold several runs back to back.
   We split on a non-increasing cycle index instead of assuming one run per file.

5. **Scientific notation** in ``t_stark_ms_avg`` (e.g. ``9.14657e-05``).

The decoder is deliberately incremental (:class:`RowDecoder`) so that Phase 2's
replay and live-tail paths can share exactly this code, one line at a time,
rather than growing a second parser that drifts from this one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import schema


class SchemaError(ValueError):
    """A row did not match the field layout expected for its attack id.

    Raised rather than absorbed: a width mismatch means every field after the
    TCAM block would be read from the wrong column, producing numbers that look
    entirely reasonable and are entirely wrong.
    """


@dataclass(frozen=True)
class Run:
    """One contiguous simulation run decoded from a metrics CSV.

    A single file yields more than one of these only when it was appended to by
    a repeated run of the same configuration (hazard 4 above).

    Attributes:
        attack_id: Attack number from the filename (0 = benign baseline).
        index: 0-based position of this run within its file.
        cycles: Routing-cycle index per row, strictly increasing.
        columns: Column name -> values, one entry per row of :attr:`cycles`.
        source: Path the run was decoded from, for error messages.
    """

    attack_id: int
    index: int
    cycles: list[int]
    columns: dict[str, list[float]]
    source: str = ""

    def __len__(self) -> int:
        return len(self.cycles)

    def series(self, name: str) -> list[float]:
        """Return one column's values.

        Raises:
            KeyError: if ``name`` is not a column of this run's schema -- most
                often asking for a TCAM column on a non-TCAM attack.
        """
        try:
            return self.columns[name]
        except KeyError:
            raise KeyError(
                f"{name!r} is not a column for attack {self.attack_id} "
                f"({'wide' if schema.has_tcam_columns(self.attack_id) else 'narrow'} "
                f"schema). Available: {sorted(self.columns)}"
            ) from None

    def final(self) -> dict[str, float]:
        """Values from the last cycle -- the run-level summary.

        The ``avg_*`` columns are cumulative, so their final value is the
        whole-run average that the sweep curves plot.
        """
        if not self.cycles:
            return {}
        return {name: values[-1] for name, values in self.columns.items()}


class RowDecoder:
    """Decodes metrics-CSV lines for one attack id.

    Stateless with respect to row order, so the same instance serves a whole
    file, a replay, or a live tail.

    Note:
        Callers reading a file that is still being written must pass only
        newline-terminated lines. A partially flushed row would fail the width
        check and raise :class:`SchemaError`, which is the correct behaviour for
        a complete file but is merely "not finished yet" for a growing one.
        ``routing.cc`` closes the file every cycle, so complete lines are the
        normal case; the tailer still enforces this.
    """

    def __init__(self, attack_id: int) -> None:
        self.attack_id = attack_id
        self.column_names = schema.columns_for(attack_id)
        self.expected_width = schema.width_for(attack_id)

    def decode(self, line: str, *, line_no: int | None = None) -> tuple[int, dict[str, float]] | None:
        """Decode one line.

        Returns:
            ``(cycle, {column: value})``, or ``None`` for blank lines and
            ``#``-prefixed header lines of either header format.

        Raises:
            SchemaError: on a field-count mismatch or an unparseable number.
        """
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        fields = [f.strip() for f in stripped.split(",")]
        # The header lines end with a trailing comma; data rows do not, but
        # tolerate it so a future writer change cannot break every row at once.
        while fields and fields[-1] == "":
            fields.pop()

        if len(fields) != self.expected_width:
            where = f" at line {line_no}" if line_no is not None else ""
            raise SchemaError(
                f"attack {self.attack_id} expects {self.expected_width} fields "
                f"per row, got {len(fields)}{where}. "
                f"Attacks {sorted(schema.TCAM_ATTACK_IDS)} carry "
                f"{len(schema.TCAM_BLOCK)} extra TCAM fields inserted after "
                f"index {len(schema.BASE_HEAD) - 1}; check the attack id was "
                f"taken from the filename and not guessed."
            )

        try:
            values = [float(f) for f in fields]
        except ValueError as exc:
            where = f" at line {line_no}" if line_no is not None else ""
            raise SchemaError(f"non-numeric field{where}: {exc}") from exc

        row = dict(zip(self.column_names, values))
        return int(row["cycle"]), row


def parse_lines(
    lines: Iterable[str],
    attack_id: int,
    *,
    source: str = "",
) -> list[Run]:
    """Decode an iterable of CSV lines into one :class:`Run` per contiguous run.

    A new run starts wherever the cycle index fails to increase, which is how a
    second append to the same file shows up (hazard 4).
    """
    decoder = RowDecoder(attack_id)
    runs: list[Run] = []
    cycles: list[int] = []
    columns: dict[str, list[float]] = {name: [] for name in decoder.column_names}

    def flush() -> None:
        if cycles:
            runs.append(
                Run(
                    attack_id=attack_id,
                    index=len(runs),
                    cycles=list(cycles),
                    columns={k: list(v) for k, v in columns.items()},
                    source=source,
                )
            )

    for line_no, line in enumerate(lines, start=1):
        decoded = decoder.decode(line, line_no=line_no)
        if decoded is None:
            continue
        cycle, row = decoded

        if cycles and cycle <= cycles[-1]:
            # Cycle went backwards: this file holds a second appended run.
            flush()
            cycles.clear()
            for values in columns.values():
                values.clear()

        cycles.append(cycle)
        for name, value in row.items():
            columns[name].append(value)

    flush()
    return runs


def parse_file(path: str | os.PathLike[str], attack_id: int) -> list[Run]:
    """Decode a metrics CSV into its constituent runs.

    Raises:
        SchemaError: with the file and line number, if any row is malformed.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        try:
            return parse_lines(fh, attack_id, source=str(p))
        except SchemaError as exc:
            raise SchemaError(f"{p.name}: {exc}") from exc


def load_run(path: str | os.PathLike[str], attack_id: int, *, index: int = -1) -> Run:
    """Decode a metrics CSV and return a single run from it.

    Args:
        index: Which run to return; ``-1`` (the default) takes the most recent,
            which is what a file appended to by a re-run should display.

    Raises:
        SchemaError: if the file contains no data rows.
    """
    runs = parse_file(path, attack_id)
    if not runs:
        raise SchemaError(f"{Path(path).name}: no data rows (header only?)")
    return runs[index]
