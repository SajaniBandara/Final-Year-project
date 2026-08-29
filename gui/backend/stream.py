"""Cycle streaming for the Live PEM Monitor: replay and live tail.

Both sources yield the *same* decoded rows through the *same*
:class:`gui.backend.parser.RowDecoder`, so the UI cannot tell them apart and a
bug can only exist in one of them, not two. That was the point of making the
decoder incremental in Phase 0.

Why replay exists at all
------------------------
The demo runs on the laptop while ns-3 runs on the HPC, so a genuinely live tail
needs the simulator writing to a visible path. Replay reproduces a recorded run
at wall-clock speed against the identical message contract, so the Live tab
always has something to show and a live run becomes a toggle rather than a
dependency. Replay is honest, not a fake: it emits the real rows of a real run,
and the UI labels which source is feeding it.

Why tailing works with no change to routing.cc
----------------------------------------------
``write_security_metrics_csv()`` opens the metrics CSV with ``ios::app``, writes
the cycle row, and **closes it every cycle**. Each row is therefore flushed to
disk once per simulated second -- roughly every 4 wall-seconds in an
``optimized`` build. :class:`TailSource` only ever decodes newline-terminated
lines, so a half-written row is held back until it is complete rather than
raising on a short field count.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

from .parser import RowDecoder, SchemaError, parse_file

#: One routing cycle is one simulated second (`data_transmission_frequency` is
#: fixed at 1.0 by design -- CLAUDE.md, "Known gotchas"), so real time is the
#: natural replay rate.
CYCLE_PERIOD_S: float = 1.0

#: Bounds on the replay speed multiplier. The upper bound keeps a "fast" replay
#: from becoming a single burst that renders as a static chart.
MIN_SPEED, MAX_SPEED = 0.1, 60.0

#: How often :class:`TailSource` looks for new bytes.
DEFAULT_POLL_S: float = 0.5

#: How long to wait for a live run's CSV to appear before giving up.
DEFAULT_APPEAR_TIMEOUT_S: float = 120.0


@dataclass(frozen=True)
class Cycle:
    """One decoded cycle row, ready to send to the browser."""

    cycle: int
    columns: dict[str, float]
    source: str
    #: True when this row began a new appended run in the same file, so the UI
    #: should reset its series instead of drawing across the discontinuity.
    restarted: bool = False

    def to_message(self) -> dict[str, object]:
        return {
            "type": "cycle",
            "cycle": self.cycle,
            "cols": self.columns,
            "source": self.source,
            "restarted": self.restarted,
        }


def clamp_speed(speed: float) -> float:
    """Constrain a replay speed multiplier to a sane range."""
    return max(MIN_SPEED, min(MAX_SPEED, speed))


class ReplaySource:
    """Replays a finished metrics CSV at wall-clock speed.

    Args:
        path: The metrics CSV to replay.
        attack_id: Attack id from the filename, selecting the column layout.
        speed: Multiplier on real time; 1.0 emits one cycle per second.
        run_index: Which appended run in the file (``-1`` = most recent).
    """

    source_name = "replay"

    def __init__(
        self,
        path: str | os.PathLike[str],
        attack_id: int,
        *,
        speed: float = 1.0,
        run_index: int = -1,
    ) -> None:
        self.path = Path(path)
        self.attack_id = attack_id
        self.speed = clamp_speed(speed)
        self.run_index = run_index

    @property
    def interval(self) -> float:
        return CYCLE_PERIOD_S / self.speed

    async def __aiter__(self) -> AsyncIterator[Cycle]:
        runs = parse_file(self.path, self.attack_id)
        if not runs:
            raise SchemaError(f"{self.path.name}: no data rows to replay")
        run = runs[self.run_index]

        for index, cycle in enumerate(run.cycles):
            # Emit the first row immediately so the UI paints at once instead of
            # showing an empty chart for a full interval.
            if index:
                await asyncio.sleep(self.interval)
            yield Cycle(
                cycle=cycle,
                columns={name: values[index] for name, values in run.columns.items()},
                source=self.source_name,
            )


class TailSource:
    """Follows a metrics CSV as the simulator appends to it.

    Only newline-terminated lines are decoded, so a row caught mid-write is held
    in the buffer until the simulator finishes it.

    Args:
        path: The metrics CSV to follow; it need not exist yet.
        attack_id: Attack id from the filename, selecting the column layout.
        from_start: Replay existing rows before following (default), rather than
            starting at the current end of file.
        poll: Seconds between reads.
        appear_timeout: How long to wait for the file to be created.
    """

    source_name = "live"

    def __init__(
        self,
        path: str | os.PathLike[str],
        attack_id: int,
        *,
        from_start: bool = True,
        poll: float = DEFAULT_POLL_S,
        appear_timeout: float = DEFAULT_APPEAR_TIMEOUT_S,
    ) -> None:
        self.path = Path(path)
        self.attack_id = attack_id
        self.from_start = from_start
        self.poll = poll
        self.appear_timeout = appear_timeout

    async def _await_file(self) -> None:
        """Wait for the CSV to be created, e.g. by a run that just launched."""
        waited = 0.0
        while not self.path.exists():
            if waited >= self.appear_timeout:
                raise FileNotFoundError(
                    f"{self.path} did not appear within {self.appear_timeout:g}s; "
                    f"is the simulation running and writing to this path?"
                )
            await asyncio.sleep(self.poll)
            waited += self.poll

    async def __aiter__(self) -> AsyncIterator[Cycle]:
        await self._await_file()

        decoder = RowDecoder(self.attack_id)
        buffer = ""
        stat = self.path.stat()
        offset = 0 if self.from_start else stat.st_size
        last_mtime = stat.st_mtime
        last_cycle: int | None = None

        while True:
            try:
                stat = self.path.stat()
                size = stat.st_size
            except FileNotFoundError:
                # The file was removed mid-run (a re-run that truncates).
                await asyncio.sleep(self.poll)
                continue

            # Two ways a fresh run replaces the file rather than appending to it:
            # it shrinks, or it is rewritten in place to a coincidentally equal
            # length. Size alone misses the second, so mtime is checked too --
            # otherwise the stream would sit silent for the whole new run.
            rewritten = size < offset or (size == offset and stat.st_mtime > last_mtime)
            last_mtime = stat.st_mtime
            if rewritten:
                offset, buffer, last_cycle = 0, "", None

            if size > offset:
                with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    offset = fh.tell()

                buffer += chunk
                # Everything after the final newline is a partial row: keep it.
                lines = buffer.split("\n")
                buffer = lines.pop()

                for line in lines:
                    decoded = decoder.decode(line)
                    if decoded is None:
                        continue
                    cycle, row = decoded
                    # A non-increasing cycle means ios::app started a new run in
                    # the same file. Flag it so the UI can clear its chart
                    # rather than drawing the new run on top of the old one.
                    restarted = last_cycle is not None and cycle <= last_cycle
                    last_cycle = cycle
                    yield Cycle(
                        cycle=cycle,
                        columns=row,
                        source=self.source_name,
                        restarted=restarted,
                    )

            await asyncio.sleep(self.poll)


def make_source(
    mode: str,
    path: str | os.PathLike[str],
    attack_id: int,
    *,
    speed: float = 1.0,
    from_start: bool = True,
) -> ReplaySource | TailSource:
    """Build the source for ``mode``.

    Raises:
        ValueError: on an unknown mode.
    """
    if mode == "replay":
        return ReplaySource(path, attack_id, speed=speed)
    if mode == "live":
        return TailSource(path, attack_id, from_start=from_start)
    raise ValueError(f"unknown stream mode {mode!r}; expected 'replay' or 'live'")
