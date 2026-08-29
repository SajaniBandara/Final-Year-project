"""Streaming tests: replay, live tail, and the WebSocket contract.

Run with::

    python -m unittest gui.tests.test_stream -v

The property that matters most here is that **replay and live emit the same
message sequence**. The demo defaults to replay and switches to a live tail; if
the two contracts drifted, the Live tab would work in rehearsal and fail in the
room.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gui.backend import schema, stream
from gui.backend.app import app, get_service
from gui.backend.service import ResultsService


def _row(attack_id: int, cycle: int, mcc: float = 0.5) -> str:
    values = {name: 0.0 for name in schema.columns_for(attack_id)}
    values["cycle"] = float(cycle)
    values["cur_MCC"] = mcc
    values["TP"] = 10.0
    values["TN"] = 200.0
    return ", ".join(
        str(cycle) if name == "cycle" else f"{values[name]:g}"
        for name in schema.columns_for(attack_id)
    )


async def _collect(source, limit: int, timeout: float = 5.0) -> list[stream.Cycle]:
    """Take up to ``limit`` cycles from a source, then stop.

    A live tail never completes on its own, so the caller always bounds it.
    """
    collected: list[stream.Cycle] = []

    async def run() -> None:
        async for cycle in source:
            collected.append(cycle)
            if len(collected) >= limit:
                return

    await asyncio.wait_for(run(), timeout=timeout)
    return collected


class TestReplaySource(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "MOBIGUARD_Attack1_40_seed1.csv"
        header = "# " + ", ".join(schema.columns_for(1))
        rows = [_row(1, c, mcc=c / 10) for c in range(1, 6)]
        self.path.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    async def test_replays_every_cycle_in_order(self):
        source = stream.ReplaySource(self.path, 1, speed=60)
        cycles = await _collect(source, 5)
        self.assertEqual([c.cycle for c in cycles], [1, 2, 3, 4, 5])
        self.assertEqual([c.source for c in cycles], ["replay"] * 5)
        self.assertAlmostEqual(cycles[2].columns["cur_MCC"], 0.3)

    async def test_first_row_is_immediate(self):
        """The UI must paint at once, not after a full interval of blank chart."""
        source = stream.ReplaySource(self.path, 1, speed=1)
        loop = asyncio.get_running_loop()
        started = loop.time()
        await _collect(source, 1)
        self.assertLess(loop.time() - started, 0.5)

    async def test_speed_controls_pacing(self):
        source = stream.ReplaySource(self.path, 1, speed=20)
        loop = asyncio.get_running_loop()
        started = loop.time()
        await _collect(source, 3)
        elapsed = loop.time() - started
        # Two intervals of 1/20 s between three rows; generous upper bound.
        self.assertGreater(elapsed, 0.05)
        self.assertLess(elapsed, 2.0)

    async def test_speed_is_clamped(self):
        self.assertEqual(stream.ReplaySource(self.path, 1, speed=9999).speed, stream.MAX_SPEED)
        self.assertEqual(stream.ReplaySource(self.path, 1, speed=0).speed, stream.MIN_SPEED)

    async def test_empty_file_raises(self):
        empty = Path(self._tmp.name) / "empty.csv"
        empty.write_text("# header only\n", encoding="utf-8")
        with self.assertRaises(Exception):
            await _collect(stream.ReplaySource(empty, 1, speed=60), 1)


class TestTailSource(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "MOBIGUARD_Attack1_40_seed1.csv"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _append(self, text: str) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(text)

    async def test_reads_existing_rows_then_follows(self):
        self.path.write_text(
            "# header\n" + _row(1, 1) + "\n" + _row(1, 2) + "\n", encoding="utf-8"
        )
        source = stream.TailSource(self.path, 1, poll=0.02)

        async def append_later():
            await asyncio.sleep(0.1)
            self._append(_row(1, 3) + "\n")

        task = asyncio.create_task(append_later())
        cycles = await _collect(source, 3)
        await task
        self.assertEqual([c.cycle for c in cycles], [1, 2, 3])
        self.assertEqual(cycles[0].source, "live")

    async def test_from_start_false_skips_existing_rows(self):
        self.path.write_text("# header\n" + _row(1, 1) + "\n", encoding="utf-8")
        source = stream.TailSource(self.path, 1, poll=0.02, from_start=False)

        async def append_later():
            await asyncio.sleep(0.1)
            self._append(_row(1, 2) + "\n")

        task = asyncio.create_task(append_later())
        cycles = await _collect(source, 1)
        await task
        self.assertEqual([c.cycle for c in cycles], [2])

    async def test_partial_row_is_held_until_newline(self):
        """A row caught mid-write must not be decoded as a short row.

        routing.cc closes the file each cycle so this is rare, but a torn read
        would otherwise raise SchemaError and kill the stream mid-demo.
        """
        self.path.write_text("# header\n", encoding="utf-8")
        source = stream.TailSource(self.path, 1, poll=0.02)

        complete = _row(1, 1)
        half = complete[: len(complete) // 2]

        async def dribble():
            await asyncio.sleep(0.05)
            self._append(half)               # torn row, no newline
            await asyncio.sleep(0.15)
            self._append(complete[len(half):] + "\n")   # completed

        task = asyncio.create_task(dribble())
        cycles = await _collect(source, 1)
        await task
        self.assertEqual([c.cycle for c in cycles], [1])

    async def test_truncation_restarts_the_stream(self):
        self.path.write_text("# header\n" + _row(1, 5) + "\n", encoding="utf-8")
        source = stream.TailSource(self.path, 1, poll=0.02)

        async def truncate_later():
            await asyncio.sleep(0.1)
            self.path.write_text("# header\n" + _row(1, 1) + "\n", encoding="utf-8")

        task = asyncio.create_task(truncate_later())
        cycles = await _collect(source, 2)
        await task
        self.assertEqual([c.cycle for c in cycles], [5, 1])

    async def test_missing_file_times_out_with_a_useful_message(self):
        source = stream.TailSource(
            self.path, 1, poll=0.02, appear_timeout=0.1
        )
        with self.assertRaises(FileNotFoundError) as ctx:
            await _collect(source, 1)
        self.assertIn("is the simulation running", str(ctx.exception))


class TestMakeSource(unittest.TestCase):
    def test_modes(self):
        self.assertIsInstance(stream.make_source("replay", "x.csv", 1), stream.ReplaySource)
        self.assertIsInstance(stream.make_source("live", "x.csv", 1), stream.TailSource)

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            stream.make_source("magic", "x.csv", 1)


class TestStreamWebSocket(unittest.TestCase):
    """The contract the Live tab depends on."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        header = "# " + ", ".join(schema.columns_for(1))
        rows = [_row(1, c) for c in range(1, 4)]
        (base / "MOBIGUARD_Attack1_40_seed1.csv").write_text(
            "\n".join([header, *rows]) + "\n", encoding="utf-8"
        )
        app.dependency_overrides[get_service] = lambda: ResultsService(base)
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        self._tmp.cleanup()

    def test_replay_emits_meta_then_cycles_then_end(self):
        with self.client.websocket_connect(
            "/ws/stream?run_id=MOBIGUARD_Attack1_40_seed1&mode=replay&speed=60"
        ) as ws:
            meta = ws.receive_json()
            self.assertEqual(meta["type"], "meta")
            self.assertEqual(meta["mode"], "replay")
            self.assertEqual(meta["attack_start_s"], 10.0)
            self.assertIn("cur_MCC", meta["kpi_columns"])
            self.assertIn("cur_MCC", meta["caveats"])

            cycles = [ws.receive_json() for _ in range(3)]
            self.assertEqual([m["type"] for m in cycles], ["cycle"] * 3)
            self.assertEqual([m["cycle"] for m in cycles], [1, 2, 3])
            self.assertEqual([m["source"] for m in cycles], ["replay"] * 3)
            self.assertFalse(any(m["restarted"] for m in cycles))

            end = ws.receive_json()
            self.assertEqual(end["type"], "end")

    def test_unknown_run_sends_error_not_a_crash(self):
        with self.client.websocket_connect("/ws/stream?run_id=nope&mode=replay") as ws:
            message = ws.receive_json()
            self.assertEqual(message["type"], "error")
            self.assertIn("nope", message["detail"])

    def test_unknown_mode_sends_error(self):
        with self.client.websocket_connect(
            "/ws/stream?run_id=MOBIGUARD_Attack1_40_seed1&mode=magic"
        ) as ws:
            ws.receive_json()  # meta is sent before the mode is validated
            message = ws.receive_json()
            self.assertEqual(message["type"], "error")
            self.assertIn("magic", message["detail"])


if __name__ == "__main__":
    unittest.main()
