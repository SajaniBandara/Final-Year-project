# MOBIGUARD Demo GUI — Implementation Plan

**Supervisor instruction (verbatim):** *"GUI better shows the offline simulation
statistics and graphs and also PEMs for realtime simulation. This is how you can
score marks in the demo."*

PEM = Performance Evaluation Metrics (the term used in
`docs/task8_verification/FUNCTIONAL_VERIFICATION_GUIDE.md` §1, deliverable 5).

So the GUI has exactly two halves, and both must be visibly present in the demo:

1. **Offline** — statistics and graphs over the finished sweeps already in
   `results_routing/`.
2. **Realtime** — PEMs updating live, cycle by cycle, while a simulation runs.

---

## 0. Locked decisions

| Decision | Choice | Consequence |
|---|---|---|
| Where it runs | **Windows laptop**, against the `results_routing/` copy already in this repo | No SSH dependency during the demo. Sim stays on the HPC; CSVs are copied over. |
| Realtime mode | **Replay engine first, live tail as a stretch**, behind one identical contract | Demo defaults to replay of a recorded run; a live run is a toggle, not a dependency. |
| Scope for v1 | **Phases 0–2** | Parser + Offline Analytics + Live/Replay PEM monitor. Topology view and verification tab are Phase 3, optional. |

---

## 1. Why this is mostly a rendering problem

Every number the GUI needs already exists on disk. Nothing in `routing.cc`
changes for Phases 0–2.

| Source | Contents | Screen |
|---|---|---|
| `results_routing/MOBIGUARD_Attack<N>_<pct>[_d<X>ms]_seed<S>.csv` | 52–61 columns, **one row per 1 s routing cycle** | Offline **and** realtime |
| `bc_{anchor,detection,dkg,flowmod,tref,trust_updates}_*.csv` | blockchain event logs | Blockchain panel |
| `crypto_timing_log_*.csv` | per-op wall-clock timings | Crypto overhead panel |
| `tcam_{occupancy,snapshots}_*`, `rsu_density_*`, `lambda_*` | S3/S4 evidence | TCAM panel |
| `fade_results_*`, TAP outputs | B1/B2/B3 external baselines | Baseline comparison |
| `lstm_pipeline/*.json` | per-variant MCC/DR/FPR, M4–M8, BRFA poisoning sweep, mobility-stratified | Federated-LSTM panel |
| `output/**/*.png` (34, git-tracked) | finished thesis figures | Thesis-figures gallery |

### The realtime path already works, with zero code changes

`write_security_metrics_csv()` in `scratch/routing.cc`:

- opens the metrics CSV with `ios::out|ios::app` (line ~117885),
- appends the cycle row,
- **`fout.close()`s it every cycle** (line ~118029).

Every PEM is therefore durably on disk once per simulated second — about every
4 wall-seconds in an `optimized` build (3.93 wall-s/sim-s per `CLAUDE.md`). A
tailing reader sees complete, flushed rows. **No `routing.cc` change is needed
for the live half.**

---

## 2. Architecture

```
gui/
  backend/
    catalog.py    scan results_routing/ -> run index {attack, pct, delay, seed, tag}
    parser.py     schema-aware row decoder  (THE critical piece, see §3)
    aggregate.py  sweep curves + 95% CI across seeds
    live.py       WebSocket: tail a run's CSV, push each new cycle
    replay.py     same WebSocket contract, replays a finished CSV at wall-clock
    app.py        FastAPI app + static mount
  frontend/
    index.html    single page, tabbed
    js/           vanilla ES modules
    vendor/       uPlot + Chart.js VENDORED LOCALLY (see below)
```

**Stack: Python 3.11 (already installed) + FastAPI + uvicorn. Nothing else.**

- No pandas / numpy / scipy. The laptop has none of them installed, and the data
  is tiny (532 files x ~30 rows). Stdlib `csv` and `statistics` cover it.
- 95% CI needs a t-critical value. `scripts/plot_hf_results.py` uses
  `scipy.stats.t`; the GUI uses a **hardcoded two-sided t-table for df 1–30**
  instead. Same numbers, one less dependency. Cross-check the table against the
  existing plot scripts once so the GUI and the thesis figures agree.
- **No chart library at all** (revised at Phase 1b; the plan originally said
  vendor uPlot/Chart.js into `gui/frontend/vendor/`). The charts are hand-rolled
  inline SVG in `gui/frontend/js/charts.js`. Three reasons it came out better:
  no download or vendored bundle to go stale, confidence-interval bands and
  error bars are first-class rather than a Chart.js plugin, and the dataviz mark
  specs (2px strokes, ≥8px markers, a 2px surface ring on overlapping marks,
  recessive grid) are enforced directly instead of fought with. The original
  goal stands either way: **a demo that needs internet to draw a chart is a demo
  that can fail in the room.**

Setup is then exactly: `pip install fastapi uvicorn`, then
`python -m uvicorn gui.backend.app:app`.

Python because everything in `scripts/` and `lstm_pipeline/` is Python, so the
aggregation logic can be checked line-for-line against the existing plot scripts.
No frontend build step because `npm install` failing on demo day scores zero.

---

## 3. Parser specification — the part most likely to silently produce wrong numbers

Five hazards, each verified against the files currently on disk.

### 3.1 Two schema widths, keyed by attack id

The writer inserts 9 TCAM columns mid-row for `active_attack_variant` 2, 3, or -1
— i.e. **attacks 3, 4 and the baseline (Attack0)**:

- Fields 0–20 (21) — `cycle, cur_PDR, avg_PDR, cur_lat_ms, avg_lat_ms, cur_MCC,
  avg_MCC, cur_DR, avg_DR, cur_FPR, avg_FPR, cur_mit_ms, avg_mit_ms, TP, FP, TN,
  FN, cur_TVR, avg_TVR, cur_UCR, avg_UCR`
- **Attacks 3/4/0 only**, 9 fields — `max_tcam_util, avg_tcam_util,
  total_lambda_fm, total_lambda_pi, total_malicious, s3_fired_count,
  s4_fired_count, any_s3, any_s4`
- Remaining 31 fields — `sig_valid_rate, avg_trust_score,
  stark_timing_fail_count, stark_hop_fail_count, flowmod_endorsement_rate,
  rsu_chain_len, global_chain_len, witness_da_count, witness_nfa_count,
  d_obu_count, d_rsu_count, escalation_count, ctrl_failover_max_ms,
  ctrl_failover_events, ctrl_failover_reassigned, o_crypto_bytes_pkt,
  t_batch_ms_avg, batch_B_avg, t_consensus_ms_avg, t_stark_ms_avg, witness_TP_W,
  witness_FP_W, witness_FN_W, WAP_precision, WAP_recall, eps_ref_s,
  avg_eps_ref_s, time_ref_f_bad, ufcr_unauth_total, ufcr_blocked, UFCR`

Totals: **21 + 31 = 52**, or **21 + 9 + 31 = 61**. Measured on disk:
`Attack1_40 -> 52`, `Attack5_40 -> 52`, `Attack3_40 -> 61`. Confirmed.

The parser derives the expected width from the attack id **and asserts it against
the actual field count**, raising on mismatch rather than reading a shifted
column. This is the exact trap `routing.cc`'s own header comment warns about
(positional `COL_TP`/`COL_FP` reads in `run_q1q6_ablation.py`).

### 3.2 Two header formats coexist on disk

Runs before 2026-08-21 wrote a **4-line** header (6 lines for TCAM variants);
newer runs write one line. Both are present in `results_routing/` right now.
So: skip every `#`-prefixed line and index positionally. **Never `csv.DictReader`.**

### 3.3 Space-padded fields

Rows are `1, 66.6667, 24.4179, ...` — strip each field before `float()`.

### 3.4 `ios::app` means one file can hold several runs

Re-running the same config appends to the existing file instead of truncating.
The files on disk today are clean (0 cycle resets, checked), but the parser
**splits a file into runs on a non-increasing cycle index** and surfaces the run
count, rather than assuming one run per file.

### 3.5 Scientific notation

`t_stark_ms_avg` appears as e.g. `9.14657e-05`. Plain `float()` handles it; just
do not regex for digits-and-dot.

---

## 4. Screens (v1 = Phases 0–2)

### Tab 1 — Live PEM Monitor (the realtime half)

- KPI tiles: MCC, DR, FPR, PDR, e2e latency, mitigation latency, avg trust, UFCR.
- Streaming line charts vs cycle, `cur_*` overlaid on `avg_*`.
- A vertical marker at `attack_start_time = 10.0 s` — the EWMA baseline needs
  ~10 s of benign traffic to converge, so the pre/post contrast is the story.
- Detection-event feed derived from per-cycle deltas of `d_obu_count`,
  `d_rsu_count`, `escalation_count`.
- Crypto + blockchain strip: `rsu_chain_len` / `global_chain_len` growing live,
  `flowmod_endorsement_rate`, `sig_valid_rate`.

Replay and live share one WebSocket message shape, so the UI cannot tell them
apart:

```
WS /ws/stream?run_id=<id>&mode=replay|live&speed=<x>
  -> {"cycle": 12, "cols": {"cur_MCC": 0.4509, ...}, "source": "replay"}
```

`mode=replay` reads a finished CSV and emits rows on a timer.
`mode=live` tails a growing CSV via seek-and-poll. Same decoder, same messages.

### Tab 2 — Offline Analytics (the offline half)

- Run picker: attack 1–8 x pct {0,20,40,60,80,100} x seed.
- Metric-vs-attack-% curves with **95% CI across seeds** (method mirrored from
  `scripts/plot_hf_results.py`).
- Confusion matrix from TP/FP/TN/FN, with MCC/DR/FPR **recomputed** from the raw
  counts and compared to the reported columns — same trust model as
  `functional_verification.py` GROUP B. A mismatch is shown, not hidden.
- DR-vs-FPR scatter across variants.
- Per-signature panel: S1–S8 firing counts; S3/S4 from the TCAM columns.
- Panels: TCAM occupancy, blockchain, crypto timing, federated-LSTM (from the
  `lstm_pipeline/*.json` files).
- **Baseline comparison: MOBIGUARD vs TAP (B1) vs FADE (B2/B3)** — the CSVs
  exist, and the side-by-side is what examiners ask for.
- Thesis-figures gallery: the 34 tracked PNGs under `output/`.

---

## 5. API contract

```
GET  /api/catalog                          -> [{id, attack, pct, delay_ms, seed, tag, cycles, runs}]
GET  /api/run/{id}/series?cols=cur_MCC,... -> {cycle: [...], cols: {name: [...]}}
GET  /api/sweep?attack=&metric=&seeds=     -> {pct: [...], mean: [...], ci95: [...], n: [...]}
GET  /api/panels/{blockchain|crypto|tcam|lstm|baselines}
GET  /api/figures                          -> tracked PNGs under output/
WS   /ws/stream?run_id=&mode=&speed=
```

---

## 6. Milestones

| Phase | Deliverable | Depends on |
|---|---|---|
| **0** | **DONE** — `schema.py` + `catalog.py` + `parser.py` + `aggregate.py`, 38 stdlib `unittest` tests green (`python -m unittest gui.tests.test_phase0`). All 48 local CSVs decode; both widths exercised (36 narrow, 12 wide); recomputed MCC/DR/FPR agree with the reported columns to 5.0e-05 | — |
| **1a** | **DONE** — FastAPI read API over Phase 0 (`service.py` + `app.py`), 25 tests. Routes: health/refresh/catalog/metrics/series/summary/sweep/figures. | Phase 0 |
| **1b** | **DONE** — Offline Analytics + Thesis Figures frontend: sweep chart with CI error bars, run detail (KPI tiles, per-cycle trend, confusion matrix + recomputation), figures gallery. Hand-rolled SVG, theme-aware, table view on every chart. | Phase 1a |
| **1c** | *Remaining:* the panels needing their own parsers — blockchain (`bc_*.csv`), crypto timing, TCAM occupancy/snapshots, federated-LSTM (`lstm_pipeline/*.json`), and the B1/B2/B3 baseline comparison. Not blocked; just not built yet. | Phase 1a |
| **2** | Live PEM Monitor. Build `replay.py` first, ship it working, then add `live.py` behind the same contract. | Phase 0 |
| **3** *(optional)* | Topology view (8x8 RSU grid, 4 controllers, RSUs tinted by TCAM occupancy, suspects flashing as signatures fire) + verification/evidence tab rendering the equation-audit and functional-verification logs | needs new per-cycle per-RSU emission in `routing.cc` + an HPC rebuild |

Phase 1 before Phase 2 deliberately: it is the half with no moving parts, so the
demo has something complete even if the realtime work runs late.

---

## 7. Open items

- **Copy discipline.** `results_routing/` is gitignored (`*.csv`), so the laptop
  copy is manual and *is currently a month stale*. `Catalog.newest_modified()`
  surfaces the newest mtime for a staleness banner — build that into Tab 2 so
  the demo cannot silently present old numbers.

  What to pull from the HPC, in priority order:

  | # | What | Why |
  |---|---|---|
  | 1 | `detector_windows_Attack*_*_seed*.csv` from runs with `--enable_detector_windows=1 --simTime>=90` | **The only source of the paper's M1.** None exist locally. Without these the GUI cannot show the thesis detection metric at all. |
  | 2 | `MOBIGUARD_Attack*_*_seed*.csv` for **seeds 2–5** | Turns every `n=1, no CI` into a real error bar. |
  | 3 | Fresh `MOBIGUARD_Attack*` for seed 1 | Current copy predates five detection fixes; also re-checks finding C. |
  | 4 | `bc_*`, `crypto_timing_log_*`, `tcam_*`, `fade_results_*` | Feed the blockchain / crypto / TCAM / baseline panels. Note `bc_detection_log_*` files reach **600 MB** each — copy selectively, or the panel needs a streaming reader rather than a full parse. |

  The metrics-CSV **column set is unchanged** between the stale-results commit
  (`265cf80`, 2026-07-29) and HEAD — 52/61 fields, identical order, nothing
  added or removed, verified programmatically — and `schema.py` matches HEAD
  name-for-name. Only the header *formatting* changed (multi-line to single-line,
  `599fd83`), which the parser already handles. **So fresh results drop straight
  into the Phase 0 data layer with no code change.**
- **Phase 3 gate.** The topology view is the biggest visual payoff and the only
  part needing a `routing.cc` change. Decide after Phase 2 lands whether there is
  time for a rebuild + re-run on the HPC.
- **t-table cross-check.** Verify the hardcoded t-values reproduce a known CI
  from an existing `output/` figure before trusting the GUI's error bars.

### Found during Phase 0

> **The local `results_routing/` copy is stale.** Newest mtime **2026-07-29**,
> which predates the five detection fixes committed through 2026-08-29
> (`b718110`, `3ac7f2a`, `b7c8af1`, `20ede88`, `033210a`). Findings below are
> marked for whether staleness affects them.

**A. The GUI must not plot the metrics CSV's MCC as M1.** *(unaffected by
staleness — this is a convention, not a measurement)*

`docs/WHICH_MCC_TO_REPORT.md` is binding:

> Report `M1` computed per `eq:eval_dedup`: per-RSU, non-overlapping 10 s
> blocks. **Never quote the per-node MCC printed by the simulator as M1.**

`cur_MCC`/`avg_MCC`/`cur_DR`/`avg_DR`/`cur_FPR`/`avg_FPR` in the metrics CSV are
the inline **per-node** confusion matrix (268 nodes, sticky latches, whole-run) —
an implementation artefact the thesis never defines. The paper's M1/DR/FPR come
from `detector_windows.csv` via `metrics/m01_detection_quality.py`. Measured
2026-08-06 on one Q6 config: **0.264 per-node vs ~0.895 per-window.** Not a
rounding difference — a different answer to a different question.

Guarded in code: `schema.DIAGNOSTIC_ONLY_COLUMNS` marks all six, `schema.caveat_for()`
returns the reason, and `Sweep.caveat` carries it into the API response so no
chart can render one of these unlabelled. Streaming `cur_MCC` on the Live tab is
still legitimate — as a **live diagnostic**, labelled as such.

**Consequence: `detector_windows.csv` is required, and no copy exists locally.**
It is gated behind `--enable_detector_windows=1` (default off), needs
`--simTime>=90` (a 30–40 s run yields too few blocks after warm-up), and needs
three filters before scoring: RSU rows only, every *other* window so blocks tile
without overlap, and `w_start >= 30` to drop warm-up. `metrics/` is not in this
repo — it lives in the ns-3 tree — so the GUI reimplements those three filters
over the CSV rather than importing it.

**B. Only seed 1 is present locally.** *(staleness-affected: a fresh copy may
carry more seeds)* All 48 CSVs are seed 1, so every sweep point is `n=1` with
**no confidence interval** — `Estimate.ci95` is `None` and the UI must render
"n=1, no CI" rather than a zero-width error bar implying perfect precision. The
published figures in `output/` do show CIs, so they came from seeds this copy
lacks.

**C. Attacks 1, 3 and 4 have non-monotone / saturating attacker counts.**
  *(staleness-affected — **re-verify against fresh results before raising it
  with the supervisor**. Ground truth is attacker *selection*, which the recent
  fixes should not touch, but `b718110` changed detection attribution and
  `03ed37d` introduced window-level ground truth, so either could move
  `TP+FN`.)*

  Ground-truth positives (`TP+FN` at the final cycle) against attack percentage,
  **measured on the stale 2026-07-29 copy**:

  | atk | 0% | 20% | 40% | 60% | 80% | 100% |
  |---|---|---|---|---|---|---|
  | 1 | 0 | 16 | 32 | **32** | 48 | 64 |
  | 2 | 0 | 52 | 105 | 158 | 211 | 264 |
  | 3 | 0 | 16 | 32 | **32** | 48 | 64 |
  | 4 | 0 | 31 | 36 | **42** | **42** | **42** |
  | 5 | 1 | 14 | 27 | 40 | 53 | 65 |
  | 6 | 0 | 53 | 106 | 158 | 211 | 263 |
  | 7 | 0 | 13 | 26 | 39 | 52 | 64 |
  | 8 | 0 | 53 | 106 | 158 | 211 | 263 |

  Attacks 2, 5–8 scale linearly, as expected. Attacks 1 and 3 (both
  **control-plane** variants) quantise to multiples of 16 — and 64 RSUs / 4
  controllers = 16 RSUs per controller zone, so `round(pct/100 * 64 / 16) * 16`
  reproduces the row exactly, including 60% rounding *down* to the same 2 zones
  as 40%. Attack 4 saturates at 42 from 60% upward.

  Consequence for the GUI: the 40%→60% segment of every attack-1/3 curve is
  **flat by construction**, and attack 4 is flat from 60% on. The 40% and 60%
  CSVs are different files with different per-cycle traces, but identical final
  confusion matrices — so this is not a duplicated-file mistake.

  **This is a simulation-design question, not a GUI bug, and it is not for the
  GUI to paper over.** Whether per-controller-zone quantisation of malicious
  RSUs is intended (and should be stated in `main.tex`) or is an off-by-rounding
  in attacker selection is a question for the supervisor. Until it is settled,
  the GUI plots what the CSVs contain and does not interpolate.

---

## 8. Likely viva questions this GUI invites

- *"Is this actually running, or a recording?"* — Answer honestly and have the
  live toggle ready. The replay/live split is a demo-robustness choice, not a
  claim about the data; both render identical numbers from identical CSVs.
- *"Where does this number come from?"* — Every panel should be traceable to a
  named CSV column. The recompute-and-compare in Tab 2 exists precisely so the
  answer is "from TP/FP/TN/FN, and the GUI re-derives it rather than trusting
  the reported column."
- *"Why does MCC differ from the figure in the thesis?"* — See
  `docs/WHICH_MCC_TO_REPORT.md`; the GUI must use the same choice or state which
  one it is showing.
