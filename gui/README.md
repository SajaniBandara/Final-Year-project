# MOBIGUARD Demo GUI

A local web UI over the simulation's results: offline statistics and graphs, and
performance-evaluation metrics (PEMs) streaming during a run.

Design rationale and open findings live in
[`docs/GUI_IMPLEMENTATION_PLAN.md`](../docs/GUI_IMPLEMENTATION_PLAN.md). This
file is how to run it.

---

## Quick start

```bash
python -m pip install -r gui/requirements.txt
python -m gui.backend.preflight          # what's present, what will be empty
python -m uvicorn gui.backend.app:app    # then open http://127.0.0.1:8000/
```

Run all three from the **repository root** (`gui` must be importable as a
package). `/docs` serves the generated OpenAPI reference.

Requires Python 3.10+ (the backend uses `X | Y` unions). Only `fastapi` and
`uvicorn` are needed — the whole data layer is standard library, so there is no
pandas/numpy/scipy to install and no frontend build step.

### Preflight

Run it first, and again after moving machines. Every tab is fed by a different
family of files and each can be independently absent; without this, missing data
shows up as an empty panel mid-demo with no indication of why.

```
  [ok]   fastapi                      importable
  [warn] metrics CSVs                 48 runs | attacks [1..8] | seeds [1] | newest 31d old
                                       -> refresh from the HPC
  [warn] confidence intervals         only seed 1 present -- every sweep reads n=1, no CI
                                       -> copy seeds 2-5 from the HPC to get error bars
  [ok]   tab: TCAM Grid               13 occupancy logs
```

Exit status is 0 when the server can start with at least one populated panel, so
it works as a gate in a script.

---

## The tabs

| Tab | Shows | Fed by |
|---|---|---|
| **Offline Analytics** | Metric-vs-attacker-% sweeps with 95% CI, run detail, KPI tiles, confusion matrix and its independent recomputation | `MOBIGUARD_Attack*_*_seed*.csv` |
| **Live PEM Monitor** | KPI tiles, rolling chart, detection-event feed, integrity strip — replayed or tailed live | the same CSVs, streamed |
| **Federated LSTM** | Per-variant detection quality, BRFA-v2 poisoning (M8), federated rejections, AB2/AB3, mobility heatmap | `lstm_pipeline/*.json` (**git-tracked**) |
| **TCAM Grid** | Animated 8×8 RSU occupancy with the S4 gate marked | `tcam_occupancy_*.csv` |
| **Crypto Overhead** | Per-operation wall-clock cost (M7), faceted by magnitude | `crypto_timing_log_*.csv` |
| **Verification** | Equation audit — every `eq:`/`alg:` in `main.tex` traced to code, with a live re-run button | `scripts/audit_equations.py` |
| **Thesis Figures** | The committed plots | `output/**/*.png` |

The Federated LSTM tab is the only one independent of `results_routing/`; its
JSONs are tracked in git, so it works in a fresh clone.

---

## Pointing it at a different results directory

`results_routing/` is gitignored, so the copy beside this repo is refreshed by
hand. Override the location with an environment variable:

```bash
# Linux / macOS
export MOBIGUARD_RESULTS_DIR=~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing

# Windows PowerShell
$env:MOBIGUARD_RESULTS_DIR = "D:\path\to\results_routing"
```

The header banner always states how old the newest file is. A month-old copy
renders exactly like a fresh one, so the age is on screen rather than assumed.
**Refresh data** in the top bar re-scans without a restart.

---

## Running on the HPC

The GUI is read-only over the filesystem, so the simplest arrangement is to run
it next to the results and forward the port to your laptop's browser.

```bash
# on the HPC
cd ~/path/to/Final-Year-project
export MOBIGUARD_RESULTS_DIR=~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing
python -m gui.backend.preflight
python -m uvicorn gui.backend.app:app --port 8021

# from the laptop, in a second terminal
ssh -L 8021:localhost:8021 <user>@<hpc-host>
# then open http://127.0.0.1:8021/
```

If `pip install` is unavailable there, use a virtualenv
(`python -m venv .venv && . .venv/bin/activate`) or `pip install --user`. Only
`fastapi` and `uvicorn` are needed; if neither can be installed, the data layer
(`gui.backend.parser`, `catalog`, `aggregate`, `crypto`, `tcam`, `lstm`) is
still importable from a plain Python shell, because it has no third-party
dependencies.

Do not bind to `0.0.0.0` on a shared machine — the default is loopback only, and
the SSH tunnel is what makes it reachable.

---

## Live mode

The Live PEM Monitor has two sources behind one message contract, so the UI
renders them identically and a badge states which is active:

- **Replay** — emits a recorded run's real rows at wall-clock speed. The demo
  default: nothing to go wrong.
- **Live** — tails the CSV as ns-3 appends to it. Needs the simulator writing to
  a path this process can see, so run the GUI on the HPC (above).

Live tailing needs no change to `routing.cc`: `write_security_metrics_csv()`
closes the file every cycle, so each row is flushed once per simulated second.

---

## Development

```bash
python -m unittest discover -s gui/tests -t .   # 146 tests, stdlib unittest
python -m uvicorn gui.backend.app:app --reload
```

```
gui/
  backend/
    schema.py       metrics-CSV field layout, keyed by attack id
    parser.py       schema-aware decoder (also drives replay and live tail)
    catalog.py      filesystem index of results_routing/
    aggregate.py    sweep curves, 95% CI, confusion recomputation
    stream.py       ReplaySource + TailSource
    crypto.py  tcam.py  lstm.py  verification.py    panel data sources
    service.py      application logic, HTTP-agnostic
    app.py          FastAPI routes + static mount
    preflight.py    environment check
  frontend/         single page, vanilla ES modules, no build step
  tests/
```

Two conventions worth keeping if you extend this:

- **The metrics CSV has two row widths.** Attacks 3, 4 and the baseline carry
  nine extra TCAM fields inserted *mid-row*. `schema.py` owns the layout and the
  parser asserts the width rather than reading a shifted column.
- **`cur_MCC`/`avg_MCC` and their DR/FPR siblings are per-node diagnostics, not
  the thesis metric.** Per `docs/WHICH_MCC_TO_REPORT.md` the paper's M1 is
  per-RSU over non-overlapping 10 s blocks from `detector_windows.csv`. Anything
  plotting those six columns carries a caveat automatically
  (`schema.DIAGNOSTIC_ONLY_COLUMNS`); don't remove it.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `503 results directory not found` | `results_routing/` missing — set `MOBIGUARD_RESULTS_DIR`. |
| Run picker empty | Directory exists but holds no `MOBIGUARD_Attack*.csv`. |
| Every sweep says `n=1, no CI` | Only one seed present. Copy seeds 2–5. |
| Verification tab reports failures | Genuine — the equation audit does not currently pass. See the plan, §7 finding E. |
| Live mode never receives a cycle | Nothing is appending to that CSV from this machine's view. |
| `ModuleNotFoundError: gui` | Run from the repository root, not from `gui/`. |
