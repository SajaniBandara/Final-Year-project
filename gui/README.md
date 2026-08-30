# MOBIGUARD Demo GUI — How to Run It

A local web interface over the simulation's results. Two halves, matching the
brief it was built for:

- **Offline** — statistics and graphs over finished simulation sweeps.
- **Realtime** — performance-evaluation metrics (PEMs) updating cycle by cycle,
  either replayed from a recorded run or tailed live from a running simulation.

Everything runs on your own machine. Nothing is uploaded anywhere, and no
internet connection is needed once installed.

> Design rationale, open questions and known data issues live in
> [`docs/GUI_IMPLEMENTATION_PLAN.md`](../docs/GUI_IMPLEMENTATION_PLAN.md).
> **This file is only how to run it.** If you are about to demo, also read
> [§7 Known limitations](#7-known-limitations-read-before-a-demo) — there are
> things an examiner may ask about.

---

## Contents

1. [Before you start](#1-before-you-start)
2. [Step-by-step: first run](#2-step-by-step-first-run)
3. [Starting it again later](#3-starting-it-again-later)
4. [A guided tour of the seven tabs](#4-a-guided-tour-of-the-seven-tabs)
5. [Running the Live PEM Monitor](#5-running-the-live-pem-monitor)
6. [Running it on the HPC](#6-running-it-on-the-hpc)
7. [Known limitations](#7-known-limitations-read-before-a-demo)
8. [Troubleshooting](#8-troubleshooting)
9. [For developers](#9-for-developers)

---

## 1. Before you start

**You need:**

| | |
|---|---|
| Python | **3.10 or newer** (the code uses `X \| Y` type syntax). Check with `python --version`. |
| A browser | Any modern one — Chrome, Edge, Firefox. |
| Disk | Nothing extra. The GUI only reads files. |

**You do NOT need:** an internet connection (after install), Node.js, npm, a
build step, pandas, numpy, or scipy. The data layer is pure standard library;
only the web server needs two packages.

**Where the data comes from.** The GUI reads simulation output from
`results_routing/` in the repository root. Those CSVs are **not** in git —
they are copied by hand from the HPC. If that folder is missing or empty, the
GUI still starts, but some tabs will be empty. Step 2 below tells you exactly
which.

**Important: run every command from the repository root**, not from inside
`gui/`. That is the folder containing `gui/`, `scratch/`, `docs/`. If you are in
the wrong place you will get `ModuleNotFoundError: No module named 'gui'`.

```powershell
# check you are in the right place - you should see gui, scratch, docs listed
cd D:\UOR\FYP\Final-Year-project
dir
```

---

## 2. Step-by-step: first run

### Step 1 — Install the two packages

```powershell
python -m pip install -r gui/requirements.txt
```

<details><summary>What this installs</summary>

`fastapi` (the web framework), `uvicorn` (the server that runs it), and `httpx`
(used only by the tests). Nothing else.
</details>

You only ever do this once per machine.

### Step 2 — Check your environment

```powershell
python -m gui.backend.preflight
```

This tells you, **before** you start the server, whether each tab has the data
it needs. Run it whenever something looks empty, and always after moving to a
different machine.

Example output:

```
MOBIGUARD demo GUI -- preflight

  [ok]   python                       3.11.9
  [ok]   fastapi                      importable
  [ok]   uvicorn                      importable
  [ok]   results dir                  D:\UOR\FYP\Final-Year-project\results_routing
  [warn] metrics CSVs                 48 runs | attacks [1..8] | seeds [1] | newest 31d old
                                       -> refresh from the HPC
  [warn] confidence intervals         only seed 1 present -- every sweep reads n=1, no CI
                                       -> copy seeds 2-5 from the HPC to get error bars
  [ok]   tab: TCAM Grid               13 occupancy logs
  [ok]   tab: Crypto Overhead         48 timing logs
  [ok]   tab: Federated LSTM          10 variants
  [ok]   tab: Thesis Figures          34 PNGs under output/

Server will start. 5 warning(s) -- those tabs will be empty or incomplete.
```

**How to read it:**

| Marker | Meaning |
|---|---|
| `[ok]` | Fine, nothing to do. |
| `[warn]` | The server will start, but that tab will be empty or incomplete. The `->` line tells you how to fix it. |
| `[FAIL]` | The server **cannot** start. Only two things cause this: the wrong Python version, or `fastapi`/`uvicorn` not installed. Fix these first. |

Warnings are normal and do not block the demo.

### Step 3 — Start the server

```powershell
python -m uvicorn gui.backend.app:app --port 8021
```

You should see:

```
INFO:     Started server process [452]
INFO:     Waiting for application startup.
results copy is 31 days old (newest 2026-07-29...) -- charts may not reflect the current simulator
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8021 (Press CTRL+C to quit)
```

**Leave this window open.** The server runs until you close it. The staleness
line is a warning, not an error.

> Any free port works. `--port 8021` is only a convention used throughout this
> guide; omit it and uvicorn uses 8000.

### Step 4 — Open it in your browser

Go to **<http://127.0.0.1:8021/>**

You should see the MOBIGUARD header with seven tabs and a banner stating how
old the results copy is.

### Step 5 — Stopping it

Press **Ctrl+C** in the terminal window running the server.

---

## 3. Starting it again later

After the first install, it is two commands:

```powershell
cd D:\UOR\FYP\Final-Year-project
python -m uvicorn gui.backend.app:app --port 8021
```

Then open <http://127.0.0.1:8021/>.

**If you copied new results in while the server was running**, you do not need
to restart it — click **Refresh data** in the top-right of the page.

---

## 4. A guided tour of the seven tabs

Suggested demo order. Each section says what to click and what it shows.

### Tab 1 — Offline Analytics

*The "statistics and graphs" half.*

1. In the left panel, pick a **Metric** (e.g. *MCC (average)*).
2. Tick one or more **Attacks** — each keeps its own fixed colour, so
   deselecting one never repaints the others.
3. The top chart plots that metric against attacker percentage.
4. Hover anywhere on the chart for a crosshair and exact values.
5. Click **Show table** to switch to the numbers — every chart has this.
6. Scroll to **Run detail**: KPI tiles, a per-cycle trend with the 10 s attack
   start marked, the confusion matrix, and — worth pointing out — the
   **independent recomputation**, where MCC/DR/FPR are re-derived from the raw
   TP/FP/TN/FN and compared against what the simulator reported.

> Metrics marked **"◦ diagnostic"** are per-node values, not the thesis's M1.
> See [§7](#7-known-limitations-read-before-a-demo).

### Tab 2 — Live PEM Monitor

*The "realtime PEMs" half.* See [§5](#5-running-the-live-pem-monitor) for detail.

1. Pick a **Run**.
2. Leave **Source** on *Replay* and pick a speed (5× is a good demo pace).
3. Click **Start**.

Watch the KPI tiles, the rolling chart and the detection-event feed fill in
cycle by cycle. A badge next to the title always states whether you are seeing
**REPLAY** or **LIVE**.

### Tab 3 — Federated LSTM

The federated anomaly detector. Leads with **Byzantine robustness (M8)**: the
MCC lost to sign-flip poisoning with 25% of RSUs malicious.

Also shows per-variant detection quality, the federated rejection breakdown
(how many RSU updates survived screening), the AB2/AB3 ablations, and MCC by
mobility regime.

> This is the only tab whose data is stored in git, so it is always current and
> works even with no `results_routing/` at all.

### Tab 4 — TCAM Grid

The most visual tab. An 8×8 grid of the RSUs, coloured by how full each one's
TCAM is.

1. Pick an occupancy log — **Attack 3 (pct40)** shows the attack clearly.
2. Drag the **Simulated second** slider, or press **▶ Play**.
3. Watch rules accumulate until cells cross the S4 detection gate — they gain a
   red outline and a ▲ marker.

The chart below plots mean and peak occupancy with the S4 gate drawn on it.

### Tab 5 — Crypto Overhead

Post-quantum cryptography cost (M7): ML-DSA-87 sign and verify, batch
verification, STARK hop proofs, consensus.

Costs span four orders of magnitude, so they are split into two charts rather
than squashed onto one axis. The table states, per operation, what its "ok"
result actually means — they are not all the same thing.

### Tab 6 — Verification

Evidence that the code implements the thesis. Every `eq:` and `alg:` label in
`docs/main.tex` traced to its implementing symbol.

- Failing checks are listed **first**.
- **Re-run audit** re-runs the check live (~15 s). Worth doing in front of an
  examiner.

> It currently reports **3 failures**. That is real — see
> [§7](#7-known-limitations-read-before-a-demo).

### Tab 7 — Thesis Figures

The 34 published figures from `output/`, grouped. Click any to open full size.

---

## 5. Running the Live PEM Monitor

Two sources, one identical message format — the display is the same either way,
and a badge always says which is active.

### Replay (default, recommended for demos)

Emits a **recorded run's real rows** at wall-clock speed. It is not fake data;
it is the actual output of an actual run, played back. Nothing can fail.

Speed multiplier: `1×` = one cycle per second (real time). `5×` or `10×` keeps a
demo moving.

### Live

Tails the CSV as ns-3 writes to it. For this to work, **the GUI must be able to
see the file the simulator is writing** — in practice that means running the GUI
on the same machine as the simulation (see [§6](#6-running-it-on-the-hpc)).

1. Set **Source** to *Live*.
2. Click **Start**. If the simulation has not started yet, it waits for the file
   to appear.
3. Rows arrive once per simulated second — roughly every 4 seconds of real time
   in an optimised build.

If nothing arrives, nothing is writing to that file from this machine's point of
view. Check the path with `python -m gui.backend.preflight`.

---

## 6. Running it on the HPC

The simulation runs on the HPC; the GUI only reads files. The simplest
arrangement is to run the GUI **there** and view it in your **local** browser
through an SSH tunnel.

### On the HPC

```bash
cd ~/path/to/Final-Year-project

# point it at the live results directory
export MOBIGUARD_RESULTS_DIR=~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing

python -m pip install -r gui/requirements.txt   # first time only
python -m gui.backend.preflight
python -m uvicorn gui.backend.app:app --port 8021
```

### On your laptop, in a second terminal

```bash
ssh -L 8021:localhost:8021 <user>@<hpc-host>
```

Leave that open, then browse to <http://127.0.0.1:8021/>.

**Notes:**

- Keep the default loopback binding. Do **not** use `--host 0.0.0.0` on a shared
  machine — the SSH tunnel is what makes it reachable, safely.
- If `pip install` is blocked, use a virtual environment
  (`python -m venv .venv && . .venv/bin/activate`) or `pip install --user`.
- Live mode works properly in this arrangement, because the GUI can now see the
  files ns-3 is writing.

### Pointing at a different results folder locally

```powershell
# Windows PowerShell
$env:MOBIGUARD_RESULTS_DIR = "D:\path\to\results_routing"
```

```bash
# Linux / macOS
export MOBIGUARD_RESULTS_DIR=/path/to/results_routing
```

---

## 7. Known limitations (read before a demo)

These are real and an examiner may notice them. Better to know now.

| What you will see | Why |
|---|---|
| **"Results copy is 31 days old"** in the banner | `results_routing/` is copied from the HPC by hand and has not been refreshed. The banner is deliberate — a stale copy renders identically to a fresh one. |
| **Every sweep says "n=1, no CI"** | Only seed 1 has been copied across. Confidence intervals need seeds 2–5. Shown as "n=1" rather than a zero-width error bar, which would falsely imply perfect precision. |
| **MCC/DR/FPR marked "◦ diagnostic"** | These are the simulator's inline **per-node** values. The thesis's M1 is per-RSU over non-overlapping 10 s blocks, computed from `detector_windows.csv` — which has not been generated yet, so the GUI cannot show it. See `docs/WHICH_MCC_TO_REPORT.md`. |
| **Verification tab shows 3 failures** | Genuine. The paper says the S1 EWMA factor β is 0.8, the code uses 0.95; and five thesis labels have no audit entry. Not a GUI bug. |
| **Attack 1 and 3 curves are flat between 40% and 60%** | The number of attackers is identical at those two points in the current data, so the metric genuinely does not change. |
| **Baseline comparison (TAP / SFTO / eFADE) is missing** | Not built: TAP produced no local output and all eFADE result files are empty. |

To clear the first three, copy from the HPC: fresh CSVs, seeds 2–5, and
`detector_windows_*.csv` from a run with `--enable_detector_windows=1
--simTime=90`.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'gui'` | You are in the wrong folder. `cd` to the repository root (the one containing `gui/`), not into `gui/`. |
| `No module named uvicorn` | Run step 1: `python -m pip install -r gui/requirements.txt`. |
| `ERROR: [Errno 10048] address already in use` | Something is already on that port — an old server. Close it, or use `--port 8022`. |
| Page won't load / "can't reach this site" | The server window is closed or errored. Check it is still running and the port matches the URL. |
| `503 results directory not found` | `results_routing/` is missing. Copy the CSVs, or set `MOBIGUARD_RESULTS_DIR`. |
| Run picker is empty | The folder exists but holds no `MOBIGUARD_Attack*.csv`. |
| A tab is blank | Run `python -m gui.backend.preflight` — it names the missing files and the command that produces them. |
| Live mode receives nothing | Nothing is appending to that CSV from this machine's view. Run the GUI on the machine running ns-3. |
| Charts look wrong after copying new files | Click **Refresh data** (top right). |
| Everything is unreadable / wrong colours | Click **Theme** to toggle light/dark. |

---

## 9. For developers

```bash
python -m unittest discover -s gui/tests -t .    # 158 tests, stdlib unittest
python -m uvicorn gui.backend.app:app --reload   # auto-reload while editing
```

`/docs` on the running server gives the generated OpenAPI reference for every
endpoint.

```
gui/
  backend/
    schema.py       metrics-CSV field layout, keyed by attack id
    parser.py       schema-aware decoder (also drives replay and live tail)
    catalog.py      filesystem index of results_routing/
    aggregate.py    sweep curves, 95% CI, confusion recomputation
    stream.py       ReplaySource + TailSource, one message contract
    crypto.py       tcam.py   lstm.py   verification.py   panel data sources
    service.py      application logic, HTTP-agnostic and directly testable
    app.py          FastAPI routes + static mount
    preflight.py    environment check
  frontend/
    index.html      single page
    css/app.css     design tokens, light + dark
    js/             vanilla ES modules, no build step
  tests/
```

Two conventions to preserve if you extend this:

- **The metrics CSV has two row widths.** Attacks 3, 4 and the baseline carry
  nine extra TCAM fields inserted *mid-row*. `schema.py` owns the layout and the
  parser asserts the width rather than reading a shifted column.
- **`cur_MCC`/`avg_MCC` and their DR/FPR siblings are per-node diagnostics, not
  the thesis metric.** Anything plotting those six columns carries a caveat
  automatically via `schema.DIAGNOSTIC_ONLY_COLUMNS`. Do not remove it.
