# MOBIGUARD — Final Year Project Simulation

MOBIGUARD is a mobility-aware, zero-trust SDVN (Software-Defined Vehicular Network) security framework simulated in NS-3.35. It models 200 vehicles, 64 RSUs (8×8 grid), and 4 distributed SDVN controllers across a ~2061 m × 2137 m urban area (Los Angeles), and implements 8 attack variants across two attack families — Selective Time Delay and Hidden Forwarding — alongside their corresponding MOBIGUARD detection signatures.

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Requirements](#2-requirements)
3. [Quick Start](#3-quick-start)
4. [SUMO Mobility Trace Generation](#4-sumo-mobility-trace-generation)
5. [Building the Simulation](#5-building-the-simulation)
6. [Running Experiments](#6-running-experiments)
7. [Attack Variants](#7-attack-variants)
8. [Detection Signatures](#8-detection-signatures)
9. [Result Files](#9-result-files)
10. [CLI Reference](#10-cli-reference)
11. [Node Architecture](#11-node-architecture)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Project Structure

```
Final-Year-project/
├── routing.cc                  # Main NS-3 simulation — routing, attacks, SUMO integration
├── attack_variables.h          # Global attack state (delay value, malicious node arrays)
├── attack_declaration.h        # Attack arming — declare_attack_states(), declare_attackers()
├── selective_time_delay.h      # Delay injection logic for CP (Attack 1) and DP (Attack 2)
├── s1_detection.h              # MOBIGUARD Signature S1 — mobility-adjusted EWMA detector
├── s2_detection.h              # MOBIGUARD Signature S2 — hop-delay threshold detector
├── tap_detection.h             # TAP baseline detector (Attack 2 only)
├── tcam_detection.h            # MOBIGUARD Signatures S3/S4 — TCAM exhaustion detector
├── tcam_attack_helper.h        # TCAM attack injection helpers (Attacks 3 & 4)
├── efade_detection.h           # eFADE detector (Attacks 5–8, Hidden Forwarding)
├── hf_attack_helper.h          # Hidden Forwarding attack helpers (Attacks 5–8)
├── optimization.py             # Link-lifetime route optimization helper
├── optimization_lifetime.py    # Per-run lifetime optimization (reads tagged CSV from NS-3)
├── scripts/
│   ├── run_std_attacks.py      # Parallel experiment launcher — main entry point
│   └── run_attack2_sweep.sh    # Legacy shell sweep (superseded by run_std_attacks.py)
├── mobility/                   # SUMO-exported NS-2 mobility traces (.tcl files)
├── sumo_sim/                   # SUMO scenario folders (net, trips, sumocfg)
├── logs/                       # Per-run simulation logs (auto-created by launcher)
├── docs/
│   └── main (10).tex           # Thesis document
└── output/
    └── tap/                    # TAP result plots
```

---

## 2. Requirements

| Dependency | Version | Notes |
|---|---|---|
| Ubuntu | 20.04+ | or equivalent Linux |
| NS-3 | 3.35 | installed at `~/ns-allinone-3.35/` |
| NetAnim | 3.109 | bundled with ns-allinone |
| SUMO | any recent | `sudo apt install sumo sumo-tools` |
| Python | 3.8+ | for launcher and optimization scripts |

---

## 3. Quick Start

If you already have a mobility trace (`mobility_urban_150.tcl`) and NS-3 is installed, the fastest way to run both attack variants across all six percentages in parallel:

```bash
# Sync project files to NS-3 scratch, build, then run all 12 combinations
python3 scripts/run_std_attacks.py --build

# Results appear in:
#   ~/ns-allinone-3.35/ns-3.35/results_routing/MOBIGUARD_Attack1_<pct>_d80ms.csv
#   ~/ns-allinone-3.35/ns-3.35/results_routing/MOBIGUARD_Attack2_<pct>_d80ms.csv
#   ~/ns-allinone-3.35/ns-3.35/results_routing/TAP_Attack2_<pct>_d80ms.csv
#   logs/A<N>_pct<P>_d80ms_seed1.log
```

---

## 4. SUMO Mobility Trace Generation

The SUMO workflow produces a `.tcl` mobility file that NS-3 reads via `Ns2MobilityHelper`. Skip this section if `mobility/mobility_urban_150.tcl` already exists.

### Step 4.1 — Generate the road network

```bash
python3 $SUMO_HOME/tools/osmWebWizard.py
```

In the browser UI:
- Navigate to a dense urban area (~2061 m × 2137 m, e.g. Los Angeles)
- Enable vehicle types: **Passenger** and **Truck**
- Set **Duration** to `600` seconds
- Click **Generate Scenario**

A timestamped folder (e.g. `sumo_sim/2026-06-17-06-41-46/`) is created.

### Step 4.2 — Verify network dimensions

```bash
cd sumo_sim/<timestamp>/
gunzip -k osm.net.xml.gz
grep -o '<location[^>]*>' osm.net.xml
```

Confirm `convBoundary` spans approximately 2061 m × 2137 m.

### Step 4.3 — Generate trip files (200 vehicles total)

```bash
cd sumo_sim/<timestamp>/

# 100 cars
python3 $SUMO_HOME/tools/randomTrips.py -n osm.net.xml -o trips_car.trips.xml \
  --vehicle-class passenger -b 0 -e 30 --period 0.3 \
  --min-distance 1000 --random-factor 20 --random-routing-factor 25 --random --seed 11111

# 25 buses
python3 $SUMO_HOME/tools/randomTrips.py -n osm.net.xml -o trips_bus.trips.xml \
  --vehicle-class bus -b 0 -e 28.9 --period 1.2 \
  --min-distance 1000 --random-factor 20 --random-routing-factor 25 --random --seed 22222

# 25 lorries
python3 $SUMO_HOME/tools/randomTrips.py -n osm.net.xml -o trips_lorry.trips.xml \
  --vehicle-class truck -b 0 -e 28.9 --period 1.2 \
  --min-distance 1000 --random-factor 20 --random-routing-factor 25 --random --seed 33333

# 25 vans
python3 $SUMO_HOME/tools/randomTrips.py -n osm.net.xml -o trips_van.trips.xml \
  --vehicle-class delivery -b 0 -e 28.9 --period 1.2 \
  --min-distance 1000 --random-factor 20 --random-routing-factor 25 --random --seed 44444

# 25 trucks
python3 $SUMO_HOME/tools/randomTrips.py -n osm.net.xml -o trips_truck.trips.xml \
  --vehicle-class trailer -b 0 -e 28.9 --period 1.2 \
  --min-distance 1000 --random-factor 20 --random-routing-factor 25 --random --seed 55555
```

### Step 4.4 — Set maxSpeed and run SUMO

```bash
# Set max speed to 41.67 m/s (150 km/h) in all trip files
for f in trips_car.trips.xml trips_bus.trips.xml trips_lorry.trips.xml trips_van.trips.xml trips_truck.trips.xml; do
  sed -i '/<vType /s/\/>/maxSpeed="41.67"\/>/' "$f"
done

# Verify 200 vehicles inserted, zero stuck, zero teleports
sumo -c osm.sumocfg 2>&1 | tee sumo_run.log
grep "Inserted\|Waiting\|Teleporting" sumo_run.log
```

### Step 4.5 — Export mobility trace and back up

```bash
# Export NS-2 compatible trace (adjust timestamps to start from 0)
python3 $SUMO_HOME/tools/traceExporter.py \
  --fcd-input fcd_output.xml --ns2mobility-output mobility_urban_150.tcl

# Copy to the locations NS-3 and the project repo both expect
cp mobility_urban_150.tcl /home/user/mobility/
cp mobility_urban_150.tcl "/home/user/Final Year Project/1. Attacks/Final-Year-project/mobility/"
```

Verify the trace:

```bash
# Should show 200 unique nodes (IDs 0–199)
grep -o '\$node_([0-9]*)' /home/user/mobility/mobility_urban_150.tcl | sort -u | wc -l

# Should span t=0.0 to t≈599.0
grep -o '\$ns_ at [0-9.]*' /home/user/mobility/mobility_urban_150.tcl \
  | awk '{print $3}' | sort -n | tail -1
```

---

## 5. Building the Simulation

The `--build` flag on the launcher handles syncing and building in one step:

```bash
python3 scripts/run_std_attacks.py --build
```

What this does internally:
1. Copies all source files from the project directory to `~/ns-allinone-3.35/ns-3.35/scratch/`
2. Runs `./waf build`

**Files synced to scratch on every `--build`:**

| File | Role |
|---|---|
| `routing.cc` | Main simulation |
| `attack_declaration.h` | Attack arming |
| `attack_variables.h` | Attack state globals |
| `selective_time_delay.h` | Delay injection |
| `s1_detection.h` | Signature S1 detector |
| `s2_detection.h` | Signature S2 detector |
| `tap_detection.h` | TAP baseline detector |
| `tcam_detection.h` | Signatures S3/S4 detector |
| `tcam_attack_helper.h` | TCAM attack helpers |
| `efade_detection.h` | eFADE detector |
| `hf_attack_helper.h` | Hidden Forwarding helpers |
| `optimization_lifetime.py` | Optimization script (per-run tagged) |
| `optimization.py` | Optimization helper |

To build manually without the launcher:

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf build 2>&1 | grep -i error
```

---

## 6. Running Experiments

All experiments are driven by `scripts/run_std_attacks.py`, which launches NS-3 simulations in parallel using a `ThreadPoolExecutor`.

### 6.1 — Standard sweep (both attacks, all 6 percentages)

```bash
python3 scripts/run_std_attacks.py --delay 80
```

Runs 12 simulations concurrently: Attack 1 and Attack 2 × {0, 20, 40, 60, 80, 100}% with an 80 ms attack delay. Result files are tagged `_d80ms`.

> **Tag behaviour:** For Attacks 1 and 2, the `_d<X>ms` tag **always appears** in result filenames — even without `--delay` — because `attack_delay_ms` defaults to 80 ms. Passing `--delay 60` changes the tag to `_d60ms` and also changes the injected delay. For Attacks 3–8 (TCAM, Hidden Forwarding), the tag never appears and `--delay` has no effect on filenames or behaviour.

### 6.2 — Rebuild then run

```bash
python3 scripts/run_std_attacks.py --build --delay 80
```

### 6.3 — Single attack or percentage

```bash
# Attack 1 (CP) only, at 40%, explicit delay
python3 scripts/run_std_attacks.py --attack 1 --percentage 40 --delay 80

# Attack 2 (DP) only, at 40%, explicit delay
python3 scripts/run_std_attacks.py --attack 2 --percentage 40 --delay 80

# Attack 1 only, all percentages
python3 scripts/run_std_attacks.py --attack 1 --delay 80

# Attack 2 only, all percentages
python3 scripts/run_std_attacks.py --attack 2 --delay 80
```

### 6.4 — Delay sweep (treat delay as independent variable)

Attack delay (default 80 ms) can be treated as an independent variable to validate the S1/S2 detection thresholds. Each delay value produces its own set of result CSVs tagged `_d<X>ms`.

```bash
# Sweep specific delay values
python3 scripts/run_std_attacks.py --delay 40 50 55 60 80 100 150 200

# Shorthand for the full default sweep set
python3 scripts/run_std_attacks.py --delay-sweep
```

> **Design note:** The original implementation drew delays from Uniform(50–300 ms), the handoff jitter window at highway speeds (50–300 ms, thesis §1322). The fixed `--attack_delay_ms` parameter replaces this so runs are fully reproducible and comparable across seeds. Default 80 ms > S2 Δ_max = 50 ms, so Signature S2 fires by default. Sweep below 50 ms to probe the detection boundary.

### 6.5 — Seed / reproducibility control

```bash
# Run with a specific RNG seed (thesis requires 5 seeds: 1–5)
python3 scripts/run_std_attacks.py --seed 2 --delay 80

# Full 5-seed thesis sweep
for s in 1 2 3 4 5; do
  python3 scripts/run_std_attacks.py --seed $s --sim-time 300 --delay 80
done
```

### 6.6 — Longer production runs

```bash
# 300 s data window (thesis requirement) with clean output directory
python3 scripts/run_std_attacks.py --build --clean --sim-time 300 --delay 80
```

### 6.7 — Running a single variant directly via waf

**Attack 1 — Control Plane (CP) Selective Time Delay:**

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf --run "scratch/routing \
  --routing_test=false \
  --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 \
  --simTime=40 --architecture=3 \
  --attack_number=1 \
  --attack_percentage=40 \
  --attack_delay_ms=80"
```

**Attack 2 — Data Plane (DP) Selective Time Delay:**

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf --run "scratch/routing \
  --routing_test=false \
  --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 \
  --simTime=40 --architecture=3 \
  --attack_number=2 \
  --attack_percentage=40 \
  --attack_delay_ms=80"
```

> `--attack_delay_ms` applies to both attacks and is the only delay parameter. The suffix `_d80ms` will be appended to all result CSVs for that run.

---

## 7. Attack Variants

### Attack family 1 — Selective Time Delay

| `--attack_number` | `active_attack_variant` | Plane | Mechanism |
|---|---|---|---|
| 1 | 0 | Control Plane (CP) | Compromised controller installs poisoned FlowMod rules on RSUs; RSUs (unaware) forward safety-critical packets with an injected delay |
| 2 | 1 | Data Plane (DP) | Malicious vehicle or RSU intercepts and buffers safety-critical packets before forwarding |
| 3 | 2 | Control Plane | TCAM exhaustion via controller-injected bogus flow rules, forcing the slow path |
| 4 | 3 | Data Plane | TCAM exhaustion via attacker vehicle sending unique 5-tuple streams |

**Common to both Attack 1 and Attack 2:**
- Only **safety-critical** (high-priority) packets are delayed; best-effort traffic is passed immediately. This selective behaviour is the distinguishing signature vs. generic congestion.
- Attack arms at `attack_start_time` (default 10 s) to allow a 10-second benign baseline window for Signature S1's EWMA to converge before any attack packets appear.
- Delay is a single deterministic value (`--attack_delay_ms`, default 80 ms) shared by both attacks.

### Attack family 2 — Hidden Forwarding

| `--attack_number` | `active_attack_variant` | Plane | Mechanism |
|---|---|---|---|
| 5 | 4 | Control Plane (Active) | Compromised controller installs rules that duplicate and fabricate packet content to an unauthorized destination |
| 6 | 5 | Data Plane (Active) | Malicious RSU/vehicle forwards original packet and sends a content-modified duplicate to an eavesdropper |
| 7 | 6 | Control Plane (Passive) | Compromised controller silently duplicates packets to an unauthorized listener |
| 8 | 7 | Data Plane (Passive) | Malicious node duplicates packets to an eavesdropper without modifying content |

---

## 8. Detection Signatures

### MOBIGUARD Signatures (S1 & S2) — Selective Time Delay

**Signature S1 — Control Plane (Attack 1)**

Fires when a safety-critical packet's per-hop forwarding delay at RSU *r* exceeds the mobility-adjusted baseline by *k* standard deviations:

```
δ_p(v,r,t) > δ̄_r(t) + k·σ_r(t)  ∧  Priority(p) = HIGH
```

Where the mobility-adjusted baseline is:

```
δ̄_r(t) = δ₀ + α_ρ·ρ(t) + α_v·v̄(t)⁻¹
```

- `ρ(t)` — vehicle density in RSU zone (from live link-lifetime matrix)
- `v̄(t)` — mean vehicle speed in RSU zone
- `σ²_r(t)` — EWMA variance: `β·σ²(t-1) + (1-β)·(δ_r(t) − δ̄_r(t))²`
- Parameters configurable via CLI: `--s1_alpha_rho`, `--s1_alpha_v`, `--s1_k`, `--s1_beta`

> **Note:** Current parameter values (δ₀=2ms, α_ρ=0.0001, α_v=0.05, k=3, β=0.9) are initial candidates pending calibration against benign SUMO traces (least-squares regression for δ₀/α_ρ/α_v; grid-search for k/β).

**Signature S2 — Data Plane (Attack 2)**

Fires when the inter-node hop delay exceeds the fixed threshold Δ_max:

```
t_recv_{u+1} − t_fwd_u > Δ_max  ∧  π_delay(u) = ⊥
```

- `Δ_max = 50 ms` (configurable via `S2_DELTA_MAX` in `s2_detection.h`)
- `t_fwd_u` is the **claimed** forwarding timestamp — set at receipt time before any attack buffering, so a malicious node cannot hide buffering delay
- The ZKP conjunction `π_delay(u) = ⊥` is simulated as a deterministic proxy (a node that buffered beyond Δ_max cannot produce a valid STARK timing proof)

### TAP Baseline Detector (Attack 2 only)

Implements the Timing Attack Prevention (TAP) protocol from Arsalan & Rehman (FIT 2018). Computes the expected signal propagation time from sender to receiver using physical distance, and flags nodes whose claimed forwarding timestamp deviates from the physics-derived expectation beyond `TAP_MARGIN`.

> TAP is **only active for Attack 2** (`active_attack_variant == 1`). It is not applicable to Attack 1 (CP) because the threat model is a compromised controller, not a delaying vehicle, and TAP's signal-propagation model cannot observe the control plane.

### MOBIGUARD Signatures S3/S4 — TCAM Exhaustion (Attacks 3 & 4)

Active only for `active_attack_variant ∈ {2, 3}`. Metrics are appended as extra columns in the MOBIGUARD CSV for those variants and are absent for Attacks 1 and 2.

---

## 9. Result Files

All result CSVs are written to `~/ns-allinone-3.35/ns-3.35/results_routing/`.

### Filename convention

```
MOBIGUARD_Attack<N>_<pct>_d<delay>ms.csv   — MOBIGUARD S1/S2 metrics
TAP_Attack<N>_<pct>_d<delay>ms.csv         — TAP baseline metrics
FADE_Attack<N>_<pct>_d<delay>ms.csv        — eFADE forwarding metrics
```

Example: `MOBIGUARD_Attack2_40_d80ms.csv` — Attack 2, 40% intensity, 80 ms delay.

### MOBIGUARD / TAP CSV columns

```
cycle, cur_PDR%, avg_PDR%, cur_lat_ms, avg_lat_ms,
cur_MCC, avg_MCC, cur_DR%, avg_DR%, cur_FPR%, avg_FPR%,
cur_mit_ms, avg_mit_ms, TP, FP, TN, FN
```

Attacks 3 & 4 append additional TCAM columns:
```
max_tcam_util, avg_tcam_util, total_lambda_fm, total_lambda_pi,
total_malicious, s3_fired_count, s4_fired_count, any_s3, any_s4
```

### Per-run logs

```
logs/A<attack>_pct<percentage>_d<delay>ms_seed<seed>.log
```

Each log begins with:
```
[ATTACK DELAY] Configured delay = 80 ms  |  original random range (CP & DP): 50–300 ms  |  S2 delta_max threshold = 50 ms  |  above S2 threshold: YES (S2 should fire)
```

---

## 10. CLI Reference

Pass any flag as `--flag=value` inside `./waf --run "scratch/routing ..."`.

### Topology

| Flag | Default | Description |
|---|---|---|
| `N_Vehicles` | 200 | Number of vehicle nodes |
| `N_RSUs` | 64 | Number of RSU nodes (8×8 grid, 260m × 270m spacing) |
| `N_Controllers` | 4 | Number of SDVN controllers (2×2 grid, center of quadrants) |
| `architecture` | 3 | 1=DSRC only, 3=SDVN (DSRC + controller) |
| `routing_test` | false | true=small synthetic test network, false=SUMO network |

### Mobility

| Flag | Default | Description |
|---|---|---|
| `use_sumo_mobility` | 1 | 1=load SUMO `.tcl` trace, 0=synthetic mobility |
| `mobility_scenario` | 0 | 0=urban, 1=non-urban, 2=highway |
| `maxspeed` | 150 | Selects trace file `mobility_urban_<maxspeed>.tcl` |

### Simulation

| Flag | Default | Description |
|---|---|---|
| `simTime` | 40 | Total simulation duration in seconds (use 300 for thesis production runs) |
| `sim_seed` | 1 | NS-3 RNG seed — same seed guarantees identical run; sweep {1,2,3,4,5} per thesis |
| `sim_run` | 1 | NS-3 RNG run index (secondary seed dimension) |
| `data_transmission_frequency` | 1.0 | Routing cycles per second — do not change |

### Attacks

| Flag | Default | Description |
|---|---|---|
| `attack_number` | 1 | Primary attack selector: 1=CP Delay, 2=DP Delay, 3=TCAM-CP, 4=TCAM-DP, 5–8=HF variants |
| `active_attack_variant` | -1 | Legacy direct selector (-1=baseline, 0–7=attack variants). Superseded by `attack_number` for new runs |
| `attack_percentage` | 0 | Attacker proportion 0–100%. 0=baseline (no attack) |
| `attack_delay_ms` | 80.0 | Fixed attack delay in ms for both CP and DP attacks. Original range was Uniform(50–300 ms). Only meaningful for `attack_number` 1 or 2 |
| `attack_start_time` | 10.0 | Seconds before the attack arms. 10 s gives S1's EWMA time to converge on a benign baseline |
| `attack_rate_pps` | 20.0 | TCAM slow-flow injection rate in pkt/s (Attacks 3 & 4) |
| `num_attackers` | 1 | Number of attacker vehicles for Attack 4 |

### Detection tuning (S1)

| Flag | Default | Description |
|---|---|---|
| `s1_alpha_rho` | 0.0001 | S1: density sensitivity α_ρ (s/vehicle) |
| `s1_alpha_v` | 0.05 | S1: speed sensitivity α_v (s²/m) |
| `s1_k` | 3.0 | S1: std-dev multiplier k |
| `s1_beta` | 0.9 | S1: EWMA forgetting factor β ∈ (0,1) |

### Attack variant index (for reference)

| `active_attack_variant` | `attack_number` | Description |
|---|---|---|
| -1 | — | Baseline (no attack) |
| 0 | 1 | Selective Time Delay — Control Plane |
| 1 | 2 | Selective Time Delay — Data Plane |
| 2 | 3 | TCAM Exhaustion — Control Plane |
| 3 | 4 | TCAM Exhaustion — Data Plane |
| 4 | 5 | Active Hidden Forwarding — Control Plane |
| 5 | 6 | Active Hidden Forwarding — Data Plane |
| 6 | 7 | Passive Hidden Forwarding — Control Plane |
| 7 | 8 | Passive Hidden Forwarding — Data Plane |

---

## 11. Node Architecture

With `N_Vehicles=200`, `N_RSUs=64`, `N_Controllers=4`, global NS-3 node IDs are assigned as follows:

| Global ID range | Node type | NetAnim label | Color |
|---|---|---|---|
| 0 – 3 | Controllers | CTRL-1 to CTRL-4 | Purple (large, 40×40) |
| 4 – 203 | Vehicles | V-1 to V-200 | Green (20×20) |
| 204 – 267 | RSUs | RSU-1 to RSU-64 | Yellow (20×20) |

**Controller positions** (network coordinate space, ~2061 m × 2137 m):

| Controller | Position | Quadrant |
|---|---|---|
| CTRL-1 | (515, 534) | SW |
| CTRL-2 | (1545, 534) | SE |
| CTRL-3 | (515, 1602) | NW |
| CTRL-4 | (1545, 1602) | NE |

RSU-to-controller assignment: each RSU is assigned to its nearest controller by Euclidean distance (`c*(k) = argmin d(r_k, c_i)`), computed automatically at simulation start.

### NetAnim Visualization

```bash
~/ns-allinone-3.35/netanim-3.109/NetAnim
# File → Open → ~/ns-allinone-3.35/ns-3.35/routing.xml
```

---

## 12. Troubleshooting

### Build error: "not declared in this scope"

Caused by a VLA (Variable Length Array) if a non-`const` variable is used as an array dimension. Ensure `total_size` (a `const int`) is used for all static array sizes. `N_Controllers` must only appear in runtime expressions, never in type declarations like `type name[N_Controllers]`.

### Simulation "Interrupted" — exits early

The optimizer (`optimization_lifetime.py`) reads a per-run tagged CSV (e.g. `optimization_link_lifetime_data_V0_pct20_d80ms.csv`) and fails if it cannot find the file. Check that:
1. The `--tag` argument passed by NS-3 matches the actual filename written to scratch
2. The scratch copy of `optimization_lifetime.py` is up to date (use `--build` to re-sync)

### SIGSEGV at simulation start

Run under gdb:

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf --run "scratch/routing --attack_number=2 --attack_percentage=40" --gdb
# In gdb: run  →  bt
```

Most common cause: node-ID offset arithmetic error. The code uses `nid = GetId() - N_Controllers` to convert global IDs to routing array indices. If `N_Controllers` changed, all such offsets must be updated consistently.

### Mobility trace not found

```bash
ls -lh /home/user/mobility/mobility_urban_150.tcl
```

If missing, re-run the SUMO export (Section 4) or copy the backup from `mobility/`.

### Vehicles clustered at one point in NetAnim

The SUMO coordinate origin may not align with the RSU grid origin. Both are set to (0,0) in the current configuration. If you regenerate the SUMO network with a large `netOffset`, re-export the trace with `--trace-offset` to re-zero coordinates, or shift the RSU grid `MinX`/`MinY` in `routing.cc` to match.

### S2 never triggers

Confirm `attack_delay_ms > 50` (the S2 Δ_max threshold). The log line at simulation start reports this:

```
[ATTACK DELAY] Configured delay = 40 ms  |  ...  |  above S2 threshold: NO  (S2 will NOT fire — below threshold)
```

If the delay is below 50 ms, either raise `--attack_delay_ms` or this is an intentional below-threshold experiment.

### Old result CSVs mixing with new

Always clean before a fresh sweep:

```bash
python3 scripts/run_std_attacks.py --clean --build
```

Or manually:

```bash
rm ~/ns-allinone-3.35/ns-3.35/results_routing/MOBIGUARD_Attack*.csv
rm ~/ns-allinone-3.35/ns-3.35/results_routing/TAP_Attack*.csv
```

---

## Notes

- Never commit `routing.xml` or `fcd_output_*.xml` to Git — they are 100+ MB and regenerated every run. Both are already in `.gitignore`.
- `simTime=40` is sufficient for quick validation. Use `simTime=300` for thesis production results (thesis requires 5 seeds × 6 percentages × 2 attacks = 60 runs total).
- `data_transmission_frequency` is fixed at 1.0 (one routing cycle per second). Higher values cause proportional slowdown — do not change.
- The S1 EWMA baseline requires approximately 10 seconds of benign traffic to converge. This is why `attack_start_time` defaults to 10.0 s. Do not lower it below ~5 s.
- Attacks 1 and 2 are safe to run in parallel (separate processes, unique filenames). Other attack variants that share intermediate scratch files should not be parallelized without further filename isolation.
