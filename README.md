# MOBIGUARD — Final Year Project

MOBIGUARD is a mobility-aware, zero-trust SDVN (Software-Defined Vehicular Network) defense framework simulated in NS-3.35 with realistic SUMO-generated vehicular mobility traces. The simulation models 200 vehicles, 64 RSUs (8×8 grid, 260m x 270m spacing), and 4 distributed SDVN controllers over a ~2061 m × 2137 m urban area (Los Angeles), and supports 8 attack variants including Selective Time Delay and Hidden Forwarding attacks.

---

## Project Files

| File | Purpose |
|---|---|
| `routing.cc` | Main NS-3 simulation — routing, attack logic, SUMO mobility integration, NetAnim output |
| `tcam_attack_helper.h` | TCAM attack helper header included by `routing.cc` |
| `LDA(2).cc` | Related attack and detection logic |
| `optimization.py` | Link-lifetime optimization helper |
| `optimization_lifetime.py` | Lifetime-aware optimization helper |
| `LDA_security(1) (1).py` | Security metrics analysis |
| `LDA_PQ_security(1) (1).py` | Post-quantum security analysis |
| `sumo_sim/` | SUMO scenario folder (network, trip files, sumocfg, mobility trace) |

---

## 1. Selective Time Delay Attacks
- **Attack 1 (Control Plane):** RSUs delay flow-rule packets from SDVN Controllers, desynchronizing routing tables.
- **Attack 2 (Data Plane):** RSUs delay DSRC data packets between vehicles.
- **Parameters:** Delay is fixed at 80ms.
- **Node Allocation:** `--attack_percentage` dictates the exact attacker count: `round(N_RSUs * percentage/100)`. A uniform random distribution assigns these to unique RSU IDs without overlap.

## 2. TAP Defense Module
- **Global Initialization:** `tap_reset_state()` initializes timing metrics and quarantine lists for all 8 attack variants automatically.
- **Clean Logs:** Removed per-packet debug noise. Only aggregated cycle metrics (MCC, TP, FP) and `ATTACKER DETECTED` events are printed.

## 3. Architecture Improvements
- **Dynamic Arrays:** Removed hardcoded limits. Threat arrays (`is_malicious_node`, `t_onset`) now scale dynamically to support large SUMO topologies (e.g., 200 vehicles + 64 RSUs).
- **CLI Dispatcher:** Added `--attack_number` to select attacks safely without breaking the legacy `--active_attack_variant` logic used by other researchers.

---

## Requirements

- Ubuntu 20.04+ (or equivalent Linux)
- NS-3.35 installed at `~/ns-allinone-3.35/`
- NetAnim 3.109 (bundled with ns-allinone)
- SUMO (Simulation of Urban Mobility) — `sudo apt install sumo sumo-tools`
- Python 3.8+

---

## Part 1: SUMO Mobility Trace Generation

The SUMO workflow generates a realistic vehicular mobility trace (`.tcl` file) that NS-3 reads via `Ns2MobilityHelper`. Follow these steps every time you want a fresh mobility trace. If you already have `mobility.tcl` skip to Part 2.

### Step 1.1 — Generate the road network

Launch the OSM Web Wizard to generate a SUMO scenario from OpenStreetMap:

```bash
python3 $SUMO_HOME/tools/osmWebWizard.py
```

In the browser UI that opens:
- Navigate to a dense urban area with broad multi-lane roads (e.g. Kuala Lumpur city centre — avoid narrow residential streets which cause congestion)
- Draw a rectangle covering approximately 2061 m × 2137 m (e.g. Los Angeles)
- Enable vehicle types: **Passenger** and **Truck** (Bus optional)
- Set **Duration** to `600` seconds
- Leave **Add polygons** and **Import public transport** unchecked
- Click **Generate Scenario**

A timestamped folder (e.g. `sumo_sim/2026-06-15-11-28-16/`) is created containing `osm.net.xml.gz`, `osm.sumocfg`, and trip files.

### Step 1.2 — Verify the network size

```bash
cd ~/Final\ Year\ Project/1.\ Attacks/Final-Year-project/sumo_sim/<timestamp>/
gunzip -k osm.net.xml.gz
grep -o '<location[^>]*>' osm.net.xml
```

Check the `convBoundary` field in the output. The width and height (maxX − minX, maxY − minY) should both be approximately 2061 m and 2137 m respectively. If the area is too large, re-generate with a tighter bounding box.

### Step 1.3 — Generate trip files (100 cars + 25 each of bus/lorry/van/truck)

Run `randomTrips.py` separately for each vehicle type:

```bash
# 100 cars — departures spread over 0–30 s (warm-up window)
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

Verify the trip counts:

```bash
for f in trips_car.trips.xml trips_bus.trips.xml trips_lorry.trips.xml trips_van.trips.xml trips_truck.trips.xml; do
  echo "$f: $(grep -c '<trip ' $f)"
done
```

Expected: `trips_car = 100`, others ≈ 25–26 each. If any file has 26 trips instead of 25, remove the last trip:

```bash
for f in trips_bus.trips.xml trips_lorry.trips.xml trips_van.trips.xml trips_truck.trips.xml; do
  last_id=$(grep -o '<trip id="[^"]*"' "$f" | tail -1 | grep -o '"[^"]*"' | tr -d '"')
  sed -i "/<trip id=\"$last_id\" /d" "$f"
done
```

### Step 1.4 — Set maxSpeed = 41.67 m/s (150 km/h) in each trip file

Each file must have a `<vType>` with `maxSpeed="41.67"`. Add it to every file:

```bash
for f in trips_car.trips.xml trips_bus.trips.xml trips_lorry.trips.xml trips_van.trips.xml trips_truck.trips.xml; do
  sed -i '/<vType /s/\/>/maxSpeed="41.67"\/>/' "$f"
done
```

Verify that the `vType id=` matches the `<trip type=>` attribute in each file:

```bash
for f in trips_car.trips.xml trips_bus.trips.xml trips_lorry.trips.xml trips_van.trips.xml trips_truck.trips.xml; do
  echo "=== $f ==="
  grep -m1 "<vType" "$f"
  grep -m1 "<trip " "$f"
done
```

If `vType id=` does not match the trip `type=`, rename the `id` to match (e.g. change `id="car"` to `id="passenger"` to match `type="passenger"`). See project notes for the exact sed commands.

### Step 1.5 — Create the combined sumocfg

```bash
cat > test_osm_1000.sumocfg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<sumoConfiguration>
    <input>
        <net-file value="osm.net.xml"/>
        <route-files value="trips_car_1000.xml,trips_bus_1000.xml,trips_lorry_1000.xml,trips_van_1000.xml,trips_truck_1000.xml"/>
    </input>
    <time>
        <begin value="0"/>
        <end value="600"/>
    </time>
    <output>
        <tripinfo-output value="tripinfos.xml"/>
        <summary-output value="summary.xml"/>
        <statistic-output value="stats.xml"/>
    </output>
    <processing>
        <ignore-route-errors value="true"/>
    </processing>
</sumoConfiguration>
EOF
```

### Step 1.6 — Verify the SUMO simulation

Run headless to check for issues:

```bash
sumo -c test_osm_1000.sumocfg 2>&1 | tee sumo_run.log
```

Key checks:
- `Inserted: 200` — all 200 vehicles entered the network
- `Waiting: 0` — no vehicles stuck
- Zero `Teleporting` warnings — no gridlock
- Average speed should be reasonable for the road network

Check vehicle counts at key timestamps:

```bash
for t in 30 60 100 178 200 300; do
  echo -n "t=$t: "
  grep "<step time=\"$t\.00\"" summary.xml
done
```

Optionally view in SUMO-GUI:

```bash
sumo-gui -c test_osm_1000.sumocfg
```

### Step 1.7 — Automate Trace Generation for All Speeds

To easily run "Speed Sweep" experiments in NS-3, we use a custom script (`generate_speeds.sh`) that automatically calculates the physics and generates `.tcl` files for 0, 10, 20, 30, 40, 50, 60, and 150 km/h:

```bash
bash generate_speeds.sh
```

This script will seamlessly execute the headless `sumo` simulation and `traceExporter.py` to convert the data, saving the resulting files perfectly into `/home/user/mobility/mobility_urban_X.tcl`!

Verify the trace:

```bash
# Should show exactly 200 nodes (0–199)
grep -o '\$node_([0-9]*)' mobility.tcl | sort -u -t'(' -k2 -n | wc -l

# Should show max node ID = 199
grep -o '\$node_([0-9]*)' mobility.tcl | grep -o '[0-9]*' | sort -n | tail -3

# Should span t=0.0 to t=599.0
grep -o '\$ns_ at [0-9.]*' mobility.tcl | sort -t' ' -k3 -n -u | head -1
grep -o '\$ns_ at [0-9.]*' mobility.tcl | sort -t' ' -k3 -n -u | tail -1
```

### Step 1.8 — Backup the traces to the Project Repo

The `generate_speeds.sh` script automatically places the `.tcl` files in `/home/user/mobility/` (where NS-3 executes). To keep your git repository fully synchronized and backed up, copy those files into your project's `mobility/` folder:

```bash
cp /home/user/mobility/mobility_urban_*.tcl "/home/user/Final Year Project/1. Attacks/Final-Year-project/mobility/"
```

---

## Part 2: NS-3 Simulation Setup

### Step 2.1 — Copy routing.cc to the NS-3 scratch folder

```bash
cp "/home/user/Final Year Project/1. Attacks/Final-Year-project/routing.cc" \
   ~/ns-allinone-3.35/ns-3.35/scratch/routing.cc

cp "/home/user/Final Year Project/1. Attacks/Final-Year-project/tcam_attack_helper.h" \
   ~/ns-allinone-3.35/ns-3.35/scratch/tcam_attack_helper.h
```

Repeat this copy step every time you edit the source files.

### Step 2.2 — Build NS-3

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf build 2>&1 | grep -i error
```

If you see no errors, the build succeeded. A clean build from scratch:

```bash
./waf configure
./waf build
```

---

## Part 3: Running the SUMO/SDVN Simulation

### Step 3.1 — SUMO mobility run (200 vehicles, 64 RSUs, 4 controllers)

This is the main simulation run for the SDVN deliverables:

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf --run "scratch/routing \
  --routing_test=false \
  --N_Vehicles=200 \
  --N_RSUs=64 \
  --N_Controllers=4 \
  --mobility_scenario=0 \
  --maxspeed=150 \
  --use_sumo_mobility=1 \
  --simTime=10 \
  --architecture=3" > /dev/null 2>&1
```

**Key parameters:**

| Parameter | Value | Meaning |
|---|---|---|
| `routing_test` | `false` | Real network run (not small test topology) |
| `N_Vehicles` | `200` | 200 vehicles from SUMO trace |
| `N_RSUs` | `64` | 8×8 RSU grid, 260m x 270m spacing, min offset 100m |
| `N_Controllers` | `4` | 4 distributed SDVN controllers (2×2 grid, center of quadrants) |
| `mobility_scenario` | `0` | Urban mobility |
| `maxspeed` | `150` | Selects the mobility_urban_150.tcl trace |
| `use_sumo_mobility` | `1` | Load SUMO `.tcl` trace via Ns2MobilityHelper |
| `simTime` | `10` | Simulation duration in seconds |
| `architecture` | `3` | SDVN architecture (DSRC + controller) |

For a longer production run (300 s data window + 30 s warm-up):

```bash
./waf --run "scratch/routing \
  --routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 \
  --simTime=330 --architecture=3" > /dev/null 2>&1
```

### Step 3.2 — Check the output

```bash
ls -lh ~/ns-allinone-3.35/ns-3.35/routing.xml
```

The `routing.xml` file is the NetAnim animation file. It should be several MB for a 10 s run.

To save console output for debugging:

```bash
./waf --run "scratch/routing --routing_test=false --N_Vehicles=200 --N_RSUs=64 \
  --N_Controllers=4 --mobility_scenario=0 --maxspeed=150 \
  --use_sumo_mobility=1 --simTime=10 --architecture=3" 2>&1 | tee run.log
```

---

## Part 4: NetAnim Visualization

### Step 4.1 — Open NetAnim

```bash
~/ns-allinone-3.35/netanim-3.109/NetAnim
```

### Step 4.2 — Load the animation file

Go to **File → Open** and load:

```
~/ns-allinone-3.35/ns-3.35/routing.xml
```

### Step 4.3 — What you will see

| Node | Color | Label | Count |
|---|---|---|---|
| Vehicles | Green | V-1 to V-200 | 200 |
| RSUs | Yellow | RSU-1 to RSU-64 | 64 |
| Controllers | Purple (larger) | CTRL-1 to CTRL-4 | 4 |

**Controller placement** (in network coordinate space, ~2061 m × 2137 m LA area):
- CTRL-1: (515, 534) — SW quadrant
- CTRL-2: (1545, 534) — SE quadrant
- CTRL-3: (515, 1602) — NW quadrant
- CTRL-4: (1545, 1602) — NE quadrant

Controllers are positioned at the exact centers of the four map quadrants to avoid visual overlap with the RSU grid points. They are rendered at 2× size (40×40) compared to RSUs and vehicles (20×20).

### Step 4.4 — Recording the 10-second clip

Use a screen recorder (e.g. `kazam`, `simplescreenrecorder`, or OBS):

```bash
# Install if needed
sudo apt install kazam
kazam &
```

In NetAnim:
1. Press **Play** and confirm vehicles are moving
2. Start your screen recorder
3. Record for 10 seconds of simulation time
4. Stop the recording

---

## Part 5: Attack Scenarios (Test Network)

These use a small synthetic test network (`routing_test=true`) — **not** the SUMO mobility trace.

### Baseline run

```bash
./waf --run "scratch/routing"
```

### Selective Time Delay Attacks (Attack 1 & Attack 2) in Full SUMO Scenario

To execute the full SUMO simulation with the Selective Time Delay attacks, utilize the `--attack_number` parameter. The delay constraint is fixed at 80ms, and the `--attack_percentage` scales the proportion of compromised attackers within the network. The TAP detector supports all attack variants and provides aggregated metric logs per routing cycle.

**Attack 1 — Control Plane (CP) Selective Time Delay:**
```bash
./waf --run "scratch/routing \
  --routing_test=false \
  --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 \
  --simTime=15 --architecture=3 \
  --attack_number=1 \
  --attack_percentage=20 \
  --attack_start_time=2.0"
```

**Attack 2 — Data Plane (DP) Selective Time Delay:**
```bash
./waf --run "scratch/routing \
  --routing_test=false \
  --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 \
  --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 \
  --simTime=15 --architecture=3 \
  --attack_number=2 \
  --attack_percentage=20 \
  --attack_start_time=2.0"
```

### TAP Experiment Sweep (Test Network, all intensities)

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf build 2>&1 | tail -5

rm -f results_routing/TAP_Attack*_*.csv
rm -f results_routing/MOBIGUARD_Attack*_*.csv

# For Attack 1 (Test Network)
./waf --run "scratch/routing --routing_test=true --attack_number=1 --attack_percentage=20"
# For Attack 2 (Test Network)
./waf --run "scratch/routing --routing_test=true --attack_number=2 --attack_percentage=20"
# ... change percentages to 40, 60, 80, 100 as needed
```

**Attack parameters:**
- `attack_percentage`: Controls the proportion of malicious nodes (e.g. 20% compromises 12 RSUs in a 64 RSU grid).
- Delay strength is fixed at 80ms for standard consistency.

| Value | Attackers | Delay strength |
|---|---|---|
| 0 | 0 (baseline) | 0% |
| 20 | 2 | 20% |
| 40 | 4 | 40% |
| 60 | 6 | 60% |
| 80 | 8 | 80% |
| 100 | 10 | 100% |

Output files: `results_routing/TAP_Attack2_<percentage>.csv` and `results_routing/MOBIGUARD_Attack2_<percentage>.csv`

### Plot TAP Results

```bash
python3 visualization/plot_tap_results.py
```

Plots are saved to `output/tap/`.

---

## Part 6: Command-Line Reference

### All available flags

| Flag | Default | Description |
|---|---|---|
| `N_Vehicles` | 80 | Number of vehicle nodes |
| `N_RSUs` | 20 | Number of RSU nodes |
| `N_Controllers` | 4 | Number of SDVN controllers (C = {c1,...,cm}) |
| `simTime` | 60 | Total simulation time in seconds |
| `mobility_scenario` | 0 | 0=urban, 1=non-urban, 2=highway |
| `use_sumo_mobility` | 1 | 1=load SUMO .tcl trace, 0=synthetic mobility |
| `maxspeed` | — | Selects trace file `mobility_urban_<maxspeed>.tcl` |
| `architecture` | — | 1=DSRC only, 3=SDVN (DSRC + controller) |
| `routing_test` | true | true=small test network, false=real SUMO network |
| `routing_algorithm` | 4 | 0=ECMP, 1=RR, 2=QR-SDN, 3=RLMR, 4=proposed, 5=DCMR |
| `experiment_number` | 3 | 0=QoS, 1=flow size, 2=mobility, 3=network size |
| `attack_number` | -1 | Supersedes active_attack_variant for new attacks. 1=CP Selective Time Delay, 2=DP Selective Time Delay |
| `active_attack_variant` | -1 | Legacy parameter (-1=baseline, 0–7=attack variants). Handled securely under the hood by attack_number |
| `attack_percentage` | 0 | Attack intensity 0–100% |
| `attack_start_time` | 10.0 | Seconds before attack begins |
| `attack_rate_pps` | 20.0 | Slow-flow injection rate (pkt/s) for Attacks 3+4 |
| `num_attackers` | 1 | Number of attacker nodes for Attack 4 |
| `data_transmission_frequency` | 1.0 | Routing cycles per second |
| `link_lifetime_threshold` | 0.4 | Minimum link lifetime for route selection |
| `flow_size` | 55 | Packets per flow |
| `single_cycle` | false | true=one packet per flow (debug mode) |
| `lambda` | — | Traffic parameter |
| `qf` | — | Queue factor |

### Attack variant index

| `active_attack_variant` | Attack |
|---|---|
| -1 | Baseline (no attack) |
| 0 | Attack 1 — Selective Time Delay (Control Plane) |
| 1 | Attack 2 — Selective Time Delay (Data Plane) |
| 2 | Attack 3 |
| 3 | Attack 4 |
| 4 | Attack 5 |
| 5 | Attack 6 |
| 6 | Attack 7 |
| 7 | Attack 8 — Passive Hidden Forwarding |

---

## Part 7: Node Architecture

With `N_Vehicles=200`, `N_RSUs=64`, `N_Controllers=4`, the global NS-3 node IDs are:

| Global ID range | Node type | NetAnim label | Color |
|---|---|---|---|
| 0 – 3 | Controllers | CTRL-1 to CTRL-4 | Purple (large) |
| 4 – 203 | Vehicles | V-1 to V-200 | Green |
| 204 – 267 | RSUs | RSU-1 to RSU-64 | Yellow |

RSU-to-controller assignment follows the proposal equation: each RSU is assigned to the nearest controller by Euclidean distance — `c*(k,t) = argmin d(r_k, c_i)`. This is computed automatically at simulation start.

---

## Part 8: Troubleshooting

### Build errors: "not declared in this scope"

The arrays `neighbordata_inst`, `data_at_nodes_inst`, etc. appear undeclared. This is caused by a VLA (Variable Length Array) error if any global array dimension uses a non-`const` variable. Ensure `total_size` (a `const int`) is used for all static array sizes. `N_Controllers` must only appear in runtime expressions (loop bounds, index arithmetic), never in `type name[N_Controllers]`.

### Simulation crashes with SIGSEGV at "current time is 0"

Run under gdb to get a backtrace:

```bash
./waf --run "scratch/routing --routing_test=false --N_Vehicles=200 --N_RSUs=64 \
  --N_Controllers=4 --mobility_scenario=0 --maxspeed=150 \
  --use_sumo_mobility=1 --simTime=10 --architecture=3" --gdb
# In gdb:
run
bt
```

Common cause: a node-ID offset arithmetic error. The code uses `nid = GetId() - N_Controllers` to convert global IDs to 0-indexed routing array indices. If `N_Controllers` changed, all `-N_Controllers` offsets must be consistent.

### Controllers not visible in NetAnim

Controllers at positions that coincide exactly with RSU grid points are hidden behind yellow RSU nodes. Current controller positions (515, 534, etc.) are offset from the RSU grid to avoid this. If you change `N_Controllers` or RSU spacing, update controller positions accordingly in the `ctrl_positions` vector in `main()`.

### SUMO trace not loading / `mobility.tcl` not found

Ensure the trace is at the exact path the code expects:

```bash
ls -lh /home/user/mobility/mobility_urban_150.tcl
```

If the file is elsewhere, either copy it to the expected path or change `maxspeed` to a value that matches a case in the `trace_file` switch inside `routing.cc`.

### Vehicles all clustered at one point in NetAnim

The SUMO trace coordinate origin may not align with the RSU grid origin. Both are set to (0,0) in the current configuration — the RSU grid starts at `MinX=0, MinY=0` and the SUMO trace is exported from `netOffset` coordinates. If your network has a large `netOffset`, re-export the trace with `--trace-offset` or shift the RSU grid `MinX`/`MinY` to match.

---

## Notes

- Always rebuild NS-3 after editing `routing.cc` or `tcam_attack_helper.h`.
- Keep `/home/user/mobility/mobility_urban_150.tcl` in sync with the current SUMO scenario. If you regenerate the SUMO network, regenerate and re-export the trace.
- For the TAP Attack 2 sweep, always delete old CSV files before a fresh run to avoid mixing results.
- `simTime=10` is sufficient for the 10-second NetAnim clip deliverable. Use `simTime=330` (30 s warm-up + 300 s data) for production results.
- The `data_transmission_frequency` is set to `1.0` (one routing cycle per second). Do not change this to a higher value — `5.0` was a test value that caused a 5× slowdown.
- SUMO should be run for 600 s total. The 300 s data-collection window for NS-3 starts at SUMO t=30 s (warm-up). For the `.tcl` trace, re-zero timestamps so SUMO t=30 s = NS-3 t=0 s, or simply start NS-3 at t=0 and begin recording results from t=30 s onward.
- **Git Repository Hygiene:** Never commit `routing.xml` (the NetAnim file) or `fcd_output_*.xml` files to Git, as they are massive (100+ MB) and change every run. Add them to your `.gitignore`. You can safely commit the `.tcl` traces to make your repository self-contained.
