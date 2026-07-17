# Performance Metrics Verification Runbook

Manual, step-by-step commands to confirm all 12 performance metrics (docs/main.tex §4.6) are
computing real, non-broken values after this session's fixes (TVR wiring, M5 race fix, T_ref
anchoring, M8/M9/M11/M12 implementations). Run these on the actual hosts (ns-3/Ubuntu box for
Parts 1-3, GPU training host for Part 4, Fabric test-network for Part 5) — this session had no
access to any of those toolchains, so everything below is unverified by execution and needs a
real run.

Companion script: `scripts/verify_metrics.py` — reads the CSVs these commands produce and prints
PASS/WARN/FAIL per metric automatically. Run it after each stage below.

---

## Part 0 — Build check (run this first, every time code changes)

```bash
cd /home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35
./waf build 2>&1 | tee /tmp/waf_build.log | grep -i error
echo "Exit code: $?"   # 0 with no output above = clean build
```

If this fails, stop here — nothing below will produce valid data.

---

## Part 1 — Baseline run (no attack)

Establishes the "clean" reference point. Every metric should show near-zero attack-related
values here (MCC≈0 or undefined, TVR≈0%, UCR≈0%, UFCR undefined).

```bash
./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --simTime=60"
```

**Check:** `results_routing/MOBIGUARD_baseline.csv` exists and has rows.
```bash
python3 scripts/verify_metrics.py --file results_routing/MOBIGUARD_baseline.csv --mode baseline
```

---

## Part 2 — Per-variant attack sweep (M1, M2, M3, M4)

Per the proposal's own methodology (main.tex:4945 — "separate simulation runs, one variant active
at a time"), run each attack variant once. `attack_number` 1-8 maps to Variants 1-8 (0-indexed
`active_attack_variant` 0-7 internally).

```bash
for n in 1 2 3 4 5 6 7 8; do
  echo "=== Attack $n ==="
  ./waf --run "scratch/routing/routing --attack_number=$n --attack_percentage=40 --simTime=60"
done
```

**What to check per variant:**

| Attack # | Variant | Expect non-zero on | CSV file pattern |
|---|---|---|---|
| 1 | S1, CP Selective Delay | `cur_TVR`/`avg_TVR` > 0 (this was the dead-counter bug — **must not be 0%**) | `MOBIGUARD_Attack1_40_d*.csv` |
| 2 | S2, DP Selective Delay | `cur_TVR`/`avg_TVR` > 0 | `MOBIGUARD_Attack2_40_d*.csv` |
| 3 | S3, CP TCAM Exhaustion | `s3_fired_count` > 0 | `MOBIGUARD_Attack3_40_d*.csv` |
| 4 | S4, DP TCAM Exhaustion | `s4_fired_count` > 0 | `MOBIGUARD_Attack4_40_d*.csv` |
| 5 | S5, Active HF CP | `cur_UCR`/`avg_UCR` > 0 | `MOBIGUARD_Attack5_40_d*.csv` |
| 6 | S6, Active HF DP | `cur_UCR`/`avg_UCR` > 0 | `MOBIGUARD_Attack6_40_d*.csv` |
| 7 | S7, Passive HF CP | `cur_UCR` > 0 AND `witness_TP_W + witness_FP_W` > 0 | `MOBIGUARD_Attack7_40_d*.csv` |
| 8 | S8, Passive HF DP | `cur_UCR` > 0 AND `witness_TP_W + witness_FP_W` > 0 | `MOBIGUARD_Attack8_40_d*.csv` |

For **every** variant, also check:
- `cur_MCC` ∈ [-1, 1] and `TP+FP+TN+FN` > 0 (M1)
- `cur_mit_ms`/`avg_mit_ms` ≥ 0 (M4) — should be > 0 once quarantine fires (may need higher
  `attack_percentage` or longer `simTime` for trust to cross `TRUST_T_MIN`)

```bash
python3 scripts/verify_metrics.py --dir results_routing --mode sweep
```

---

## Part 3 — Ablation-specific runs (M5, M7, M9, M11, M12)

### M5 — Controller Failover Latency
Requires multiple controllers and a scenario that revokes one. Attack 1 at high
`attack_percentage` compromises multiple controllers (per `declare_attackers()`'s ladder):
```bash
./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=100 --N_Controllers=4 --simTime=60"
```
**Check:** `ctrl_failover_events` > 0, `ctrl_failover_max_ms` > 0 and ≤ 100 (target bound).

### M7 — Security/Consensus Overhead
No special flags — check any run above:
```bash
python3 scripts/verify_metrics.py --file results_routing/MOBIGUARD_Attack1_100_d*.csv --mode m7
```
**Check:** `o_crypto_bytes_pkt` ≈ 4691 (4627 B ML-DSA-87 sig + 64 B π_delay commitment),
`t_batch_ms_avg` ≥ 0, `t_consensus_ms_avg` ≥ 0.

### M9 — Distributed Time Reference Robustness
Sweep `f_bad` with `N_RSUs=64` (default): `{0, 1, 16, 31, 32}`.
```bash
for f in 0 1 16 31 32; do
  ./waf --run "scratch/routing/routing --routing_test=1 --active_attack_variant=-1 --time_ref_f_bad=$f --time_ref_delta_attack=0.5 --simTime=30"
  mv results_routing/MOBIGUARD_baseline.csv results_routing/MOBIGUARD_baseline_fbad${f}.csv
done
python3 scripts/verify_metrics.py --dir results_routing --mode m9
```
**Expected:** `eps_ref_s` ≈ 0 for `f_bad ∈ {0,1,16,31}`; `eps_ref_s` ≈ 0.5 (= `delta_attack`) at
`f_bad=32` — confirms the bound holds below `N_RSUs/2` and fails exactly at `N_RSUs/2`.

### M11 — Unauthorized FlowMod Containment Rate
Run each endorsement mode on a control-plane variant (1, 3, 5, or 7):
```bash
./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=40 --enable_endorsement_requirement=true  --simTime=60"
mv results_routing/MOBIGUARD_Attack1_40_d*.csv results_routing/MOBIGUARD_Attack1_40_AB8B.csv

./waf --run "scratch/routing/routing --attack_number=1 --attack_percentage=40 --enable_endorsement_requirement=false --simTime=60"
mv results_routing/MOBIGUARD_Attack1_40_d*.csv results_routing/MOBIGUARD_Attack1_40_AB8A.csv
```
**Expected:** `UFCR` ≈ 100 in the AB8B (`true`) file, `UFCR` ≈ 0 in the AB8A (`false`) file.
```bash
python3 scripts/verify_metrics.py --file results_routing/MOBIGUARD_Attack1_40_AB8B.csv --mode m11 --expect-ufcr 100
python3 scripts/verify_metrics.py --file results_routing/MOBIGUARD_Attack1_40_AB8A.csv --mode m11 --expect-ufcr 0
```

### M12 — Witness Alert Precision/Recall
Already covered by Attack 7/8 in Part 2. Re-check explicitly:
```bash
python3 scripts/verify_metrics.py --file "results_routing/MOBIGUARD_Attack7_40_d*.csv" --mode m12
```
**Check:** `WAP_precision`, `WAP_recall` ∈ [0, 100], and `witness_TP_W + witness_FP_W` > 0 (some
threshold event actually fired).

---

## Part 4 — M8: Federated Model Poisoning Resistance (Python, GPU host)

Run on the training host, from `lstm_pipeline/src/`. Needs clean per-RSU models first.

```bash
cd lstm_pipeline/src

# One-time: preprocess + train clean local models (steps 1-2 only)
python3 preprocessor.py
python3 local_trainer.py --epochs 30

# M8 sweep — BRFA-v2 vs naive FedAvg across malicious-RSU fractions
python3 poison_sweep.py --rho 0.0 0.1 0.2 0.3 --modes brfa fedavg
```

**Expected console output:** a `Target check` block showing `[PASS]` for every `rho_mal < 1/3`
under `brfa` mode. If any show `[CHECK]`, inspect `poison_sweep_results.json`.

```bash
python3 ../../scripts/verify_metrics.py --file ../poison_sweep_results.json --mode m8
```
**Expected:** for `mode=brfa`, `|delta_poison|` < 0.05 for every `rho_mal < 0.334`; for
`mode=fedavg`, `delta_poison` should generally increase with `rho_mal` (no rejection mechanism).

---

## Part 5 — Blockchain chaincode + bridge (M5, M8, M11 audit trail; new M9 T_ref commit)

Requires the Fabric test-network up and `mobiguard-cc` deployed (see `blockchain/DEPLOY.md`).

```bash
cd blockchain/fabric-samples/test-network
go version   # confirm Go toolchain present — this session had none, never build-checked

# Deploy/upgrade chaincode with the new tref.go + types.go changes
./network.sh deployCC -ccn mobiguard-cc -ccp ../../mobiguard-cc -ccl go

# Run the full synthetic test (includes new §9 T_ref section)
cd ../../mobiguard-cc
./test_synthetic.sh 2>&1 | tee /tmp/test_synthetic.log
grep -A2 "=== 9\." /tmp/test_synthetic.log
```
**Expected:** section 9 shows `CommitTRef` succeeding twice (seq 1, seq 2), `GetTRef` returning
matching `tRefValue`/`epsRef`, and the duplicate-seq re-invoke printing the expected failure line.

**Bridge (optional, live integration):**
```bash
cd blockchain/bridge
npm install   # first time only
node --check index.js && node --check tailers/tref.js   # already done in-session, re-confirm
N_RSUS=4 N_CONTROLLERS=1 node index.js
```
Watch for `[BRIDGE] T_ref tailer watching: .../bc_tref_log.csv` and, once an ns-3 run with
`--routing_test=1` is producing `bc_tref_log.csv` rows, `🕒 T_REF COMMITTED` blocks in the log.

---

## Part 6 — Full report

Once all parts above are done, aggregate everything:
```bash
python3 scripts/verify_metrics.py --dir results_routing --mode full-report
```
This prints one line per metric (M1-M12): `PASS`, `WARN` (ran but suspicious value), or
`FAIL` (missing file, wrong column count, or value outside valid range) — see script for the
exact criteria used per metric.

---

## Quick reference — CSV column layout

`write_security_metrics_csv()` (`scratch/routing.cc`) writes a **fixed-order, comma-separated**
row per cycle, with a multi-line `#`-prefixed comment header (not a real CSV header row — parse
by position, not by pandas auto-header). Two possible row lengths:

- **51 columns** — all variants except 2, 3, and baseline (no TCAM block)
- **60 columns** — variants 2, 3 (TCAM attacks), and baseline (9 extra TCAM columns inserted
  after column 21)

Full column order is in `scripts/verify_metrics.py`'s `COLUMNS_NO_TCAM` / `COLUMNS_TCAM` lists —
kept in sync with `routing.cc:117447-117461`'s header comment by hand; if you add/remove a column
in `routing.cc`, update both lists in the script to match.
