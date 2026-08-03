# Task 8 — Full-System Implementation Evidence (Verification Guide)

This guide documents the evidence for **Task 8: full-system implementation
evidence with correct timing and correct coding without bypassing modeling.** It
explains what the two verification scripts do, how to regenerate the logs from
scratch, and how to read the results.

Picking this up cold? Read **§1** (the deliverables), then **§4** (the commands,
in order). Everything else is reference.

---

## 1. The five Task 8 deliverables

| # | Deliverable | Produced by | Status |
|---|---|---|---|
| 1 | Equation & algorithm presence audit log (with test-passed messages) | `scripts/audit_equations.py` → `equation_audit.log` | ✅ done |
| 2 | Full-system functional verification log | `scripts/functional_verification.py` → `functional_verification.log` | ✅ done |
| 3 | Manual timing verification confirmation | `functional_verification.py` GROUP J + `scripts/crypto_scripts/timing_report.py` | ◑ partial |
| 4 | Small video clip of the NS-3 simulation | (manual screen capture) | ☐ pending |
| 5 | Performance-evaluation metrics from a 30–40 s run ("1 data point of PEMs") | any sweep at `--sim-time 40`, then the CSVs in `results_routing/` | ☐ run-dependent |

Deliverables **1 and 2** are the two scripts documented here. Deliverable **5** is
just "run the simulation for one short data point" — the same sweep that feeds
deliverable 2 produces it.

---

## 2. The two verification scripts

### 2.1 `scripts/audit_equations.py` — PRESENCE audit (deliverable 1)

Static check that **every equation and algorithm in `docs/main.tex` exists in the
code.** It does not run the simulation. For each of the 87 `eq:` labels and 5
`alg:` labels in the thesis it either:

- points at the implementing symbol in the source tree (**CODE**),
- confirms the parameter plumbing that carries it (**PARAM**), or
- declares it analytical/paper-only with a stated reason (**PAPER**, reported as
  INFO — never a pass, never a fail).

Key properties:

- **Coverage self-check (Section Y):** re-reads `main.tex` and FAILS if any label
  has no audit entry — so the audit cannot silently drift as the paper grows.
- **Negative control (`--self-test`, Section S):** erases each equation's symbol
  from the source index and confirms the check flips to FAIL. Proves no check
  passes vacuously.
- **Baseline guard:** evidence from `tap_detection.h` / `efade_detection.h` /
  `sfto_pipeline/` (the external B1/B2/B3 comparators) is tagged `[BASELINE]` and
  cannot on its own satisfy a MOBIGUARD equation.

Flags: `--self-test`, `--strict` (exit 1 on any FAIL), `--no-color`.

```bash
python3 scripts/audit_equations.py --self-test --no-color > docs/task8_verification/equation_audit.log
```

Expected tail: `TEST PASSED — EQUATION & ALGORITHM PRESENCE AUDIT`
(e.g. `104 PASS, 0 FAIL, 8 INFO`).

### 2.2 `scripts/functional_verification.py` — BEHAVIOURAL verification (deliverable 2)

The audit proves the code *exists*; this proves the code *worked*. It is a
**post-run checker**: it reads the CSVs and logs a finished simulation produced
and runs ~250–600 assertions, each tied to the thesis equation (`eq:…`) and
metric (`M1`–`M12`) it exercises.

Every check prints one line with a status:

- **PASS** — the artefact exists and the property holds.
- **FAIL** — the artefact exists and the property is **violated** → a real defect.
- **WARN** — the artefact was not produced by this run, so the property could not
  be evaluated → a *coverage gap*, not a defect.

`--strict` exits non-zero on **FAIL only** (WARNs never fail the run).

It auto-discovers every attack sweep in the result directories and, per sweep,
runs groups **A–P**; groups **A0, J, N, O, Q, R** run once globally:

| Group | What it verifies | Metric |
|---|---|---|
| A0 | Mobility/density instrumentation written | — |
| A | CSV schema, monotone cycle index, no NaN/Inf, artefact freshness | — |
| **A1** | **No-bypass attestation** (see §6) — the full model ran, nothing disabled | — |
| B | Metric validity + **independent recomputation** of MCC/DR/FPR from TP/FP/TN/FN | M1–M4, M6 |
| C | Attack took effect vs clean baseline (latency/TVR/UCR/TCAM occupancy) | M2, M3, M6 |
| D | Detector separated attacked from clean; FPR bounded | M1 |
| E | Dual-mode OBU→escalation→RSU pipeline exercised | — |
| F | TCAM signatures S3/S4 fired (TCAM variants only) | — |
| G | Hidden-forwarding signatures S5–S8 / unauthorised copies | M3 |
| H | Witness precision/recall valid + recomputed | M12 |
| I | ML-DSA sign/verify, batch verify, STARK proofs, crypto overhead | M7 |
| J | **Causal ordering** — sign before verify, no escalation before its OBU detection | M7 |
| K | Blockchain endorsement, UFCR, chain growth, audit logs | M11 |
| L | Trust erodes under attack; controller failover accounting | M5 |
| M | Time-reference error bounded; BFT fault bound | M9 |
| N | Federated LSTM pipeline (AB2/AB3/BRFA/mobility JSONs) | M8 |
| O | External baselines B2 (SFTO) + B3 (FADE) produced usable output | — |
| P | External baseline B1 (TAP) comparator | M1 |
| Q | Metric coverage roll-up (which of M1–M12 were exercised) | — |
| R | Attack-variant coverage roll-up (which of the 8 variants were verified) | — |

Flags: `--results-dir <path>` (repeatable), `--attack N`, `--delay MS`,
`--strict`, `--no-color`.

```bash
python3 scripts/functional_verification.py --no-color > docs/task8_verification/functional_verification.log
```

**What makes it trustworthy (not a rubber stamp):**

1. **It recomputes, it doesn't trust.** MCC/DR/FPR/UFCR/WAP are re-derived from
   the raw confusion-matrix columns and compared to the reported value, so a
   subsystem cannot report a fake number and pass.
2. **It checks against a clean baseline.** Most attack checks assert
   `attacked ≥ clean`, proving the *attack* caused the effect.
3. **The no-bypass attestation (GROUP A1)** — the part that makes this Task-8
   evidence specifically. See §6.

---

## 3. Dependencies & I/O

**Code dependency:** exactly one — `scripts/verify_metrics.py`, loaded for its
positional CSV parser (`parse_mobiguard_csv`) and the column schemas
(`COLUMNS_NO_TCAM` = 52 cols, `COLUMNS_TCAM` = 61 cols). The MOBIGUARD CSV has no
real header row — columns are identified by **position**, which must match the
order `routing.cc:write_security_metrics_csv()` emits. Keeping that schema in one
place stops the two scripts from drifting. Everything else is Python stdlib.

**Reads (data, not code):**

| Input | Location |
|---|---|
| MOBIGUARD / TAP / FADE CSVs | `~/ns-allinone-3.35/ns-3.35/results_routing/` |
| LSTM pipeline JSONs (Group N) | `lstm_pipeline/*.json` |
| SFTO metrics (Group O) | `sfto_pipeline/results/*/metrics.json` |
| Run logs (no-bypass attestation) | `logs/` and `logs/rule_based_sweep/` |
| Design constants + mtimes | `scratch/*.h`, `scratch/*.cc` |

It does **not** parse `main.tex` (it cites labels as strings). The
label-vs-`main.tex` cross-check lives in `audit_equations.py`.

**Output directories (where a run writes):**

| Output | Location |
|---|---|
| Per-cycle metric CSVs | `…/ns-3.35/results_routing/MOBIGUARD_Attack<N>_<pct>[_d80ms][_seed<S>].csv` |
| Blockchain / aux logs | `…/ns-3.35/results_routing/bc_*`, `tcam_*`, `rsu_density.csv`, `crypto_timing_log.csv`, … |
| Per-run logs (std/hf runners) | `Final-Year-project/logs/A<N>_pct<pct>[_d80ms]_seed<S>.log` |
| Per-run logs (rule-based runner) | `Final-Year-project/logs/rule_based_sweep/A<N>_pct<pct>_seed<S>.log` |

---

## 4. How to regenerate the evidence (commands, in order)

> Run everything from the project directory:
> `cd ~/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project`

### Step 0 — Understand the runners

No single runner covers all 8 attacks with baselines. Pick based on what you need:

| Runner | Attacks | Also produces | Notes |
|---|---|---|---|
| `run_std_attacks.py` | 1, 2 | TAP baseline (B1) | `--build` syncs + compiles |
| `run_hf_attacks.py` | 5–8 | FADE baseline (B3) | |
| `run_rule_based_sweep.py` | **all 8** | none (MOBIGUARD only) | seeds default `[1,2,3]`; filenames get `_seed<S>`; `--build` syncs + compiles |

- All three runners' `--build` now call the same `sync_files()` (project
  `scratch/` → ns-3 tree) before `./waf build`, so any of them can be used to
  refresh the binary — no need to build with `run_std_attacks.py` first.
- The runners call the **same binary with identical `FIXED_PARAMS`** — they
  differ only in orchestration (which attacks, whether a baseline is paired,
  seed handling).

### Step 1 — Build once (required)

Your binary is stale if it predates the newest `scratch/` source. `--build`
syncs project sources → ns-3 and compiles, then exits without simulating:

```bash
python3 scripts/run_rule_based_sweep.py --build
```

### Step 2 — Run a sweep (survives terminal close)

**All 8 attacks, MOBIGUARD-only, 40 s, single seed, 8 workers** — the simplest
full-coverage option (no baselines):

```bash
nohup bash -c '
  python3 scripts/run_rule_based_sweep.py --build &&
  python3 scripts/run_rule_based_sweep.py --clean --sim-time 40 --seeds 1 --workers 8
' > logs/sweep_driver.log 2>&1 < /dev/null &

echo "driver PID $!"
```

- `nohup … < /dev/null &` detaches it so it survives closing the terminal.
- `&&` chains the build first — a build failure aborts before wasting 48 runs on
  a stale binary. `run_rule_based_sweep.py --build` now syncs `scratch/` and
  compiles on its own, so no separate `run_std_attacks.py --build` call is needed.
- `--seeds 1` → 48 runs (8 attacks × 6 pct × 1 seed). The default `[1,2,3]` would
  be 144 runs; one seed is enough for deliverables 2 and 5.
- `--clean` removes prior `MOBIGUARD_Attack*` CSVs for the swept scope (it does
  **not** touch TAP/FADE/`bc_*` leftovers — clean those manually if wanted).

**If you also want the baseline comparison data** (deliverable 5 / GROUPs O & P),
run the baseline-pairing runners instead of / in addition to rule-based —
**but never over the same attack number concurrently** (two processes writing the
same `MOBIGUARD_Attack1_*.csv` interleave via `ios::app` into a corrupt file):

```bash
python3 scripts/run_std_attacks.py --clean --sim-time 40 --workers 8   # attacks 1,2 + TAP
python3 scripts/run_hf_attacks.py  --clean --sim-time 40 --workers 8   # attacks 5-8 + FADE
# then rule-based ONLY for the gap:
python3 scripts/run_rule_based_sweep.py --clean --attack 3 --sim-time 60 --seeds 1
python3 scripts/run_rule_based_sweep.py --clean --attack 4 --sim-time 90 --seeds 1
```

### Step 3 — Monitor

```bash
tail -f logs/sweep_driver.log                         # driver progress + build output
ls logs/rule_based_sweep/A*.log 2>/dev/null | wc -l   # runs started
ls ~/ns-allinone-3.35/ns-3.35/results_routing/MOBIGUARD_Attack*_seed1.csv | wc -l  # completed (target 48)
pgrep -c routing                                      # concurrent sims (0 = done)
```

The `_seed1.csv` final name appears only **after** each sim finishes (the runner
writes `MOBIGUARD_Attack<N>_<pct>.csv` during the run, then renames it). So
mid-run you will see non-seed files; that is normal.

### Step 4 — Generate the logs

Once `pgrep -c routing` returns 0:

```bash
python3 scripts/audit_equations.py --self-test --no-color \
  > docs/task8_verification/equation_audit.log

python3 scripts/functional_verification.py --no-color \
  > docs/task8_verification/functional_verification.log
```

Scope to one attack while debugging with `--attack N`; point at a specific
directory with `--results-dir <path>` (repeatable).

---

## 5. Reading the output

Bottom-line summary looks like:

```
result: 240 PASS, 1 FAIL, 59 WARN
```

- **FAIL > 0** → a real defect to explain. This is the number that matters.
- **WARN** → coverage gaps (subsystems not exercised because that sweep/artefact
  was absent). WARNs shrink as you run more sweeps; they are not defects.
- `--strict` exits non-zero iff there is at least one FAIL.

Each line names its equation and metric, e.g.:

```
[PASS] FV19 eq:delay_updated  M6   attack inflates end-to-end latency vs clean
       avg_lat_ms: attacked=97.9250 >= clean=22.8274
```

---

## 6. The no-bypass attestation (GROUP A1) — why this is Task-8 evidence

Task 8 requires "correct coding **without bypassing modeling**." The build exposes
one kill-switch and ten ablation gates that each short-circuit a modelled
subsystem:

```
--disable_crypto                 --enable_lrad_obu        --enable_lrad_rsu
--enable_stark_delay             --enable_stark_hop       --enable_witness_mechanism
--enable_quarantine              --enable_endorsement_requirement
--enable_controller_failover     --enable_key_rotation    --enable_lstm_inference
```

A run made with any of them off is an **ablation** run, not full-system evidence.
GROUP A1 attests, per subject, that none were set:

1. **Authoritative source:** the runner writes `# Command: …` as line 1 of each
   run log. GROUP A1 parses it and FAILS if a bypass flag is present. (This is
   why the run logs matter — keep them.)
2. **Artefact fallback:** where the command line is unavailable, it proves the
   subsystem *executed* from its own output (e.g. crypto ⇒ non-zero sign/verify
   ops + crypto bytes; key rotation ⇒ `bc_dkg_log` round > 1).

---

## 7. Coverage & known caveats

**Attack families** (`main.tex` "Attack Scenarios"):

- Variants 1–4 = **Selective Time Delay** (1–2 direct injection, 3–4 via TCAM
  exhaustion). Variants 5–8 = **Hidden Forwarding** (5–6 active, 7–8 passive).

**Caveats to be aware of when reading a log:**

1. **UCR bug (genuine, code-level).** `routing.cc:117476` computes `current_UCR`
   as a *cumulative* eavesdrop counter ÷ a *non-cumulative* packet total, so
   `cur_UCR` can exceed 100 % (observed 150 %). The GROUP B UCR range check is
   **right to FAIL** on this — it is a real defect in `calculate_ucr_metric()`,
   not a script fault. Re-running will not fix it; it needs a code change.
2. **TCAM at 40 s under-collects.** The TCAM table only saturates at ≈ 22.8 s
   (256 entries ÷ 20 pps + 10 s start), so at 40 s S3/S4 barely fire. For strong
   Attack-3/4 evidence, re-run them at `--sim-time 60` / `90` respectively
   (see the per-attack timing in `run_tcam_sweep.py`). At 40 s the TCAM groups
   will show thin evidence / WARNs — expected, not a fault.
3. **TAP/FADE baselines are external, not the proposed system.** GROUPs O and P
   verify the B1/B2/B3 comparators only for the deliverable-5 comparison. Their
   absence WARNs; it never means MOBIGUARD is unverified. `enable_tap` defaults
   to `false`, and `run_rule_based_sweep.py` never enables it — so a MOBIGUARD-only
   sweep produces no TAP files.
4. **Stale leftovers.** `--clean` only removes `MOBIGUARD_Attack*` files. Old
   `TAP_*`, `bc_*_TAP`, `FADE_*`, or files for combos a sweep doesn't regenerate
   linger. They cannot corrupt results (the verifier selects newest-mtime and
   `split_runs()` segments any concatenated file), but delete them **after** a run
   for a clean folder. Never delete mid-run.
5. **Result files older than the newest `scratch/` source** are flagged by GROUP A
   as "PREDATES the current simulator sources" — re-run that sweep; failures
   below such a banner may already be fixed in the current code.

---

## 8. Manual timing (deliverable 3)

Two complementary pieces:

- **GROUP J** in `functional_verification.py` proves causal ordering from
  `crypto_timing_log.csv`: sign precedes verify for every packet; no escalation
  precedes the OBU detection that raised it; consensus rounds completed.
- **`scripts/crypto_scripts/timing_report.py <raw_run_log>`** is the deeper
  6-part timing proof (global causal order, per-packet chain, 50 ms batch-tick
  precision, T_ref dependency, STARK timing, witness timing). It needs a raw
  NS-3 run log (one of the files in `logs/` or `logs/rule_based_sweep/`).

---

## 9. File map

```
Final-Year-project/
├── scripts/
│   ├── audit_equations.py            # deliverable 1
│   ├── functional_verification.py    # deliverable 2
│   ├── verify_metrics.py             # shared CSV schema + parser (dependency)
│   ├── run_std_attacks.py            # attacks 1,2 + TAP;  --build syncs+compiles
│   ├── run_hf_attacks.py             # attacks 5-8 + FADE;  --build syncs+compiles
│   ├── run_rule_based_sweep.py       # all 8, MOBIGUARD only;  --build syncs+compiles
│   └── crypto_scripts/timing_report.py   # deliverable 3 (deep timing)
├── logs/
│   ├── A<N>_pct<pct>_...log          # std/hf run logs
│   ├── rule_based_sweep/*.log        # rule-based run logs
│   └── sweep_driver.log              # nohup driver output
├── docs/task8_verification/
│   ├── FUNCTIONAL_VERIFICATION_GUIDE.md   # this file
│   ├── equation_audit.log                 # deliverable 1 output
│   └── functional_verification.log        # deliverable 2 output
└── scratch/                          # NS-3 sources (synced into ns-3 tree on build)

~/ns-allinone-3.35/ns-3.35/results_routing/   # all CSV output
```
