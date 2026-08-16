# Q1–Q6 Component-Isolation Ablation — HPC Runbook

**Status:** ready to run. Local laptop runs were abandoned on wall-clock grounds
(~6 h at 8 workers, thermally limited at 93–97 °C). This is an HPC job.

**Owner of this doc:** whoever runs the sweep on the cluster. Read §1 and §6
before starting; §5 is what you send back.

---

## 0. What this is, and what it is NOT

This is the **supervisor's Q1–Q6 diagnostic**, which isolates *detection
components* (rule signatures / crypto / LSTM / witness).

It is **not** any of the thesis's own AB* ablations, which already exist and are
unaffected by this work:

| Existing | Ablates | Script |
|---|---|---|
| AB1 / AB4 | OBU-vs-RSU engine modes; STARK proof variants | `scripts/run_ablation_sweep.py` |
| AB3 | LSTM feature set (5-feature vs 7-feature) | `lstm_pipeline/src/ab3_feature_ablation.py` |
| **Q1–Q6** | **detection components** | **`scripts/run_q1q6_ablation.py`** |

The purpose, in the supervisor's words, is to *"confirm each component is wired
correctly and contributing in the expected direction"* — **not** to produce
publishable performance numbers. See §6 for why that distinction matters.

---

## 1. Prerequisites on the cluster

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35        # NS3_DIR default matches this
./waf build                                   # or via the launcher, see below
```

Checklist — all five must hold or results are silently wrong:

1. **Binary built in `optimized` profile, not `debug`.** Check before
   anything else:
   ```bash
   grep BUILD_PROFILE build/c4che/_cache.py
   ```
   `ns-3`'s default/first-time `./waf configure` produces a **`debug`**
   build (`-O0`, plus `NS3_ASSERT_ENABLE` and `NS3_LOG_ENABLE` compiled in).
   Measured 2026-08-10 on a single lane, same config, same machine, only the
   build profile differed:

   | Profile | Wall-s per simulated second |
   |---|---|
   | `debug` (`-O0`) | **88.6** |
   | `optimized` | **7.43** |

   **≈12× faster.** That is *not* the naive `-O0`→`-O2` codegen difference
   alone (typically 2–5×) — most of it comes from `NS3_ASSERT_ENABLE` and
   `NS3_LOG_ENABLE` being fully compiled out in `optimized`, and those checks
   run on nearly every packet/event throughout ns-3's core, not just in
   `routing.cc`. Detection correctness was spot-checked post-switch (MCC,
   DR, FPR in the expected range for the config tested) — the numbers below
   are unaffected, only wall-clock is.

   To build in `optimized`:
   ```bash
   ./waf configure --build-profile=optimized --enable-examples --disable-werror
   ./waf build
   ```
   `--disable-werror` is required on this checkout as of 2026-08-10: an
   `optimized` build recompiles the whole tree from scratch (a `debug` build
   here had been incremental for a long time), and that surfaces
   pre-existing `-Wunused-result` warnings (unchecked `std::system()` return
   values in `routing.cc`, `lstm_logger.h`, `efade_detection.h`) that
   `-Werror` turns into hard failures. These are unrelated to detection
   logic — safe to suppress for the build, not worth fixing line-by-line
   under a time constraint. Before reaching for it, one real bug **was**
   found and fixed this way: `routing.cc`'s `size_channel.CW` (a
   `custom_struct` field) was read without ever being assigned. Traced and
   confirmed harmless — `check_and_transmit()`, the only function this
   struct reaches, overwrites `.CW` as its first statement before ever
   reading it, so the uninitialized value was always dead — but it's exactly
   the class of bug `-O0` silently tolerates and `optimized`'s stricter
   data-flow analysis correctly flags. Fixed by zero-initializing at the
   declaration site.

   **Do not test the binary by invoking it directly**
   (`./build/scratch/routing/routing ...`) — it will fail with
   `error while loading shared libraries: libns3.35-*-optimized.so: cannot
   open shared object file`, because the optimized `.so`s are named
   differently and only `./waf --run`/`--run-no-build` sets up the correct
   `LD_LIBRARY_PATH`. That failure is a testing-methodology mistake, not a
   build problem.

   **Provenance note:** the Q1/Q4/Q5 results already in the report were
   measured on a `debug` binary. This does not affect their validity — same
   source, same arithmetic — but if asked, that's the honest answer to "were
   all results produced under identical build conditions."
2. **Binary present** at `$NS3_DIR/build/scratch/routing/routing`.
   The runner refuses to start if it is missing.
3. **Scratch synced.** The real source lives in
   `~/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/scratch/`; `scratch/routing/` in
   the ns-3 tree is symlinks/copies. Sync + build with:
   ```bash
   cd ~/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project
   python3 scripts/run_std_attacks.py --build
   ```
   A plain `./waf build` does **not** copy the `.py` helpers and the sim will
   abort mid-run with "Solution not found".
4. **Mobility traces present** at the paths compiled into `routing.cc`
   (`/home/nipuni/mobility/...`). On the cluster these are
   the real paths — no swapping needed. Seeds 1–5 use
   `mobility_urban_150_seed{N}.tcl`.
5. **`lstm_pipeline/lstm_weights_cpp.bin` exists.** Q3 and Q6 set
   `--enable_lstm_inference=1`, but if the weights file is absent the LSTM
   **silently no-ops**, `flag_LSTM` stays false, and Q3/Q6 look like a wiring
   failure when they are actually a missing file. Check it explicitly:
   ```bash
   ls -la lstm_pipeline/lstm_weights_cpp.bin
   ```

---

## 2. Running it

```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project

python3 scripts/run_q1q6_ablation.py --table      # flag mapping, runs nothing
python3 scripts/run_q1q6_ablation.py --dry-run    # all 48 commands, runs nothing
python3 scripts/run_q1q6_ablation.py --workers 16 # execute
```

`NS3_DIR` defaults to `~/ns3_g13/ns-allinone-3.35/ns-3.35`. Override without
editing the file:

```bash
NS3_DIR=/some/other/path python3 scripts/run_q1q6_ablation.py --workers 16
```

**Run Q4 first.** It is the single load-bearing check (§4), it is 8 runs rather
than 48, and if it fails there is no point running the rest:

```bash
python3 scripts/run_q1q6_ablation.py --configs Q4 --workers 8
python3 scripts/run_q1q6_ablation.py --analyse            # inspect
python3 scripts/run_q1q6_ablation.py --configs Q1,Q2,Q3,Q5,Q6 --workers 16
```

Configs compose — each writes its own tagged CSV, so a later invocation does not
redo earlier ones.

### Sizing

**Check the build profile before trusting any of these numbers** — see §1
item 1. Everything below assumes `optimized`.

**Superseded 2026-08-14 (supervisor Fix 4): `--sim-time` default is now 300 s,
not 30/90.** 90 s runs (used throughout the 2026-08-13 session) yield only 9
evaluation blocks/RSU (6 post-warmup) against 300 s's 30 (27 post-warmup) —
late-run detection events (A4 TCAM saturation, A8 witness accumulation) never
appear in a 90 s window. `lstm_pipeline/src/preprocessor.py`'s `MAX_CYCLE=310`
already anticipated 300 s runs (set 2026-08-02) and needs no change. Below,
read every "90 s" figure as the prior (now-superseded) spec — re-measure at
300 s before trusting wall-clock projections for a real sweep; a 300 s run is
roughly 3.3x a 90 s one, so the `optimized` single-lane 20-40 min projection
below becomes plausibly 65-135 min at 300 s.

Throughput is expressed as wall-seconds per simulated second, since `simTime`
varies by spec (30 s originally, 90 s for Q1/Q4/Q5 so `detector_windows.csv`
clears the M1 evaluator's 30-cycle warm-up exclusion, 75 s tried for Q6):

| Build | Wall-s / sim-s | 90 s run, 8-lane config |
|---|---|---|
| `debug` (measured on Q1/Q4/Q5) | 143–158 | 3 h 34 m – 3 h 57 m |
| `optimized` (single-lane measurement) | **7.43** | plausibly **20–40 min** |

The `optimized` figure is a **single isolated lane**, not an 8-lane run under
full contention — expect the real 8-lane number to land somewhat above the
naive scaling, and re-measure once an actual 90 s config has been run on this
binary rather than trusting the projection. Configs with natural crypto (Q2,
Q5, Q6) may benefit less than this ratio suggests: `liboqs` is a separately
built, already-optimized library, so its ML-DSA-87 calls don't speed up
further — only the ns-3/`routing.cc` glue code around them does.

Old rule of thumb, for reference only (`simTime=30`, `debug` build, unclear
worker count): ~58–61 min/run. That resolves to ~116–122 wall-s/sim-s, roughly
consistent with the 143–158 figure above once accounted for.

Sims are single-threaded, so wall time ≈
`ceil(48 / workers) × (per-run time at the chosen simTime)`. Give each worker
one physical core; oversubscribing hyperthreads did not help locally.

---

## 3. The six configurations

Generated by `--table`, from the same dict that builds the commands, so the
table cannot drift from what actually runs.

```
        S1/S2     S3/S4     S5/S6     S7/S8      LSTM   witness        crypto
Q1    live(0)   live(0)    off(1)    off(1)    off(0)   off(0)   forced pass(1)
Q2     off(1)    off(1)   live(0)   live(0)    off(0)   off(0)       natural(0)
Q3     off(1)    off(1)    off(1)    off(1)     on(1)   off(0)   forced pass(1)
Q4     off(1)    off(1)    off(1)    off(1)    off(0)    on(1)   forced pass(1)
Q5    live(0)   live(0)   live(0)   live(0)    off(0)   off(0)       natural(0)
Q6    live(0)   live(0)   live(0)   live(0)     on(1)    on(1)       natural(0)
```

### Flag semantics — read before interpreting anything

* `g_disable_s5_s6` / `g_disable_s7_s8` gate the **signature computation**, so
  the flag, `D_RSU`, the BTMM trust penalty and the BC.Write record all go
  silent together. Without this, a "disabled" S7/S8 kept penalising trust and
  writing to the ledger, and Q4 could not isolate anything. These flags were
  added for this ablation; they did not previously exist.
* `g_disable_s3_s4` gates **only** the confusion-matrix recording, deliberately
  **not** `flag_s3`/`flag_s4`. Those still publish
  `g_tcam_flag_s3_last/s4_last`, which `lrad_rsu()` reads as the `eq:lstm_gate`
  (main.tex:3317-3326) LSTM suppression gate. That gate's rationale is
  *structural* — TCAM residual occupancy inflates reconstruction error all run —
  so it must stay live even while S3/S4's own output is off. Gating the flag
  would silently un-suppress the LSTM in Q3, the very run meant to isolate it.
  **This asymmetry is intentional and supervisor-confirmed. Do not "fix" it.**
* `disable_crypto=1` is how "b_batch = 1 and b_hop = 1 everywhere" is achieved:
  `mldsa87_verify()` and `stark_verify_hop()` both short-circuit to true.
* `enable_witness_mechanism` **defaults to true**, so every non-witness config
  passes 0 explicitly or the witness path leaks in.

---

## 4. Expected pattern — check before sending results

From the supervisor. Any violation must be reported with the exact variant and
numbers, *before* proceeding.

| Config | Expectation |
|---|---|
| Q1 | TP > 0 on A1–A4; TP = 0 on A5–A8 |
| Q2 | TP = 0 on **all** variants (b_batch cannot go false in simulation, so no crypto-only signature can fire) |
| Q3 | TP = 0 on A3/A4 (LSTM gated); TP > 0 on A1/A2/A5–A8; **nonzero suppression count** |
| Q4 | TP = 0 on A1–A6; **TP > 0 on A7/A8** |
| Q5 | Improvement over Q1 on A5/A6 (crypto + rule co-firing) |
| Q6 | Dominates every configuration on every variant |

> **Q4 is the stop condition.** Supervisor: *"if A7/A8 show TP = 0 in Q4 the
> witness is not working and experiments must not run."*

For Q3, a zero suppression count alongside TP = 0 on A3/A4 means the **LSTM
never ran** (see §1.4), not that the gate worked. The two are indistinguishable
in the confusion matrix alone — that is why the count is reported separately.

---

## 5. What to report back

`--analyse` emits all of it:

```bash
python3 scripts/run_q1q6_ablation.py --analyse
```

1. Per-variant **TP/FP/FN/TN** and **MCC** for each of Q1–Q6.
2. **Cumulative MCC table** — Q1, Q3, Q4, Q5 standalone, then Q6.
   (Q2 is omitted: expected all-zero, which gives a degenerate MCC of 0.)
3. **LSTM suppression count** for Q3 and Q6, per variant.
4. The **pre-retrain caveat** in §6 — printed automatically, do not drop it.

---

## 6. Mandatory interpretation caveats

**The LSTM is pre-retrain and was trained on stale data.** Two independent
corruptions, both fixed in the code but *not* in the model currently in the repo:

* `zkp_delay_fail` was **identically zero for A2 across all 1792 training rows** —
  a constant column contributing no gradient. Measured by matched A/B: pre-fix
  0 RSUs / 0 cycles, post-fix 37 RSUs / 187 cycles.
* **A6/A8 labels were corrupted** before the label fix (vehicle attackers left
  every RSU row at `label=0`).

⇒ **Q3 and Q6 LSTM numbers are lower bounds, not final figures.** The supervisor
has confirmed these will not be used in the paper.

**`zkp_hop_fail` is structurally zero for A2/A4** and that is correct, not a bug.
Per `eq:stark_hop` (main.tex:2993-3010), π_hop encodes *next-hop policy
compliance*; a delay attack never violates it. Only the misrouting families
A5–A8 exercise π_hop. Verification criterion per family:

* **A2, A4** → verify `zkp_delay_fail`
* **A6, A8** → verify `zkp_hop_fail`

**Q3 runs on 9 effective features, not 8.** `zkp_hop_fail` zeroes out under
`disable_crypto` but `zkp_delay_fail` does not — it is a raw wall-clock
comparison (routing.cc:121884) with no crypto gate.

---

## 7. Q4 must be read from the witness counters, NOT the confusion matrix

**This was found, diagnosed and resolved locally. The tooling already does the
right thing — this section explains why, so the output is not misread.**

A partial Q4 run completed 4 of 8 lanes locally. Read two ways:

| Q4 | generic TP | generic FP | **witness TP_W** | **FP_W** | **FN_W** | precision % | recall % | dup alerts |
|---|---|---|---|---|---|---|---|---|
| A3 | 0 | 0 | **0** | 0 | 0 | – | – | 0 |
| A5 | **32** | 167 | **0** | 0 | 0 | – | – | 16319 |
| A7 | 27 | 173 | **37** | 202 | 2 | 15.48 | 94.87 | 14777 |
| A8 | 37 | 31 | **102** | 70 | 56 | 59.30 | 64.56 | 3720 |

Read from the **generic confusion matrix**, A5 shows TP = 32 and looks like a
violation of "TP = 0 on A1–A6". Read from the **witness's own counters**, A5 is
`TP_W = 0` — the witness detected nothing there, and the expected pattern holds
exactly: witness signal on A7/A8 only.

**Why the generic matrix is the wrong instrument here.** In Q4 every signature is
disabled, and the witness path never calls `record_detection_event()` directly.
It reaches the confusion matrix only indirectly:

```
witness -> trust_update_negative() -> trust < TRUST_T_MIN -> quarantine
        -> record_detection_event()          (crypto_layer.h:1070-1074)
```

So the generic TP/FP in Q4 answer *"did trust collapse far enough to
quarantine"*, not *"did the witness detect"*. Any node drifting below the trust
threshold is recorded regardless of cause, which is also why FP is so high
(167, 173 ⇒ FPR ≈ 73–75 %) and MCC is near zero or negative.

A5's 16319 duplication alerts were logged but **none reached the 2f+1 BFT
threshold**, so no witness detection was registered — correct, since the witness
targets passive hidden forwarding, not active HF control-plane.

**What to do:** `--analyse` prints a dedicated *WITNESS-NATIVE COUNTERS* block
for Q4 and Q6. Use it for Q4. Report the generic matrix too, but state that in
Q4 it reflects the quarantine path.

**Still worth reporting to the supervisor:**

* **A7 precision is poor (15.5 %) against excellent recall (94.9 %).** The
  witness finds nearly everything and misattributes most of it. That is a BFT
  threshold characteristic (`--witness_f`, threshold `2f+1`), not a detection
  failure. A8 is better balanced (59.3 % / 64.6 %).
* Optional confirmation of the mechanism: re-run Q4 with
  `--enable_quarantine=0`. That cuts the indirect path, so the generic matrix
  should go to TP = 0 everywhere while `TP_W` is unchanged.

---

## 8. Gotchas

* **Do not commit local path swaps.** `routing.cc` stores cluster paths
  (`/home/sdvn_hidden_attacks/ns3_g13/...`) intentionally. On a dev laptop use
  `scripts/local_path_swap.sh local` before running and `... hpc` before any
  `git add`. On the cluster no swapping is needed.
* **Result files collide.** `write_security_metrics_csv()` names by
  `(attack_number, pct, delay, seed)` via `g_sim_tag` (`routing.cc:143958`) —
  the **ablation tag is not in the name**. The runner therefore runs one
  **sequential lane per attack** and renames immediately after each run. Do not
  parallelise within a lane.
  The runner's `result_filename()` must mirror `g_sim_tag` *exactly*, seed
  included. It did not until 2026-08-08: `_seed{S}` entered the simulator's
  names in #87 but was never added here, so every lookup missed, the rename
  silently never fired, each config overwrote the previous one under the shared
  name, and `--analyse` reported `MISSING` for all 48 cells. A full sweep can
  therefore run to completion and yield nothing. If `g_sim_tag` gains another
  component, update `result_filename()` in the same commit.
* **Clear stale lane logs** before a re-run (`logs/q1q6_ablation/*.log`). The
  LSTM suppression count is parsed from them, and stale files give wrong counts.
* **The CSV header is multi-line.** `write_security_metrics_csv()` emits several
  `#`-prefixed header lines, so `csv.DictReader` sees only the first 7 names
  while rows carry ~52 fields. Parse **positionally**; `read_confusion()` in the
  runner documents the layout. Column order is `TP, FP, TN, FN` — TN before FN.
