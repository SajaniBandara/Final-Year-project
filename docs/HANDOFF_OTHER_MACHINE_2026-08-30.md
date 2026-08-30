# Handoff — work to run on the machine that has the LSTM dataset

Written 2026-08-30. Everything here is blocked on, or much faster on, a machine
other than the laptop the recent A1/A2 work ran on.

**Read section 1 before running anything.** The path-swap script only knows two
machine conventions and will silently do the wrong thing on a third, and two
path families it does not handle at all are exactly the ones LSTM work needs.

---

## 0. Prerequisites

```bash
cd <REPO_ROOT>            # the Final-Year-project checkout
git checkout n11 && git pull
```

You need these commits:

| commit | what it adds |
|---|---|
| `1448111` | `--s1_suppress_handoff_fp` (item 7 handoff-jitter fix, default OFF) |
| `f90f6fc` | `score_cycles` / `score_primary_cycles` columns |
| `b5f3857` | persistence sweep tool + `t=` on the `[S5]` trace |

**Schema change:** `detector_windows.csv` is now **11 columns, not 9**. Do not
glob old and new files together — the analysis tool refuses pre-change files
outright, but ad-hoc scripts will not.

Then build (see section 1 first — build AFTER paths are correct, because
`routing.cc`'s paths are compiled in):

```bash
./waf build
```

---

## 1. Paths — check before assuming

### 1a. Find out what convention this machine is on

```bash
cd <REPO_ROOT>
./scripts/local_path_swap.sh status      # counts files per convention
echo "HOME=$HOME"
pwd                                       # where the repo actually lives
ls -d ~/mobility 2>/dev/null || find ~ -maxdepth 3 -name "mobility_urban_150_seed1.tcl" 2>/dev/null | head -1
find ~ -maxdepth 5 -type d -name lstm_training 2>/dev/null | head -1
```

### 1b. The script handles exactly TWO conventions

`scripts/local_path_swap.sh` rewrites between:

- a cluster form — `/home/<cluster-user>/ns3_g13/ns-allinone-3.35/ns-3.35/`
- a laptop form — `/home/<laptop-user>/ns-allinone-3.35/ns-3.35/`

plus the matching `.../mobility/` pair.

**If this machine is neither**, do NOT run `local` or `hpc` — it will rewrite
paths to a machine that is not this one. Instead do a targeted `sed` from
whichever form is currently in the tree to this machine's real paths, over the
same file set the script would touch:

```bash
grep -rIl --exclude-dir=.git -e '/home/' <REPO_ROOT> | grep -v local_path_swap.sh
```

### 1c. TWO path families the script does NOT handle — both matter here

| family | where | matters when |
|---|---|---|
| `.../g13_project_repo/Final-Year-project/` | `scratch/lstm_logger.h` (3 sites) | `--training=1` or `--enable_lstm_inference=1` |
| `$HOME` + `ns3_g13/ns-allinone-3.35/ns-3.35/results_routing` | `lstm_pipeline/src/preprocessor.py` (`BASE`), `evaluator.py` (`RESULTS`) | **any LSTM pipeline work, including task 1** |

The second one has no leading or trailing slash, so the script's `$HOME`-relative
rule does not match it. Check and fix both by hand:

```bash
grep -n "g13_project_repo" scratch/lstm_logger.h
grep -nE "^(BASE|RESULTS) *=" -A1 lstm_pipeline/src/preprocessor.py lstm_pipeline/src/evaluator.py
```

`BASE` must resolve to the directory that CONTAINS `lstm_training/`. Repo-internal
paths (`preprocessed/`, `models/`) are derived relatively and are portable — leave
them alone.

### 1d. Two failure modes, different timing — both silent

- **Helpers** (`scratch/optimization*.py`) are read **fresh every cycle**. Wrong
  paths → `Unexpected error in link lifetime optimization` / `Solution not found`
  each cycle. The run does not crash, it **degrades** — routing/delay results
  become invalid. Observed on the laptop: 28 minutes of CPU for 3.7 simulated
  seconds.
- **`routing.cc`'s mobility path** is **compiled in**. Wrong at build time →
  every run aborts instantly with `Could not open trace file`.

So: fix paths → rebuild → verify → run. And **never** swap paths while a
simulation is running; the ns-3 tree's `scratch/optimization*.py` are symlinks
into the repo.

Verify before trusting any run:

```bash
grep -c "Solution not found\|Unexpected error in link lifetime" <run.log>   # must be 0
```

---

## 2. Task 1 — finding (b) cross-check  *(supervisor's stated first priority)*

**Impossible on the laptop:** zero A5–A8 `lstm_training` CSVs exist there, and
`test_meta.npy` holds only `attack_v` 0–4.

Already answered from code, no run needed: `y_indep` is built in
`lstm_pipeline/src/preprocessor.py:235-238` as

```python
_inj = max(hfgt[i:i+window].max(), stdgt[i:i+window].max(), tcamgt[i:i+window].max())
yi_list.append(1 if (av > 0 and _inj > 0) else 0)
```

i.e. **a per-cycle EVENT counter, OR-ed (`max`) across the 10-cycle window** —
not a persistent state flag. For the HF variants its source is `hf_send_gt`,
which is **the same signal item 9 proved too coarse**, so `y_indep` is literally
the window-level OR of item 9's per-cycle gate.

**What to measure:** for A5, the fraction of windows with `y_indep == 1`,
against S5's measured 45–53% per-cycle firing rate.

**Prediction:** item 9's ~10% per-cycle `hf_send_gt` rate implies about
`1-(1-0.10)^10 ~= 65%` per window if cycles were independent, versus S5's
per-window rate of essentially 100%.

- lands near **65%** → one defect at two granularities → fix jointly with item 9
- lands near **100%** → the window OR already launders the coarseness → only
  item 9 needs fixing

---

## 3. Task 2 — item 9 S5 per-condition trace  *(supervisor asked for it in parallel)*

Run A5 @60%, 300 s, then inspect `[S5]` lines — they now carry `t=`.

Each line prints conjunctions 3 and 4 (`mldsa_fails`, `b_hop_fails`), and
**reaching that line proves conjunctions 1 and 2 held**, because both
early-return above it. Join `t=` to cycles and compare against the per-cycle
`hf_send_gt` column to isolate the fired-but-gate-zero cycles.

**Expected result, already established from the code:** conjunctions 1–2 are
persistent state — the FlowMod stays unendorsed, and
`active_hf_malicious_nodes[]` is assigned once in `hf_declare_malicious_rsus()`
and never cleared anywhere. So S5 fires on an **ongoing compromised state**
while `hf_send_gt` marks only the instant a duplicate is scheduled. S5 firing
more often is therefore **correct detection, not a bug**, and the replacement
signal should be a **latched** `hf_send_gt` ("has this RSU ever scheduled a
duplicate up to now") rather than a narrower per-event one.

The trace confirms conjunctions 3–4 behave as expected; it cannot change 1–2,
which are structural.

---

## 4. Task 3 — handoff-fix validation  *(unblocks reporting)*

Seed 1 gave zero-attack window FPR **0.03%** and A1 recall **95.55%**. The
published table is 5-seed, so this is what makes it reportable at equal rigour.

```bash
# 4 more zero-attack seeds
--simTime=300 --sim_seed={2,3,4,5} --enable_detector_windows=1 --s1_suppress_handoff_fp=1

# A2 recall -- the config where the best-effort arm collapsed worst (99.94% -> 81.22%)
--simTime=300 --sim_seed=1 --attack_number=2 --attack_percentage=60 \
  --attack_delay_ms=80 --attack_delay_pseudo_random=0 \
  --enable_detector_windows=1 --s1_suppress_handoff_fp=1
```

---

## 5. Task 4 — the combination nobody has measured

Zero-attack + A1 + A2 with **both** `--s1_suppress_handoff_fp=1` **and** the
count columns (the columns are automatic once built from `f90f6fc`).

Measured so far, seed 1, A1:

| approach | zero-attack FPR | A1 recall | MCC |
|---|---|---|---|
| baseline k*sigma | 18.86% | 99.13% | 0.637 |
| persistence M=3 | 0.06% | 79.11% | 0.721 |
| handoff fix | **0.03%** | **95.55%** | **0.840** |

The combination at M=2 may beat all three. Because M sweeps offline from the
count columns, this is **3 runs, not 3 x N**.

---

## 6. Analysis (either machine, once runs land)

```bash
python3 scripts/item7_persistence_sweep.py \
  --results-dir <RESULTS_ROUTING_DIR> \
  --baseline detector_windows_Attack0_0_seed1_<tag>.csv \
  --attack   detector_windows_Attack1_60_d80ms_seed1_<tag>.csv \
  --attack   detector_windows_Attack2_60_d80ms_seed1_<tag>.csv
```

Self-check built in: **M=1 must reproduce the published k*sigma figures** —
zero-attack window FPR 18.86%, and A1 TP=802 / FP=684 / FN=7 / TN=2219,
recall 99.13%, FPR 23.56%. M=1 is by definition today's OR behaviour, so if it
does not match, the run or the columns are wrong. It reproduces both exactly on
the laptop's A1 data.

Recall is printed twice — un-deduplicated (matches the published A1/A2 table,
n=3712) and deduplicated (`eq:eval_dedup`, n=1856). The two differ by 2x in
absolute counts; do not mix them.

---

## 7. Do NOT run

**The Q3–Q6 grid.** Supervisor's explicit instruction — too much of what feeds
it is unsettled (finding (b)'s rescore decision and item 9's gate signal are
both still open), so it would bake in known problems and need redoing.
