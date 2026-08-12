# Two-Machine LSTM Collection Plan — 2026-08-07

**Purpose:** first-stage LSTM training-data collection (benign seeds 1-3 +
all attacks at seed 4), split across this machine and a second PC. Read this
before launching or resuming anything in this batch.

---

## 0. Why this restart happened

Two independent things changed mid-collection, both invalidating the batch
that was running before this plan:

1. **`lambda_PI` was reading a dead counter.** `scratch/lstm_logger.h` read
   `g_slowpath_hit_count` — a counter gated to A3/A4-only at TCAM-full, which
   never fires in a benign run, so the feature was constant/zero-variance in
   every training row collected so far. Fixed to read `g_packetin_count`
   instead (the same live counter S4 already uses). **Source-only until
   rebuilt** — any job already running when the fix landed kept using the
   old binary regardless.
2. **`simTime` changed 180s → 120s.** Row counts, warm-up-window proportion,
   and block counts all depend on run length, so partially- or
   fully-collected 180s data can't be reused or truncated into a 120s
   dataset.

Both changes landed before any of this stage's data was collected under the
new spec, so **all previously-collected data for this batch (benign seeds
1-4 + attack-val seed 4, ~1984 CSV files) was deleted** rather than
partially reused. The binary was rebuilt with the fix
(`./waf build`, succeeded 2026-08-07 ~21:02) before anything in this plan
launches.

**One build-environment gotcha hit and fixed along the way:** the merge that
brought in `eq:theta_adapt` / `detector_windows.h` added a new source file
to the repo, but the NS-3 build tree's `scratch/routing/` symlink set
(`CLAUDE.md`'s "every file in scratch/ is symlinked") doesn't auto-update for
*new* files — only existing symlinks track edits. `detector_windows.h` was
missing its symlink in `~/ns3_g13/ns-allinone-3.35/ns-3.35/scratch/routing/`,
which failed the build (`fatal error: detector_windows.h: No such file or
directory`). Fixed with one `ln -s`. **If a future pull adds a new file to
`scratch/`, check for this before assuming the build will just work.**

---

## 1. Scope of this stage

Full remaining scope (per `main.tex`): `TRAIN_SEEDS={1,2,3}` (benign only),
`VAL_SEEDS={4}` (all 8 attacks × 6 pcts), `TEST_SEEDS={5}` (all 8 attacks × 6
pcts + benign). This plan covers **only** the first two pieces — benign
1-3 and the seed-4 validation split. Seed 5 (the actual held-out test data)
and seeds 1-3 attack data are a later stage, not covered here.

| | Jobs | Machine |
|---|---|---|
| Benign, seeds 1, 2, 3 | 3 | A |
| Attacks 1-6, seed 4, all 6 pcts | 36 | A |
| Attacks 7, 8, seed 4, all 6 pcts | 12 | B |
| **Total this stage** | **51** | |

`simTime=120` for every job in this stage.

## 2. Why this split

Machine A (32 cores) can run up to ~27 workers safely; Machine B (16 cores,
16.6GB RAM) is capped at 8 workers per the user's stated safe limit for that
machine. Splitting jobs roughly proportional to worker capacity
(27:8 ≈ 77:23) means both machines finish around the same time instead of
one idling while the other grinds through a backlog — 51 × 0.77 ≈ 39, which
is exactly the 3+36 = 39 jobs assigned to A. B's 12 jobs at 8 concurrent
workers is 2 short waves.

Attacks 7-8 (not e.g. 1-2) were picked for Machine B arbitrarily — there's
no dependency reason, any 2-attack slice works, this just kept the split
simple (a clean attack-number boundary rather than splitting by percentage).

## 3. Commands

**Machine A — run as two separate launcher instances (different seed sets
can't be expressed in one invocation), sized so their sum stays under the
self-throttle ceiling (see §5):**
```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
python3 scripts/run_training_attacks.py --attack 0 --seed 1 2 3 --sim-time 120 --workers 3
python3 scripts/run_training_attacks.py --attack 1 2 3 4 5 6 --seed 4 --sim-time 120 --workers 21
```
(3 + 21 = 24, comfortably under `0.85 × 32 = 27.2`.)

**Machine B — confirm repo is pulled to the commit with the `lambda_PI` fix
and rebuilt there before running:**
```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
git pull   # or however that machine syncs the repo
./waf build
python3 scripts/run_training_attacks.py --attack 7 8 --seed 4 --sim-time 120 --workers 8
```

**Check the `scratch/routing/` symlink set on Machine B before building** —
if it was set up before `detector_windows.h` existed in the repo, it'll hit
the same missing-symlink build failure described in §0.

## 4. Consolidation

No filename collisions: Machine A writes benign seeds 1-3 and attacks 1-6
(seed 4); Machine B writes attacks 7-8 (seed 4) — disjoint by construction
(`RSU_{r}/A{v}_pct{p}_seed{s}.csv`). Once Machine B finishes:
```bash
rsync -av machineB:~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/ \
    ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/
```
Pure directory merge, no reconciliation logic needed.

## 5. Why not just max out both machines' worker counts

`run_training_attacks.py`'s self-throttle (`LOAD_CEILING_FRAC=0.85`) pauses
new job launches once `load1 > 0.85 × nproc`. Two uncoordinated launcher
instances on the same machine can push combined load above that ceiling
purely from their own processes, stalling a job slot even with zero external
contention — observed directly on Machine A during the previous (now
discarded) batch: 26/27 workers active, 21 jobs queued, paused at
`load1=31.x > ceiling=27.2` for an extended period. Keep worker sums per
machine comfortably under `0.85 × nproc`.

## 6. Stage 2 (started 2026-08-08) — benign seed4 backfill + seed5 TEST split

Stage 1 (§0-5 above) finished cleanly on both machines: 51/51 jobs, merged into a single
`lstm_training/` tree on Machine A. `preprocessor.py` + `fed_aggregator.py` already ran once
against that data — 9/64 RSUs meet the 0.95 precision target, 23/64 show real signal
(MCC>0.3), 21/64 still dead/negative. This is the *pre-seed5* retrain, train+val only —
no test split existed yet at that point. `rule_calibrator.py` also ran against the stage-1
benign seeds 1-3: the β stage correctly rejected all 4 candidates (none converge within the
22s ceiling), matching the pre-existing HANDOFF finding on real data — see session notes /
`/tmp/supervisor_beta_message.md` for the actual numbers.

**Scope: 50 jobs.**

| | Jobs | Machine |
|---|---|---|
| Benign, seed 4 (backfill — seed4 attack data already existed from stage 1's VAL split, but no standalone `Attack0_0_seed4.csv`, needed for the calibration spec's 5-seed benign baseline) | 1 | A |
| Benign, seed 5 | 1 | A |
| Attacks 1-6, seed 5, all 6 pcts | 36 | A |
| Attacks 7-8, seed 5, all 6 pcts | 12 | B |
| **Total** | **50** | |

`simTime=120`, same as stage 1. Seed 5 is the actual held-out `TEST_SEEDS` split
`main.tex` reports final numbers on — nothing existed for it before this stage.

**Commands — Machine A (running):**
```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
python3 scripts/run_training_attacks.py --attack 0 --seed 4 5 --sim-time 120 --workers 2
python3 scripts/run_training_attacks.py --attack 1 2 3 4 5 6 --seed 5 --sim-time 120 --workers 10
```
Worker counts lowered from stage 1's 3+21 to 2+10 — a second, unrelated session
(`ns3_g13_apsari`, a separate working tree on the same machine) is concurrently running its
own ~19-process sweep, and the combined load was pushing well past the launcher's own
`load1 > 0.85×nproc` throttle ceiling (§5). Lower worker counts leave headroom instead of
adding to an already-oversubscribed machine (23 ours + 19 theirs = 42 processes on 32 cores
before the reduction; 12 + 19 = 31 after). Note the throttle checks *total* system load, not
just our own processes — if the other session's load climbs further, our launcher can still
pause waiting for headroom regardless of how low our own worker count is set; that part isn't
within our control.

**Command — Machine B (run this now):**
```bash
cd ~/ns3_g13/ns-allinone-3.35/ns-3.35
python3 scripts/run_training_attacks.py --attack 7 8 --seed 5 --sim-time 120 --workers 8
```

**Consolidation:** same as §4 — disjoint filenames (`RSU_{r}/Attack{v}_{pct}_seed5.csv`),
`rsync` Machine B's output into Machine A's `lstm_training/` once both finish, then re-run
`preprocessor.py` (rebuilds scaler/windows, now with a populated test split) and
`fed_aggregator.py` if a from-seed5 retrain comparison is wanted, and re-run
`rule_calibrator.py` for the full 5-seed β/S3-S4 spec plus `evaluator.py`/AB3 against the
now-real test split.

## 7. Remaining after stage 2

Seeds 1-3 attack data (144 jobs) — lower priority, not part of the official `main.tex`
train/val/test evaluation (`TRAIN_SEEDS` are benign-only), only needed if the fuller
245-job sweep is still wanted. Not started, no machine assigned yet.
