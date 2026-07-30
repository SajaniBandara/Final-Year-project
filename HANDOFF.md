# Handoff — LSTM FPR diagnostic / S3-S4 spec migration (2026-07-30)

## Where things stand

### Q30 diagnostic (pure-benign held-out seeds 6/7/8) — ANSWERED
Ran the trained global model against seeds 6/7/8 (simTime=60, 100% benign,
never used in train/val/test/calibration). Script: `lstm_pipeline/src/q30_holdout_eval.py`.

Result: **9.38% raw-window FPR / 12.71% dedup-block FPR** — 9-13x over the
1% target, on data with zero attack contamination. Per the supervisor's own
decision rule, this means the FPR excess is a genuine calibration/
generalization problem, NOT a contamination artifact from attack-run
network conditions. Do not report the TCAM (or any variant's) FPR excess as
"contamination, document as artifact" — that's ruled out.

Breakdown by RSU (script inline in the conversation, not saved as a file —
rerun by loading the model/scaler and grouping FPR by `rsu_id // 8` (row) /
`rsu_id % 8` (col)): **interior-grid RSUs average 14.2% FPR vs 3.2% for
edge RSUs** — ~4.5x gap, uncorrelated with theta value or n_train (both
flat across RSUs, n_train=51 everywhere). Interior junctions see more
seed-to-seed density/mobility variance than edge RSUs' sparser
through-traffic.

### Fixes tried against Q30, in order
1. **Q19 (window dedup)** — implemented in `evaluator.py`
   (`deduplicate_windows()`), kept. Does NOT reduce FPR — rules out
   overlap double-counting as the driver.
2. **Q27 (pooled density-stratified theta)** — tried, DR collapsed ~35pts
   network-wide, reverted.
3. **Q25 (dropout p=0.2)** — added to `lstm_model.py`
   (`self.drop_enc`/`self.drop_dec` between LSTM stages). KEPT — real but
   modest improvement: Q30 FPR 11.05%→9.38% raw, DR/MCC flat.
4. **Q27-narrow (interior-only z widening, z=5.0 vs 3.5)** — tried in
   `fed_aggregator.py`/`local_trainer.py`, informed by the interior/edge
   breakdown above. FPR only 9.38%→8.10%, but DR fell 8-12pts on
   A1/A2/A5/A7. Same bad trade-off shape as Q27, milder. **Reverted** —
   code and models both restored (see backups below).
5. **Q28 (speed-stratified)** — not attempted.

### Current deployed state (as of last pipeline run)
Models = dropout (Q25) only, no threshold stratification. Test-split
(seed 5) numbers:
```
A1 MCC=0.8668 DR=0.8254 FPR=0.0078
A2 MCC=0.8528 DR=0.8540 FPR=0.0242
A3 MCC=0.3465 DR=0.8417 FPR=0.3415
A4 MCC=0.3800 DR=0.9475 FPR=0.4031
A5 MCC=0.8691 DR=0.8527 FPR=0.0007
A6 MCC=0.9151 DR=0.9166 FPR=0.0008
A7 MCC=0.8571 DR=0.8398 FPR=0.0021
A8 MCC=0.8933 DR=0.8836 FPR=0.0000
Overall MCC=0.7266 DR=0.8702 FPR=0.1274
```
Q30 holdout: raw FPR=9.375% (162/1728), dedup FPR=12.708% (122/960).

Backups in `lstm_pipeline/`: `models_backup_20260723`,
`models_backup_20260730_preQ25` (pre-dropout), `models_backup_20260730_preQ27narrow`
(dropout-only, pre-interior-z — this is what's currently restored/deployed).
All gitignored now (`lstm_pipeline/.gitignore` updated to add `models_backup_*/`).

### Why A3/A4 MCC is so low despite decent DR
FPR (34%/40%) crushes MCC even with DR at 84-95%. Root cause per code
comments: `mask_va_benign` in both trainer files already EXCLUDES A3/A4
from theta calibration because elevated `U_TCAM` persists through the
whole run (structural, confirmed after A3/A4 re-collection), so
benign-labeled windows in A3/A4 runs still look anomalous to the model.

---

## Supervisor's proposed fix vs. thesis spec — checked, NOT yet implemented

Supervisor proposed gating `flag_LSTM` off in `LRAD-RSU` whenever S3/S4
fire (to eliminate LSTM-driven FPs on TCAM runs, arguing rule-based S3/S4
detection is already sufficient there).

**Checked against `docs/main.tex` Algorithm alg:lrad_rsu (lines
2470-2521):**

1. Current code (`scratch/lrad.h:327-328`) already matches the thesis
   exactly: `D_RSU` is a flat, unconditional OR of all 8 signals + LSTM.
   There is NO conditional-suppression term in the spec. Supervisor's gate
   would be a **deviation from the documented algorithm**, not a bug fix —
   needs to be proposed/justified as an algorithmic change and the thesis
   text updated to match, not silently patched into the code.

2. Separate, pre-existing, ALREADY-KNOWN spec mismatch (unrelated to the
   supervisor's point, and NOT included in the message sent to him — user
   decided to drop it from that message): per spec, S3/S4 should be
   RSU-side signals inside `D_RSU`'s OR (using `f_unauth`/blockchain
   endorsement for S3, `U_TCAM > U_thresh` for S4 — see
   `main.tex:2400-2410`). Current code puts S3/S4 in the OBU-side struct
   (`D_OBU`, `lrad.h:44-49`) using an older formula. Code's own comment
   (`lrad.h:64-71`) already flags this as unmigrated,
   referencing `DEV_MERGE_SPEC_CHANGES.md` items #3/#4.

3. Important: the A3/A4 FPR=34%/40% numbers reported above come from the
   **standalone Python LSTM evaluator** (`evaluator.py` scored against
   `test_meta.npy`), completely independent of `lrad.h`'s `D_RSU`
   composite. Neither the supervisor's proposed gate nor the S3/S4
   OBU→RSU migration would change those specific numbers — both are
   C++ runtime changes requiring a full NS3 rebuild + rerun to see any
   effect on live detection-event counts, a different metric than what
   `evaluator.py` reports.

Message sent to supervisor covers points 1 and 3 only (point 2 dropped
per user's decision — separate, not what he raised, don't want to muddy
the message).

---

## NEXT TASK — in progress when handed off

User asked to move forward fixing point **#2 (S3/S4 OBU→RSU migration)**
in code. Scoped plan, NOT YET STARTED:

1. The RSU-side S3/S4 detection logic **already exists and is spec-correct**
   in `scratch/tcam_detection.h`'s `ComputeTcamDetection()` (flag_s3 from
   `unauth_orphan_count > 0` ~line 218, flag_s4 from `tcam_util >
   tcam_util_thresh` ~line 254). It's already called once per RSU per
   cycle in `routing.cc:117721` and written to the MOBIGUARD CSV's TCAM
   columns. **No new detection math needed.**

2. Add a per-RSU cache array (same pattern as `g_lstm_last_dlstm[]` used
   for `flag_LSTM`, see `lrad.h:314-325`) to hold the latest
   `flag_s3`/`flag_s4` per RSU, populated at the existing
   `ComputeTcamDetection()` call site (`routing.cc:117721`).

3. Inside `lrad_rsu()` (`lrad.h:277-409`), read that cache and OR it into
   `D_RSU` alongside `flag_S2f`/`flag_S5-S8`/`flag_LSTM`
   (`lrad.h:327-328`), matching spec's flat OR.

4. Remove S3/S4 from `D_OBU` (`lrad.h:44-49`, `lrad_obu()` around
   `lrad.h:504-556` — `flags.D_OBU = flag_S1 || flag_S2p || flag_S3 ||
   flag_S4` currently; spec says `D_OBU = flag_S1 ∨ flag_S2p` only,
   `lrad.h:99-100/142/184-217` has the OBU-side `lrad_tcam_snapshot()`
   using the OLD formula that should go away). **This changes real
   runtime behavior**: currently OBU-detected TCAM condition triggers
   `HOLD_FORWARD` local quarantine via `D_OBU`; after this fix, that
   quarantine trigger disappears for S3/S4 and only the RSU-side path
   fires (via `BC.Write`/BTMM inside `lrad_rsu()`'s `D_RSU` block).

5. Rebuild (`./waf build` in `~/ns3_g13/ns-allinone-3.35/ns-3.35`) and
   rerun A3/A4 at minimum — ideally all 8 variants since BTMM/trust-update
   side effects could shift — to verify nothing regresses before trusting
   any new numbers from this change.

User had NOT yet confirmed to proceed with steps 3-4 (behavior change) —
last message from assistant asked for explicit confirmation given step 3
changes live detection behavior and step 4 requires committing to a
rebuild+rerun cycle. **Resume by getting that confirmation, or if already
given verbally on the other laptop, proceed directly to implementation.**

---

## Repo state reminders
- Current branch: `S15`. Local commit `791a918` (LSTM Z_ALPHA fix etc.)
  remains **unpushed** — no instruction given to push, don't push without
  asking.
- `lstm_pipeline/.gitignore` updated this session to also ignore
  `models_backup_*/`.
- New untracked files not yet committed: `lstm_pipeline/q30_holdout_results.json`,
  `lstm_pipeline/src/q30_holdout_eval.py` — legitimate outputs/script, not
  committed yet (no request to commit given).
- Q30 benign-holdout NS3 data already collected and lives at
  `~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training/RSU_*/A0_pct0_seed{6,7,8}.csv`
  — reusable, don't need to re-collect.
