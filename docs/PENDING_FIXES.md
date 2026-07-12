# Pending Fixes & Deferred Work

**Created:** 2026-07-10
**Status:** Living document — remove items as they are completed.
**Context:** LSTM training data (90s, 240 runs) collected 2026-07-08/09; federated LSTM
pipeline currently training on it with A3/A4 excluded (see Fix 1 for why).

---

## AI-part completion summary (all 8 attacks via LSTM)

| Issue | Attacks | Fixable | Fix | Effort |
|---|---|---|---|---|
| **A — A3/A4 label bug** | A3, A4 | Yes | Label victim RSUs holding a malicious TCAM entry (`lstm_logger.h`). U_TCAM saturates to 1.0, so detection should be strong once labeled. | code ~15 min + rebuild + re-run 60 sims + retrain |
| **B — dead ZKP hop feature** | A5–A8 | Yes | Wire `g_lstm_stark_counts` hop-fail to fire on unauthorized copies so `1[π_hop=⊥]` populates (see Fix 2b). Also makes AB3 ablation real. | code ~30–60 min + rebuild + re-run 120 sims + retrain |
| C — thin benign windows | all | Optional | Pool RSUs / more benign runs. Works as-is. | low priority, skip for deadline |

**Already fixed (working):** cycle-level labeling (AUC 0.54→0.93 for A1/A2), benign-only
autoencoder training, seeded reproducibility, `torch.load` weights_only, `_global.pt`
glob. A1/A2 detect genuinely; M8 passes (BRFA-v2 robust, FedAvg collapses).

**Batched wall-clock for A+B:** ~1–1.5 h code + one rebuild + ~20–22 h re-run (180 sims,
25 workers, mostly unattended) + ~15 min retrain ≈ **~1 day, ~2 h hands-on.**

**Code status (2026-07-10) — all sim-side fixes applied + VERIFIED, pending re-run:**
- Fix 1 (A3/A4 label, `lstm_logger.h`) — ✅ **VERIFIED**: A3 now labels 26 victim RSUs
  (was 1). Required the Fix 2c stale-header fix to actually take effect.
- Fix 2b (`zkp_hop_fail` wiring, `routing.cc`) — ✅ **VERIFIED**: A5=64, A7=78 rows with
  `zkp_hop_fail=1` (was 0).
- Fix 3 (TCAM threshold 0.80→0.054688, `routing.cc`) — ✅ compiled.
- Fix 2c (stale-header symlink) — ✅ **RESOLVED** (see below).
- HF-2/HF-3 (hidden-forwarding fixes) — ✅ code applied + compiled + running clean in
  final verification.
- HF-1 (0xDEAD fabrication marker) — ⚠️ **APPLIED THEN REVERTED same session** — caused a
  SIGSEGV (exit 139) on every active-HF packet. See "HF-1 crash" below. Marker-based
  distinction is NOT in the current build; active vs passive HF is still correctly
  distinguishable at the receiver via `active_hf_malicious_nodes[prev_sender]` (used by
  Fix 2b), so no functionality was lost — only the "signature fails on fabricated
  content" hardening is deferred.
- Fix 5 (A3 penetration bug, `cp_attack_tick()`) — ✅ **VERIFIED**: found *after* Fix 1
  labels were confirmed correct. See Fix 5 below. pct0=0 labels (was 26 RSUs
  saturated), pct60=256 labels/32 RSUs (correctly scaling), no crash.
- Pending: commit → delete old A3–A8 CSVs → re-run A3,A4,A5–A8 (180 sims) → remove
  `EXCLUDE_ATTACKS` (Fix 2) → retrain.

---

## Fix 1 — A3/A4 ground-truth labels are wrong (HIGH, blocks 2 of 8 attacks)

### Problem

The labels for A3 and A4 in the collected data are wrong, and the LSTM can't be
trained or evaluated on those two attacks without fixing them.

**How the label works now** (`scratch/lstm_logger.h:156`): each CSV row is one RSU's
features for one cycle, and the label is `is_malicious_node[variant][this_RSU]` —
i.e. *"is this RSU itself an attacker?"*

**Why that fails for A3/A4 specifically:**

- **A4 (DP-TCAM):** the attackers are **vehicles** (nodes 0..N) flooding junk flow
  rules into RSU TCAMs. No RSU is ever an attacker → every A4 row in the whole
  dataset is labeled 0. The data confirms it: **0 malicious rows across all 30 A4
  files** (every percentage, every seed).
- **A3 (CP-TCAM):** the attacker is a **compromised controller** flooding RSUs. The
  code marks a single "representative" RSU (`is_malicious_node[2][N_Vehicles]`,
  routing.cc:114968) purely as a bookkeeping marker → exactly 88 rows (1 RSU × 88
  cycles) labeled regardless of attack percentage, while in reality up to all 64
  RSUs are being flooded.

**Proof the attacks themselves ran correctly** (the labels are the only problem):

| Dataset (pct100, seed1) | U_TCAM mean | median | max |
|---|---|---|---|
| A0 benign | 0.008 | 0.004 | 0.039 |
| A3 | 0.344 | 0.016 | 1.000 |
| A4 | 0.573 | **1.000** | 1.000 |

### Consequences if unfixed

1. **A4 detection rate is structurally 0** — the evaluator has no positive labels to
   count TP/FN against. A3 DR is capped by the single labeled RSU.
2. **Benign training set is poisoned** — the autoencoder trains on label-0 windows;
   A3/A4's TCAM-saturated windows (U_TCAM = 1.0) count as "benign", teaching the
   model that attack behaviour is normal and degrading detection of *all* attacks.

### Fix (verified compile-safe; include order already correct)

In `scratch/lstm_logger.h`, after the existing `is_malicious_node` check
(line ~156), label the **victim** RSUs — any RSU holding ≥1 malicious TCAM entry.
`tcam_detection.h` (which declares `g_tcam_table`) is included immediately before
`lstm_logger.h` in routing.cc, so the symbol is visible:

```cpp
label = is_malicious_node[active_attack_variant][rsu_sim_idx] ? 1 : 0;
// A3/A4 (TCAM attacks): the attacker is a controller (A3) or vehicles (A4),
// never the RSU itself, so is_malicious_node stays false for RSU rows. Label
// the *victim* RSUs instead: any RSU holding >=1 malicious TCAM entry is
// attack-affected (entries persist — slow-flow exhaustion).
if (!label && (active_attack_variant == 2 || active_attack_variant == 3))
{
    for (const auto& entry : g_tcam_table)
    {
        if (entry.node_id == rsu_sim_idx && entry.is_malicious)
        {
            label = 1;
            break;
        }
    }
}
```

Both attacks install entries with `is_malicious = true` and the victim RSU's node id
(`tcam_install_malicious()`, tcam_attack_helper.h:372-400), so this is exact ground
truth, not a heuristic.

### Procedure when resumed

1. Apply the fix above to `scratch/lstm_logger.h`.
2. **COMMIT IT IMMEDIATELY.** This fix was already applied once (2026-07-08) but was
   never committed and a later git operation silently reverted it — the entire 90s
   A3/A4 dataset was collected with the old labels as a result.
3. Rebuild: `cd ~/ns3_g13/ns-allinone-3.35/ns-3.35 && ./waf build`
   (NS-3 scratch files are **symlinks** into this repo's `scratch/` — edit here only.)
4. **Delete old A3/A4 CSVs first** — the logger opens with `std::ios::app`, so
   re-runs would append onto stale data:
   `find ~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training -name "A[34]_*.csv" -delete`
5. Re-run only A3+A4 (60 runs ≈ 7 h at 25 workers):
   `python3 scripts/run_training_attacks.py --attack 3 4 --workers 25`
6. Sanity-check labels: A3 labeled rows should scale with attack percentage;
   A4 should be ≫ 0 (was exactly 0).
7. Remove `EXCLUDE_ATTACKS = {3, 4}` from `lstm_pipeline/src/preprocessor.py`
   (see Fix 2) and re-run the pipeline.

---

## Fix 2 — Preprocessor temporarily excludes A3/A4 (tied to Fix 1)

`lstm_pipeline/src/preprocessor.py` currently has `EXCLUDE_ATTACKS = {3, 4}` to keep
the mislabeled TCAM windows out of the benign training set (see Fix 1, consequence 2).
**Remove this after Fix 1 is complete** so A3/A4 are trained/evaluated like the rest.

---

## Fix 2b — `zkp_hop_fail` LSTM feature is dead → A5–A8 undetectable (HIGH, breaks a core thesis contribution)

### Why this is important

main.tex makes the LSTM detection of **hidden forwarding (A5–A8)** a stated novelty
(line 729: *"No work applies federated LSTM specifically to detecting selective time
delay patterns **or hidden forwarding signatures**"*). The LSTM input vector
(eq:lstm_input) includes two "novel mobility-cryptographic" binary features precisely
for this:

    x_t = [ delta_t, lambda_PI, U_TCAM, 1[pi_delay=⊥], 1[pi_hop=⊥], rho, v_bar ]

`1[pi_hop=⊥]` (hop-legitimacy failure) is the feature meant to catch hidden forwarding,
and ablation **AB3** (5-feature vs 7-feature) is built to prove it adds value.

**Current reality: both ZKP features (`zkp_delay_fail`, `zkp_hop_fail`) are 0 in every
collected row, including A5–A8 malicious rows.** So the LSTM cannot detect A5–A8, and
AB3 would show no difference between the 5- and 7-feature models — silently nullifying
a claimed contribution. This is a bug, NOT a design boundary. Do **not** describe A5–A8
as "handled by another layer, by design" — that contradicts the thesis.

(Note: eFADE = the state-of-the-art baseline compared against; UCR = an evaluation
metric; S5–S8 = MOBIGUARD's rule-based signatures. None of these is a reason the LSTM
"shouldn't" see A5–A8 — the thesis says it should.)

### Root cause

`zkp_hop_fail` is fed by `g_lstm_stark_counts`, incremented only inside
`stark_update_meta()`. That call is gated on `sig_ok` at **routing.cc:121385**:

```cpp
if (sig_ok) {
    stark_update_meta(prev_sender, packet_ID, timing_ok, hop_ok);
```

A hidden-forward copy goes to an eavesdropper that is NOT the signed next-hop, so
`mldsa87_verify` returns `sig_ok = false` (correctly — unauthorized recipient), the
`stark_update_meta` call is skipped, and the hop failure never reaches the LSTM
feature. The event IS caught on a separate path (`fade_eavesdrop_counter`, which powers
the UCR metric), but that signal is never wired into `g_lstm_stark_counts`.

### Fix

At the unauthorized-copy / eavesdrop detection point, increment the offending
(malicious) RSU's LSTM hop-fail counter, e.g.
`g_lstm_stark_counts[malicious_rsu].second++`, so `1[pi_hop=⊥]` fires for that RSU's
cycle. Methodologically sound: a hidden-forward *is* a hop-proof violation, so the
feature *should* be 1. (Same pattern would populate `zkp_delay_fail` for the relevant
timing cases.)

### Procedure when resumed

1. Wire the counter at the eavesdrop-detection site (find via `fade_eavesdrop_counter`
   increment in routing.cc; attribute to the malicious RSU's LSTM cycle counter).
2. COMMIT + rebuild (`./waf build`) — batch with Fix 1 and Fix 3 into one rebuild.
3. Delete old A5–A8 CSVs (logger appends) and re-run: 4 attacks × 6 pct × 5 seeds =
   **120 sims (~14 h at 90 s, 25 workers)**.
4. Verify `zkp_hop_fail` is now > 0 on A5–A8 malicious rows.
5. Re-run the pipeline; A5–A8 should now be LSTM-detectable via the hop feature, and
   AB3 becomes a real ablation.

**Until fixed:** present only A1/A2 as working LSTM detection. Report A5–A8 LSTM
detection as *intended design, currently blocked by this instrumentation gap* — not as
working, and not as out-of-scope.

---

## Fix 2c — Build trap: stale standalone `scratch/routing/lstm_logger.h` (CRITICAL, root-caused 2026-07-10)

The ns-3 scratch has TWO routing setups. The **running binary**
`build/scratch/routing/routing` is built from `scratch/routing/routing.cc`, and its
headers live in `scratch/routing/`. Every header there is a **symlink into this repo —
except `lstm_logger.h`, which was a stale REAL copy from Jun 29** (no Fix 1, no A3/A4
label code). So all our `lstm_logger.h` edits went to the repo file (used only by the
unused top-level `scratch/routing.cc` target), while the binary compiled the stale copy.

**Effect:** Fix 1 (A3/A4 labels) silently never took effect — the 2026-07-10 verification
showed A4=0 / A3=1-RSU despite the correct code. Fix 2b/Fix 3 (in `routing.cc`, correctly
symlinked) DID take effect, which is why `zkp_hop_fail` populated but labels didn't.

**Resolved:** replaced `scratch/routing/lstm_logger.h` with a symlink to
`Final-Year-project/scratch/lstm_logger.h` (stale copy backed up to
`/tmp/lstm_logger_stale_backup.h`), removed a stray empty top-level `scratch/routing.cc`,
and rebuilt. **Lesson:** header-only edits require `touch scratch/routing/routing.cc`
before `./waf build` (waf doesn't track header deps), and any future new header must be
symlinked into `scratch/routing/`, never copied.

---

## HF-1..HF-5 — Hidden-Forwarding (A5–A8) implementation vs main.tex (audit 2026-07-10)

Audited `hf_attack_helper.h` + `routing.cc` HF blocks against main.tex §"Overview of the
four Hidden Forwarding Attacks" (lines 1414-1424). **Topology/routing is faithful**
(malicious-node selection, copy→eavesdropper, original→legit hop, CP-poisons-controller
vs DP-self-modifies, DP-adds-vehicle-relays, pct scaling). Issues found:

- **HF-1 (HIGH) — Active/passive content distinction is cosmetic, not implemented.**
  Spec: Active (A5/A6) sends *fabricated/modified* copies (ML-DSA-87.Verify must fail);
  Passive (A7/A8) sends *unmodified* copies. In code `send_hidden_duplicate`
  (routing.cc:123363-371) builds an **identical** packet for both — `SetflowId(flow_id)`,
  same size, unsigned. The active block sets `g_hdup_flow_id = flow_id` plain
  (routing.cc:120899) — the `0xDEAD0000` fabrication marker that comments at 120960 /
  121351 claim is used is **never set**. So active vs passive differs only in the printed
  log line ("EdDSA will FAIL — content fabricated" prints but nothing fabricates). The
  misinformation-injection capability from the spec is not simulated; signature-based
  active-HF detection isn't exercising real modified traffic.

- **HF-2 (MEDIUM) — Active HF lacks the per-packet duplicate guard.**
  Passive block gates on `attempts[...] == 0` (routing.cc:120927); the active block
  (routing.cc:120874) has no such guard, so it fires on every retransmission attempt →
  multiple duplicate copies per packet, asymmetrically inflating UCR/PIR for A5/A6.

- **HF-3 (LOW) — Wrong attack numbers in comments.** routing.cc:121071-1072 says
  "Attacks 18 & 19 / 20 & 21" (should be 5&6 / 7&8); routing.cc:120920 labels the block
  "ATTACK 7 … Data Plane" but A7 is Control plane (block serves both A7/A8).

- **HF-4 (MEDIUM) — Active eavesdropper receive-detection fragile in SUMO.**
  routing.cc:121286 uses a single global `active_hf_eavesdropper_index` then falls back to
  a `passive_hf_rsu_to_eavesdropper` scan; multi-RSU runs with per-RSU eavesdroppers rely
  entirely on the map, so any RSU missing from it silently drops its eavesdrop count.

- **HF-5 (LOW/verify) — DP attacker-vehicle as second forwarder.** Spec A6/A8 have the RSU
  AND the attacker vehicle each forward original + emit a duplicate. Vehicles are flagged
  malicious and the send block gates on `..._hf_malicious_nodes[current_hop]` (includes
  vehicles), so it can fire for a vehicle forwarder — but confirm at runtime that
  vehicle-origin duplicates actually transmit (block sits in the RSU-centric TX path).

**Recommended fixes:** HF-1 — set `g_hdup_flow_id = 0xDEAD0000|flow_id` in the active
block and have the eavesdropper receive path treat the `0xDEAD` marker as a failed
signature (or actually skip signing the copy). HF-2 — add the `attempts==0` guard to the
active block. HF-3 — correct the comments. HF-4 — key active detection off
`active_hf_malicious_nodes[prev_sender]` (as the counter fix already does) rather than a
global index.

**APPLIED 2026-07-10:**
- HF-2 ✅ active block gated on `attempts[...] == 0` (routing.cc:120877) — one copy/packet.
  Verified: A5 foreground run progressed cleanly past t=4.0 with duplicates firing, no crash.
- HF-3 ✅ comments corrected (Attacks 5&6/7&8; passive block relabelled A7 CP & A8 DP).
- HF-4 — left as-is: the existing `passive_hf_rsu_to_eavesdropper` map scan
  (routing.cc:121305) already covers per-RSU eavesdroppers, and the Fix 2b counter gates
  on `active_hf_malicious_nodes[prev_sender]`.
- HF-5 ✅ **VERIFIED 2026-07-10** — ran A6 pct100 seed1: of 50 distinct duplicate-sending
  nodes, 48 were vehicles (IDs 0-199) and only 2 were RSUs (243, 245). Confirmed via log:
  `[ATTACK6] ④ Forwarding ORIGINAL packet to legitimate next hop (167) as normal` /
  `⑤ Sending CONTENT-MODIFIED duplicate ... to unauthorized Node(167)` from vehicle node
  167. The RSU-centric-looking TX path correctly fires for vehicle-origin forwarders too
  — `active_hf_malicious_nodes[current_hop]` works identically regardless of whether
  `current_hop` is a vehicle or RSU sim index. No code change was needed.

**HF-1 — APPLIED THEN REVERTED (SIGSEGV, exit 139).** Setting
`g_hdup_flow_id = 0xDEAD0000u | flow_id` put the fabrication marker onto the wire via
`dup_tag.SetflowId()`. The comments claiming "receive/FADE/S6 paths already strip it via
`& 0xFFFF`" were WRONG — that masking exists at exactly one FADE-bookkeeping call site
(routing.cc:120962), not in MacRx's generic receive path. MacRx extracts the tag's
flow_id **unmasked** at `uint32_t fid = tagmodified_routing.GetflowId();`
(routing.cc:121209) and uses it directly to index `pd_all_inst[fid]` (routing.cc:121352)
and `fade_received[fid]` — with the marker set, `fid` ≈ 3.7 billion, an out-of-bounds
array access. Confirmed by direct reproduction: reverting the one-line change made the
identical scenario run cleanly past the crash point (t=3.1 → t=4.0+) with no error.
**Reverted** `g_hdup_flow_id` back to plain `flow_id` (routing.cc, active block). No
functional loss — active vs passive HF is already correctly distinguished at the
receiver via `active_hf_malicious_nodes[prev_sender]` (the same lookup Fix 2b uses), so
HF-1's original goal is met without touching the wire flow_id.
**If HF-1's deeper goal (signature actually fails on fabricated content) is revisited
later:** do NOT reuse the flow_id field for the marker. Either add a dedicated boolean
field to `CustomDataUnicastTag_ModifiedRouting`, or mask `fid` immediately after
extraction at MacRx (routing.cc:121209) before any indexing — and audit every other
raw-`fid` array index in that ~150-line receive block first.

**Re-checked 2026-07-10, decided NOT to re-implement (even the safe version) before the
deadline.** Traced `mldsa87_verify()` (crypto_layer.h:485-491): when the eavesdropper
calls verify with `next_hop = eavesdropper_id`, the signature was made for the
*legitimate* next hop, so `next_hop != signed_next_hop` → verify already returns false
("skip_broadcast") — for BOTH active and passive HF duplicates, identically, with no
marker needed. This is the same mechanism Fix 2b's `stark_hop_ok`/`zkp_hop_fail` already
taps, so **hop-legitimacy detection (what feeds the LSTM and S5/S7) is already correct
for all 4 HF variants without HF-1.**
The remaining gap is narrower than first framed: main.tex's active/passive split is about
*content* authenticity (fabricated payload), not hop legitimacy — but `send_hidden_duplicate`
never calls `mldsa87_sign` on the copy at all (it reuses the original's signature record),
so simulating "signature fails because content was fabricated" needs payload/signing-level
changes, not a metadata flag. That's materially riskier than the reverted one-liner and
only matters for a content-authenticity-specific ablation, not for M1/LSTM results.
**Decision: leave unimplemented, documented here as future work.**

---

## Fix 3 — Apply calibrated S3/S4 TCAM threshold in routing.cc (before evaluation runs)

`rule_calibrator.py` Step 5 (2026-07-10) calibrated the TCAM utilisation threshold
from benign data:

| Threshold | Hardcoded now | Calibrated | Basis |
|---|---|---|---|
| `tcam_util_thresh` | **0.80** | **0.054688** | benign p99, 0.95% benign exceedance (FPR ≤ 1% budget) |
| `lambda_pi_thresh` | 15.0 | 15.0 retained | benign λ_PI all zero — nothing to calibrate; documented as initial estimate |
| `lambda_fm_thresh` | 10.0 | 10.0 retained | FlowMod rate not logged in LSTM CSVs; documented as initial estimate |

The hardcoded 0.80 is ~15× above the entire benign distribution (benign max 0.094) —
dead space. Update the `ComputeTcamDetection()` call site at **routing.cc:117518-117524**
(third arg = λ_FM, fourth = λ_PI, fifth = util threshold): change `0.80` → `0.054688`.
Requires the same rebuild as Fix 1 — do them together.

**Thesis caveat to note:** U_TCAM grows monotonically over a run (rule accumulation,
never plateaus), so this threshold is calibrated for the current run durations
(90–150 s). Longer evaluation runs need recalibration on matching-duration benign data.

---

## Fix 5 — A3's `attack_percentage` did nothing (penetration bug, found 2026-07-10)

Separate from Fix 1 (labels). Even with labels correct, `cp_attack_tick()`
(tcam_attack_helper.h) ignored `attack_percentage` entirely and always flooded a fixed
`ceil(64 * cp_attack_pct/100) = 26` RSUs (cp_attack_pct default 40%). Confirmed
empirically on the original data: **A3_pct0 through pct80 all showed max U_TCAM=1.0** —
identical attack severity at every percentage, including the "0% attack" baseline.

This violates main.tex's own penetration formula (line ~5046): *"At attack percentage p,
⌊0.01p × 264⌋ attacker nodes are allocated ... control-plane variants (Attacks 1, 3, 5, 7)
assign attackers among RSUs"* — at p=0 this must yield 0 attacker nodes.

**Fix:** `cp_attack_tick()` now floods only RSUs whose owning controller is compromised
(`controller_compromised[rsu_controller_assignment[r]]`), mirroring Attack 1's
`reapply_cp_selective_delay()` exactly. `controller_compromised[]` was already being
computed correctly from `attack_percentage` (same threshold ladder as A1: <33%→1,
33-66%→2, ≥66%→3, 100%→4 controllers) — it just wasn't being read by the flooding logic.
Also removed the legacy unconditional `is_malicious_node[2][N_Vehicles] = true` marker
(routing.cc), which would have caused a false-positive label at every percentage
including 0% now that Fix 1's TCAM-based labeling is the real ground truth.

**Verified 2026-07-10:** pct0 → 0/64 RSUs targeted, 0 labels, max U_TCAM=0.016 (was
26/64, 1.0). pct60 → 32/64 RSUs targeted, 256 labels across 32 RSUs (was identical to
pct0's 26/64). No crash.

**Note:** this is NOT the "Attack Intensity" dimension from Experiment 1
(main.tex ~4643-4694) — that's a separate, deliberately descoped 3-level severity axis
that the LSTM's own data-collection spec (main.tex "Federated LSTM anomaly detector"
section) does not require (confirmed: spec explicitly calls for exactly 6×8×5=240 runs,
percentage-only, no intensity sweep). This fix is about **penetration** (breadth — how
many nodes attack), which main.tex's own formula requires and which IS in LSTM scope.

**A4 does not have this bug** — verified `num_attackers = floor(0.01*attack_percentage*N_Vehicles)`
already correctly scales (A4_pct0 max U_TCAM=0.05 vs pct20+ all saturated).

---

## Fix 6 — B3/eFADE baseline never ran on any simulation (CRITICAL, found 2026-07-11)

### Problem

`scratch/efade_detection.h` implements the eFADE baseline (Li et al., IEEE
TPDS 32(11) 2021 — Zhang2021FADE in main.tex) reasonably faithfully: it
monitors every node on each flow's path, treats a `FADE_EPOCH_SEC = 1.0`
measurement window as the paper's R1 hard-timeout, and flags "duplication"
when a node forwards the same `packet_id` to ≥2 destinations (matching this
project's actual Hidden Forwarding threat model, where the original packet
always reaches its legitimate destination unmodified — see main.tex
§1415-1424 — so the paper's "hijacking"/"interception" path-divergence cases
never occur here; duplication-only detection is the correct scope, not a
gap).

However, `fade_detection_active` (routing.cc:114832) was declared `bool
fade_detection_active = false;` and — unlike the structurally identical
`enable_tap` flag one line above it — was **never wired to a CLI flag and
never assigned `true` anywhere else in the codebase.** Effect:

- `fade_detect_anomaly()` (efade_detection.h:437) early-returns every
  1-second epoch before running any of its detection/classification logic
  (lines 444-547), so `pp_tp_global/fp/tn/fn` and `fade_results[]` never
  update, and no `[eFADE ALERT]` lines are ever printed.
- The final-metrics write is gated `if (fade_detection_active) { ...
  fade_save_metrics(); }` (routing.cc:143869) — never executes, so
  `fade_metrics*.csv` is **never created** on any run, ever.
- `fade_write_per_cycle_csv()` (routing.cc:117645) also early-returns, so
  `FADE_Attack<N>_<pct>.csv` and `routing_fade_per_cycle.csv` are never
  written either.
- Only the header row of `fade_results*.csv` gets written (that file-open
  block at routing.cc:143821 is NOT gated on the flag), which is why the
  breakage wasn't obvious from file *existence* alone — the file was there,
  just permanently empty of data rows.

This was silent: `fade_received`/`fade_forwarded` (the raw TX/RX packet
observations) were populated correctly by the send/receive paths regardless
of the flag, so the plumbing looked complete on inspection — only the
detection/output stage was dead. `scripts/run_hf_attacks.py`'s own docstring
and `check_results()` have always expected `FADE_Attack<N>_<pct>.csv` to
exist for every Hidden Forwarding run (attacks 5-8) without passing any
special CLI flag — confirming the intended design was "runs automatically
for HF attacks," not "opt-in like TAP."

### Fix

Added, right before the FADE CSV/scheduling block in `main()`
(routing.cc, immediately preceding the `fade_csv.open(...)` call, after
`declare_attack_states()` has resolved `active_attack_variant` for both the
CLI-driven and `routing_test` hardcoded-topology paths):

```cpp
fade_detection_active = (active_attack_variant >= 4 && active_attack_variant <= 7);
```

Scope (`active_attack_variant` 4-7 = attack_number 5-8) matches
`fade_is_flow_attacked()`'s existing gating and main.tex's own B3 definition
("FADE ... covering packet duplication and path deviation (Variants 5-8)",
main.tex:3460-3465). Unlike `enable_tap`, this is **not** exposed as a CLI
opt-in flag: TAP needs explicit `--enable_tap=1` + `--enable_lrad_obu/rsu=0`
because it shares timestamp state with MOBIGUARD's own S1/S2 and needs
isolation for a clean baseline comparison; eFADE uses fully independent
`fade_received`/`fade_forwarded` maps with no such interference, so
auto-enabling for the relevant attack variants (mirroring how S1/S2/S5-S8
self-gate on `active_attack_variant` rather than needing per-signature CLI
flags — see the comment at routing.cc:114824-114830) is both correct and
consistent with the rest of the file's conventions.

### Verification

Rebuilt (`./waf build`, succeeded). The already-running 180-sim A3-A8
background re-collection was not disrupted (Linux keeps a running process's
old binary mapped after the file is atomically replaced); attacks 5-8 in
that same collection job — still hours away in the job queue at the time of
the fix — will pick up the fix automatically. A dedicated short A8 (variant
7, passive HF, `attack_percentage=60`, `simTime=10`) verification run
confirmed `[FADE METRICS]` now prints and `fade_metrics_V7_pct60.csv` is
written (`TP=0 FP=0 TN=31 FN=0`, PDR=68.75%) — this is the first time that
line/file has ever appeared on any run. TP/FN were both 0 in this specific
run because `attack_start_time` defaults to 10.0s and `simTime` was also
10s, so the attack fired right as the simulation ended, leaving no
post-attack window for a duplicate to be observed — not a bug in the fix
itself. See Fix 7 below for the follow-up run with a longer post-attack
window.

### Note — not fixed (deliberately out of scope for this pass)

No dedicated FADE baseline run harness (`scripts/run_hf_attacks.py`
already assumes FADE runs automatically per this fix, so no new script is
needed) — but there is currently no `run_fade_sweep.py`-style script that
runs FADE *without* MOBIGUARD's S1-S8 active simultaneously, the way
`run_std_attacks.py`'s `TAP_PARAMS` does for TAP. Since eFADE's detection
state is independent of MOBIGUARD's (see above), running them concurrently
does not corrupt eFADE's own numbers, so this is a methodology-presentation
question (do the thesis tables want an "eFADE-only" isolated run vs.
"eFADE running alongside MOBIGUARD"?) rather than a code bug — flagged here
for the user to decide, not fixed unilaterally.

---

## Fix 7 — eFADE duplication check was ID-based, not count-based per Algorithm 2 (found 2026-07-11)

### Problem

Even with Fix 6's `fade_detection_active` gate corrected, the detection
logic itself in `efade_detection.h` diverged from the paper's actual
mechanism. The pre-existing code tracked, per flow and per node, the
*set of individual packet IDs* received and forwarded:

```cpp
std::map<uint32_t, std::map<uint32_t, std::set<uint32_t>>> fade_received;
std::map<uint32_t, std::map<uint32_t, std::map<uint32_t, std::set<uint32_t>>>> fade_forwarded;
```

and flagged a node as duplicating if a specific `packet_id` was forwarded
but never received (`not_received`), or forwarded to ≥2 distinct
downstream hops (`multi_dest`). This is exact-identity matching — strictly
more precise than the mechanism described in Li et al.'s Algorithm 2
("Anomaly Identification"), which never inspects packet identity at all:
FADE's R1/R2 measurement rules only ever report raw packet **counts**
(`p1` at the reference rule vs `p_i` at each downstream rule), and
Algorithm 2's flow-conservation check is a pure count comparison
(`p_i > p1` ⇒ duplication/hijacking-style divergence). Using ID-based
tracking meant this codebase's B3 baseline was silently *stronger* than
the real FADE mechanism it's supposed to represent, undermining the
apples-to-apples comparison main.tex's benchmarking chapter (Experiment
1, §6) relies on, and obscuring the exact flow-statistics-accuracy
limitation of FADE that main.tex's own Mechanism 4 discussion (§1520-1560)
uses as motivation for MOBIGUARD's short observation windows.

### Fix

Rewrote the tracking to raw per-epoch counters, matching Algorithm 2's
`p1`/`p_i` count comparison directly:

```cpp
std::map<uint32_t, std::map<uint32_t, uint32_t>> fade_received_count;
std::map<uint32_t, std::map<uint32_t, uint32_t>> fade_forwarded_count;
```

`fade_detect_anomaly()` (efade_detection.h:438) now computes, per flow
per node per 1s epoch:

```cpp
uint32_t p_in  = fade_received_count[flow_id][node];
uint32_t p_out = fade_forwarded_count[flow_id][node];
bool duplication_detected = (p_out > p_in);
```

replacing the old per-packet-ID loop. All 7 call sites that previously
inserted into the ID `std::set`s (`routing.cc`: normal relay forward,
active-HF forward, passive-HF forward, receive, source origination) were
converted to simple `++` increments on the count maps. The active-HF and
passive-HF forward blocks also had a "seed legitimate hop" workaround
removed (it used to pre-insert the legitimate next-hop's ID into
`fade_forwarded[...]` via `passive_hf_rsu_to_legitimate_hop` so the
ID-based set-matching logic wouldn't misfire on the always-correct
original copy) — this is now unnecessary and would double-count under
count-based tracking, since a legitimate single forward is already
correctly represented by one `fade_forwarded_count[...]++`.

`fade_is_flow_active()` was updated to check `fade_received_count[flow_id]`
entries `> 0` instead of `!set.empty()`. The TP/FP/TN/FN accumulation loop
(`pp_tp_global` etc., efade_detection.h:525-551) was changed from
per-packet-ID granularity to per-node-per-epoch granularity — one verdict
per (flow, node, epoch) via the same `p_out > p_in` comparison, classified
against `active_hf_malicious_nodes`/`passive_hf_malicious_nodes` ground
truth. This mirrors Algorithm 2's own decision granularity (one
duplication verdict per measurement round per node, not per packet) and
in practice yields nearly identical sample counts to the old per-packet
version, since flows send at 1 Hz into 1s epochs (at most one packet in
flight per node per epoch in the common case).

### Verification

Rebuilt (`./waf build`, succeeded, no compile errors). A dedicated
longer-window verification run (A8, variant 7 passive HF,
`attack_percentage=60`, `sim_seed=99`, `simTime=25`, giving a 15s
post-attack observation window past the default `attack_start_time=10.0s`
that cut Fix 6's first verification run short) confirmed the
`[eFADE DEBUG]` per-epoch trace now reports raw counts per node (e.g.
`node137(recv=2,fwd=3)`) instead of packet-ID sets, and that
`duplication_detected = (p_out > p_in)` evaluates correctly against those
counts. First real detection fired at `t=11.000s`:

```
[eFADE ALERT] Flow 0 DUPLICATION anomaly detected at node 245 at t=11.000s
```

with `node245(recv=3,fwd=4)` (fwd > recv) correctly matching ground truth
(`[attacked=1]`, node 245 is the passive-HF malicious relay for this
flow). Final `[FADE METRICS]` line for the run:

```
[FADE METRICS] variant=7 atk%=60 PDR=58.333% PIR=3.015% DR=0.87 FPR=0.00 MCC=0.91 (TP=13 FP=0 TN=39 FN=2)
```

MCC=0.91, zero false positives, only 2 false negatives out of 15
attack-node-epochs — a substantial improvement over the pre-Fix-7
ID-based logic, which (on this same scenario, prior to the rewrite) never
fired at all once `fade_detection_active` was correctly gated (Fix 6's
first verification run showed TP=0 even with detection active, because
that run's `simTime` cut off before any post-attack epoch — see above;
the count-based logic itself had never been exercised against a real
duplicate before this run).

### Note — not fixed (deliberately out of scope for this pass)

Real FADE's R1/R2 rules also have asymmetric install/expire timing (R1
installed first with a longer timeout, R2 rules installed progressively
as flows are discovered) and a DFT-based *minimal* rule-covering set
(Algorithm 1) to keep flow-table usage bounded at scale. This codebase's
`fade_configure_flow()` instead instruments every node on every flow's
path uniformly each epoch — appropriate for this project's scale (tens of
flows, not iFADE's target of massive datacenter-scale flow counts) and
consistent with how the rest of this file already scopes itself to plain
FADE rather than iFADE (see the file's existing header comment). Not
changed, since main.tex's B3 definition only requires FADE-equivalent
duplication detection accuracy, not FADE's own flow-table scalability
mechanism.

---

## Fix 8 — `results_dir` silently drops `ns3_g13` path segment → FADE per-cycle CSVs never written (CRITICAL, found 2026-07-12)

### Problem

`calculate_performance_evaluation_metrics()` (routing.cc:117897-117902)
resolves the results output directory as:

```cpp
std::string results_dir = "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
char* home_env = getenv("HOME");
if (home_env != nullptr)
{
    results_dir = std::string(home_env) + "/ns-allinone-3.35/ns-3.35/results_routing/";
}
```

`$HOME` for this user is `/home/sdvn_hidden_attacks` (not
`/home/sdvn_hidden_attacks/ns3_g13`), and `getenv("HOME")` is always
non-null in every actual run environment, so the dynamic branch always
executes and always produces
`/home/sdvn_hidden_attacks/ns-allinone-3.35/ns-3.35/results_routing/` —
missing the `ns3_g13` path segment present in the hardcoded fallback one
line above it. This path resolves (via an unrelated pre-existing symlink,
`~/ns-allinone-3.35 → ~/ns3-workspace/ns-allinone-3.35`) into a completely
different, unrelated workspace tree that doesn't even have a
`ns-3.35/results_routing/` directory. `fade_write_per_cycle_csv(dir)` is
the only caller of this `results_dir` value
(`Simulator::Schedule(Seconds(0.000097), fade_write_per_cycle_csv,
results_dir);`), so **every** `FADE_Attack<N>_<pct>.csv` and
`routing_fade_per_cycle.csv` write target a nonexistent directory.
`std::ofstream::open()` on a path whose parent directory doesn't exist
fails silently (no exception, `fout.close()` on an unopened stream is a
harmless no-op) — worse, the confirmation print in section 2
(`"FADE per-cycle row written to " << filename`) is unconditional and
does not check `fout.is_open()`, so the log actively claims success on
every failed write.

This was discovered *after* Fix 6/Fix 7 were verified, while building a
dedicated FADE-vs-MOBIGUARD comparison sweep for reporting: despite
several full HF attack runs completing successfully post-fix (confirmed
via 25-50MB stdout logs with correct `[FADE METRICS]` final lines and
correctly-populated `fade_metrics_V<v>_pct<p>_s<seed>.csv` — the *other*
FADE output file, written by `fade_save_metrics()`, which uses a
different, correct path construction and was therefore unaffected), zero
`FADE_Attack<N>_<pct>.csv` files existed anywhere. This is a distinct bug
from Fix 6 (detection never running) and Fix 7 (wrong detection
granularity) — detection was running correctly and being tallied
correctly in-memory; only the *per-cycle CSV persistence* was silently
broken, and only for FADE's per-cycle file (not `fade_metrics_*.csv`,
not `MOBIGUARD_Attack<N>_<pct>.csv` — MOBIGUARD's own per-cycle writer
uses its own hardcoded absolute path literal, not this `results_dir`
variable, so it was never affected).

### Fix

```cpp
results_dir = std::string(home_env) + "/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
```

Now matches the hardcoded fallback exactly. Rebuilt (`./waf build`,
succeeded).

### Verification

A dedicated smoke-test run (Attack 7, `attack_percentage=60`, `seed=1`,
`simTime=12`, invoking the built binary directly rather than through
`./waf --run` — see the note below on why) confirmed `FADE_Attack7_60.csv`
and `routing_fade_per_cycle.csv` are now created and populated with the
expected per-cycle rows in
`~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/`.

### Note — unrelated process hygiene issue hit while diagnosing this

The dedicated FADE-vs-MOBIGUARD sweep launched via
`scripts/run_hf_attacks.py --workers 4 ...` (without `--build`) hit a
second, unrelated problem: `./waf --run` performs its own incremental
build/link check on every invocation, and waf has no locking against
concurrent invocations targeting the same binary. With 4 workers
launching near-simultaneously against a binary that needed relinking
(fresh off Fix 7's edits), two of the first four jobs failed —
`A5_pct60`: linker error "undefined reference to `main`" (link
started before another process's compile finished); `A5_pct100`:
`OSError: [Errno 26] Text file busy` (tried to exec the binary while
another worker was still linking it). This is not a code bug — it's a
process-orchestration hazard specific to launching multiple concurrent
`./waf --run` invocations against an out-of-date binary. Mitigation used
for the corrected re-run: `./waf build` once, serially, before launching
any parallel jobs, so every subsequent `./waf --run` sees "nothing to
build" and just executes rather than racing to relink.

---

## Fix 9 — FADE ran unisolated alongside full MOBIGUARD stack, unlike TAP (found 2026-07-12)

### Problem

`run_std_attacks.py` runs Attack 2 TWICE per (percentage, delay): once
normally (writes `MOBIGUARD_Attack2_<pct>.csv`) and once isolated via
`TAP_PARAMS = {enable_tap: 1, enable_lrad_obu: 0, enable_lrad_rsu: 0}`
(writes `TAP_Attack2_<pct>.csv`) — `enable_lrad_obu/rsu=0` disables
MOBIGUARD's entire S1-S8 stack (see `lrad.h`'s early-return gates), giving
TAP a clean, uncontaminated baseline measurement.

`run_hf_attacks.py` never did this for FADE: one single run per
(attack, pct) produced both `MOBIGUARD_Attack<N>_<pct>.csv` and
`FADE_Attack<N>_<pct>.csv`, with MOBIGUARD's full S1-S8 stack active
throughout. This didn't corrupt FADE's own numbers (its
`fade_received_count`/`fade_forwarded_count` state is fully independent —
confirmed correct in Fix 6). But it left MOBIGUARD's own comparison-partner
numbers exposed to a separate, pre-existing bug: `record_detection_event(v,
n)` — called by S1, S2, and S5-S8 — always writes into
`is_detected_node[active_attack_variant][n]`, using the CLI-selected
variant as the bucket key regardless of which signature actually fired.
S1/S2 (Selective Time Delay, Variants 1-4) run unconditionally on every
packet no matter which `--attack_number` is selected, so during an
HF-only run (`--attack_number` 5-8), S1/S2's own always-on false triggers
get misattributed into whichever HF variant is under test. Verified
directly: a benign (`attack_percentage=0`) Attack 6 run showed `[SECURITY]
Variant 5 | FPR=43.657% TP=0 FP=117 TN=151` — traced to 33 `[S1]` + 84
`[S2]` firings and **zero** `[S6]` firings (S6 is the actual Attack-6
detector, and it correctly found nothing, since there was no attacker).
This meant MOBIGUARD's reported MCC in every FADE-comparison plot was
dominated by unrelated S1/S2 noise, not genuine Hidden-Forwarding
detection quality.

Note: this same `record_detection_event` bucketing bug likely also affects
TAP's own `MOBIGUARD_Attack2_<pct>.csv` (e.g. S5-S8 noise could
misattribute into variant 1's bucket) — it's a pre-existing, codebase-wide
issue, not something introduced by or specific to FADE. **Not fixed here**
— fixing it properly means changing every `record_detection_event()` call
site (S1, S2, S5-S8, `crypto_layer.h`'s trust-quarantine path) to record
against the firing signature's own designated variant instead of
`active_attack_variant`, which is a larger, more invasive change than
today's isolation fix and wasn't requested.

### Fix

Mirrored TAP's exact mechanism instead of introducing a new flag:

**`routing.cc`** — `fade_detection_active`'s assignment (in `main()`) now
requires isolation:
```cpp
fade_detection_active = (active_attack_variant >= 4 && active_attack_variant <= 7)
                       && !enable_lrad_obu && !enable_lrad_rsu;
```
`write_security_metrics_csv()`'s guard extended to match:
```cpp
if (enable_tap || (!enable_lrad_obu && !enable_lrad_rsu)) return;
```
Both defaults (`enable_lrad_obu`/`enable_lrad_rsu`) are `true`
(`crypto_layer.h`), so a normal run is unaffected — FADE only activates,
and MOBIGUARD's CSV writer only fires, when explicitly isolated. Safe for
AB1's own ablation (`enable_lrad_obu`/`enable_lrad_rsu`, main.tex
§4141-4170): AB1-A and AB1-B each disable only *one* of the two flags,
never both simultaneously, so this condition never fires during AB1's own
data collection — only the (previously unused) "both off" combination
triggers it.

**`scripts/run_hf_attacks.py`** — restructured to mirror
`run_std_attacks.py`'s Attack-2 pattern exactly: each (attack, pct) now
gets two runs — the normal run (unchanged, all S1-S8 on, FADE inactive)
and a new isolated run using `FADE_PARAMS = {enable_lrad_obu: 0,
enable_lrad_rsu: 0}` (mirrors `TAP_PARAMS` without the `enable_tap` part,
since FADE has no CLI opt-in flag of its own). Also picked up
`run_std_attacks.py`'s two safety conventions while restructuring:
`--run-no-build` instead of `--run` (avoids the concurrent-waf-build race
from Fix 8's investigation) and `--build` now exits immediately after
building instead of falling through into the sweep.

### Verification

Smoke-tested (Attack 8, `attack_percentage=60`, `seed=1`, `simTime=15`,
`--clean`): both runs completed successfully.
- Normal run (`A8_pct60_seed1.log`): `MOBIGUARD_Attack8_60.csv` got 13
  rows as expected; `[eFADE DEBUG] detect flow` / `[FADE METRICS]` never
  appear (only the unconditional `fade_configure_flow()` retry-path
  messages do, which run regardless of `fade_detection_active` — expected,
  harmless). S1 (16×) and S2 (39×) still fire and still misattribute into
  variant 7's bucket — confirms the isolation fix does *not* touch the
  separate `record_detection_event` bug, exactly as intended (that bug is
  explicitly out of scope here, see above).
- Isolated run (`A8_pct60_seed1_FADE.log`): zero mentions of
  `MOBIGUARD_Attack` anywhere in the log (confirms
  `write_security_metrics_csv()`'s new guard works); real FADE output
  produced — `[FADE METRICS] variant=7 atk%=60 PDR=66.410% PIR=11.111%
  DR=0.67 FPR=0.00 MCC=0.80 (TP=4 FP=0 TN=41 FN=2)`; S1/S2/S5-S8 all
  correctly silent (only an unrelated S1 *initialization* log line
  matched, not a detection firing). The isolated run's own in-memory
  `[SECURITY] Variant 7` figures are nonzero (TP=12, FP=4) but never
  reach any CSV — traced entirely to `[TRUST-QUARANTINE]` (16 events),
  `crypto_layer.h`'s trust-decay mechanism, which is gated by
  `enable_quarantine` (a different layer than the S1-S8/AB1 signature
  stack) and is therefore unaffected by this isolation, by design — it
  doesn't touch either output file so it doesn't matter for this fix's
  purpose.

---

## Fix 4 — Evaluation-phase items (for the M2–M12 simulation runs)

1. **M9 / M11 first build+run verification** — code-complete per
   `docs/METRICS_VERIFICATION_REPORT.md` but never compiled/run. The Fix 1/3 rebuild
   covers the compile check; the first evaluation run covers the run check.
   (M8's verification is the currently-running `pipeline.py` — poison_sweep step.)
2. **MOBIGUARD result CSV filenames have no seed** —
   `MOBIGUARD_Attack{N}_{pct}{delay}.csv` opens with `ios::app`, so parallel seeds
   with the same attack+pct interleave rows into one file. For evaluation runs either
   run one seed at a time per (attack, pct) or add `_s{seed}` to the filename in
   `write_security_metrics_csv()` (routing.cc:117234).
3. **Detection flags (scheme changed 2026-07-09, commit 790e0fe)** — the individual
   per-signature `s1..s8_detection_active` flags were removed. MOBIGUARD's own rule
   detectors (S1–S8) are now gated at mode level by `enable_lrad_obu` /
   `enable_lrad_rsu` (lrad.h); the FADE baseline keeps its own `fade_detection_active`
   (default false). Evaluation runs must set the mode flags for whichever detectors
   they exercise. **Does NOT affect the LSTM pipeline** — `lstm_logger.h` feature
   logging references no detection flag; all 7 features are raw observables computed
   regardless of detector state, so training-data collection is unchanged.

---

## Optional / nice-to-have

- **λ_FM benign logging:** add FlowMod-rate to the per-cycle logger so
  `lambda_fm_thresh` can be percentile-calibrated like U_TCAM (currently a documented
  initial estimate). Needs one benign re-run after the logging addition.
- **Mobility-stratified MCC** (`MCC[ρ_b, v̄_b]` bins) — flagged "HIGH (still open)" in
  METRICS_VERIFICATION_REPORT.md; post-processing of logs, no new simulation needed.
