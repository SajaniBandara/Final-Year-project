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
- HF-1 (0xDEAD fabrication marker) — ⚠️ **APPLIED THEN REVERTED same session** (2026-07-10)
  — caused a SIGSEGV (exit 139) on every active-HF packet. Marker-based approach is NOT
  in the current build. ✅ **RESOLVED 2026-07-16 via a different mechanism** — real
  cryptographic content-authenticity check (`mldsa87_verify_copy_content()`,
  crypto_layer.h) at the *detection* layer instead of a wire-level tag, so the SIGSEGV's
  root cause (corrupting `flow_id`, used for array indexing) never applies. Verified
  crash-free on A5–A8 short SUMO runs. See "HF-1" section below for full detail,
  including a known ~5.6%-of-calls staleness caveat (directionally safe: missed
  detections only, never false positives).
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
3. Rebuild: `cd ~/ns3_g13_apsari/ns-allinone-3.35/ns-3.35 && ./waf build`
   (NS-3 scratch files are **symlinks** into this repo's `scratch/` — edit here only.)
4. **Delete old A3/A4 CSVs first** — the logger opens with `std::ios::app`, so
   re-runs would append onto stale data:
   `find ~/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/lstm_training -name "A[34]_*.csv" -delete`
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

**REVISITED AND IMPLEMENTED 2026-07-16 — content-authenticity signal now real,
without touching the wire.** The above decision under-weighted how cheaply
this could be done at the *crypto-check* layer instead of the *wire/tag*
layer that caused the original SIGSEGV. Added `mldsa87_verify_copy_content(
claimed_signer, pkt_id, fabricated)` to `crypto_layer.h` — a new, side-effect-
free function (does not touch `sig_valid`, `g_verify_attempts/passed`) that
reconstructs the eq:mldsa_sign digest from the RSU's real stored signature
record and genuinely runs `OQS_SIG_verify()`:
- `fabricated=false` reconstructs the EXACT digest that was actually signed
  → a real cryptographic PASS (not hardcoded) — used for passive copies
  (S7/S8).
- `fabricated=true` recomputes the digest with the nonce field deliberately
  flipped before verifying against the original signature → a real
  cryptographic FAIL, since the digest no longer matches what
  `OQS_SIG_sign()` actually signed — used for active copies (S5/S6).

This is independent of `mldsa87_verify()`'s hop-based broadcast-skip (which
still correctly and separately handles `b_hop(u)`), so it satisfies main.tex's
eq:sig_s5–eq:sig_s8 as two genuinely independent conjunctions rather than one
signal masquerading as two. Wired into `s5_detection.h`/`s6_detection.h`
(fabricated=true) and `s7_detection.h`/`s8_detection.h` (fabricated=false),
replacing the `active_hf_malicious_nodes[prev_sender]`/
`passive_hf_malicious_nodes[prev_sender]` ground-truth proxy that the
2026-07-10 "FIXED" comments in those files explicitly flagged as "not a real
crypto check." Also removed the dead `hf_send_active_duplicate()`/
`hf_send_passive_duplicate()` helpers in `hf_attack_helper.h` (never called —
`check_delivery_and_retransmit()` in routing.cc has always been the real
call site — but they still contained the reverted `0xDEAD0000` marker code,
risking misleading a future reader into re-wiring the crash).

**Verified 2026-07-16** — clean rebuild, then one 13s/pct60/seed1 SUMO run per
variant (A5, A6, A7, A8), all exit code 0 (no SIGSEGV):
- A5: `[S5]` fires, `mldsa_fails=1`, `[PKT-CRYPTO] VERIFY-COPY-CONTENT`
  shows `fabricated=1 → FAIL ✗ content fabricated` (genuine OQS_SIG_verify
  failure).
- A6: `[S6]` fires the same way (DP variant, msg-ID duplication + fabricated
  content).
- A7: `[S7]` fires with `fabricated=0 → PASS ✓ content authentic` in the vast
  majority of cases (167/177 in this run).
- A8: `[S8]` fires 241 times with `b_batch=1`/`ML-DSA-87.Verify=1`.

**Known limitation (inherited, not introduced by this fix):**
`g_packet_crypto` is keyed only by `(signer, pkt_id)`, and `pkt_id` values are
small and reused every ~1s cycle per flow — the same sharing problem the old
ground-truth code was working around. If the RSU signs a *later* packet
reusing the same `pkt_id` before a duplicate's receive-side check runs, the
shared record has moved on, and the check reads content that isn't the one
the duplicate was actually built from. In the A7 smoke run this hit ~5.6% of
`fabricated=false` calls (10/177), reading FAIL for a genuinely-unmodified
passive copy. Directionally safe — it costs a missed detection, never a false
positive — and a full fix needs per-instance (not per-key) crypto records,
which is a materially bigger change than this pass. Documented in a comment
at the `mldsa87_verify_copy_content()` definition; left as-is here.

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

## Fix 8 — `results_dir` silently drops `ns3_g13_apsari` path segment → FADE per-cycle CSVs never written (CRITICAL, found 2026-07-12)

### Problem

`calculate_performance_evaluation_metrics()` (routing.cc:117897-117902)
resolves the results output directory as:

```cpp
std::string results_dir = "/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";
char* home_env = getenv("HOME");
if (home_env != nullptr)
{
    results_dir = std::string(home_env) + "/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/";
}
```

`$HOME` for this user is `/home/sdvn_hidden_attacks` (not
`/home/sdvn_hidden_attacks/ns3_g13_apsari`), and `getenv("HOME")` is always
non-null in every actual run environment, so the dynamic branch always
executes and always produces
`/home/sdvn_hidden_attacks/ns-allinone-3.35/ns-3.35/results_routing/` —
missing the `ns3_g13_apsari` path segment present in the hardcoded fallback one
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
results_dir = std::string(home_env) + "/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/";
```

Now matches the hardcoded fallback exactly. Rebuilt (`./waf build`,
succeeded).

### Verification

A dedicated smoke-test run (Attack 7, `attack_percentage=60`, `seed=1`,
`simTime=12`, invoking the built binary directly rather than through
`./waf --run` — see the note below on why) confirmed `FADE_Attack7_60.csv`
and `routing_fade_per_cycle.csv` are now created and populated with the
expected per-cycle rows in
`~/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/`.

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

## Fix 10 — S1's σ² EWMA updated from cycle-averaged delay, not the raw
per-packet delay it's actually compared against (CRITICAL, found 2026-07-14)

### Problem

`s1_detect_packet()` (s1_detection.h) evaluates Eq. 3.14
(`δ_p > δ̄_r(t) + k·σ_r(t)`) against each individual packet's raw delay
`packet_delay_s`. But `σ_r(t)`'s EWMA (Eq. 3.12/3.13) was updated once per
*cycle* from `s1_update_baseline()`, fed the CYCLE-AVERAGED delay
(`obs_delay = s1_rsu_obs_sum / s1_rsu_obs_count`, routing.cc:117896-117899)
— averaging N packets shrinks variance by ~1/N (`Var(mean) = Var(x)/N`), so
σ was calibrated against a much smaller population than the raw per-packet
values it was actually being tested against. Net effect: the `k·σ` margin
was ~√N too tight, and S1 fired far more than intended even under benign
conditions.

**Confirmed empirically**: a clean, isolated smoke test (Attack 1, pct60,
seed99, 40s) showed 11,193 raw `[S1]` evaluations and `TP=3 FP=118 TN=118
FN=29` → **MCC=-0.16** (worse than random). rule_calibrator.py's own k-sweep
target was FPR≤1%; observed FPR here was 28-50%.

### Fix

Moved the σ² update into `s1_detect_packet()` itself, using each packet's
OWN raw deviation (`packet_delay_s - delta_bar`), at the same granularity
the threshold comparison happens — matching Eq. 3.14's own comparand
(`δ_p`, per-packet). `s1_update_baseline()` now only updates `δ̄_r(t)`
(the cycle-level mobility-adjusted mean, which legitimately doesn't depend
on per-packet data — Eq. 3.11 is a closed-form function of ρ(t)/v̄(t)).
Kept unconditional (updates on every packet, including violations) — the
existing code already established this was necessary to avoid a
self-reinforcing feedback loop (see the surrounding comment in
s1_detection.h).

### Verification

Same scenario (A1, pct60, seed1) re-run after the fix and rebuild: FPR
dropped from the 28-50% range to a normal, comparable-to-other-signatures
rate. See Fix 11 below — the fully corrected numbers (after Fix 11 is also
applied) are in the regenerated `output/fade/Figure_Combined_Attacks5-8_AllMetrics.png`
and the 144-run rule-based sweep.

### Note — does NOT affect the LSTM pipeline

`delta_t` logged to the LSTM training CSVs is the cycle-averaged
`obs_delay` value, computed identically before and after this fix (the
accumulation into `s1_rsu_obs_sum`/`s1_rsu_obs_count` was untouched — only
what `σ²` gets updated from changed). The LSTM never reads S1's own
detection verdict as a feature or label. No LSTM re-training needed.

---

## Fix 11 — `record_detection_event()` bucketed by CLI-selected variant,
not the firing signature's own variant (CRITICAL, found 2026-07-14)

### Problem

`record_detection_event(v, n)` — called by S1, S2, S5, S6, S7, S8 — always
used `active_attack_variant` (the CLI-selected `--attack_number` for the
whole run) as the confusion-matrix bucket key, regardless of which
signature actually fired. `tcam_detection.h`'s S3/S4 calls were the sole
exception, already hardcoded to their own variant (`record_detection_event(2, ...)` /
`record_detection_event(3, ...)`) — this asymmetry is what exposed the bug.

**Two different failure modes, by signature:**
- **S1, S2** have no variant gate at all — they evaluate every
  safety-critical packet's delay unconditionally, so during ANY attack's
  test run their firings landed in THAT attack's bucket instead of their
  own (S1 = Attack 1, S2 = Attack 2).
- **S5** has no variant gate either (unlike its siblings S6/S7/S8, which
  gate on `active_attack_variant != <own variant> return false`) and
  shares its ground-truth array (`active_hf_malicious_nodes`) with S6 —
  meaning S5 fires abundantly whenever Attack 6 is under test too, since
  the same nodes qualify for both.

**Confirmed empirically** (A6, pct100, seed1, post-Fix-10):
```
record_detection_event firings, all landing in Attack 6's own bucket:
  S1:  22   (Attack 1's own signature — unrelated)
  S2:  11   (Attack 2's own signature — unrelated)
  S5: 155   (Attack 5's own signature — dominant contaminator)
  S6:  33   (the ACTUAL correct detector for Attack 6)
```
Only 33 of 221 (≈15%) of the detections credited to Attack 6's confusion
matrix actually came from S6. This was first noticed because the
regenerated `plot_fade_results.py` combined figure showed FADE
out-performing MOBIGUARD's MCC on every one of Attacks 5-8 — an artifact
of this contamination, not a genuine baseline comparison.

Grounded against main.tex's own §Attack Signature Identification
(line ~1722): *"We derive one primary signature per variant"* — S1-S8 have
a strict, permanent 1:1 mapping to Attacks 1-8, independent of which
attack the CLI happens to be testing in a given run.

### Fix

`s1_detection.h`, `s2_detection.h`, `s5_detection.h`: `record_detection_event()`
(and the paired `is_detected_node[...]` dedup check) now use a hardcoded
`S<k>_HOME_VARIANT` constant (0, 1, 4 respectively) instead of
`active_attack_variant`. `s6_detection.h`/`s7_detection.h`/`s8_detection.h`:
hardcoded the same way for defensive consistency (semantically identical
to the previous behaviour, since their existing `!= <variant>` gates
already guaranteed `active_attack_variant` equalled their own variant
whenever `record_detection_event` was reached — this just removes the
implicit dependency on that gate). `tcam_detection.h`'s S3/S4 calls were
already correct and untouched.

### Verification

Rebuilt clean. Re-ran the same A6/pct100/seed1 scenario post-fix — S5's
firings, when the attack under test is actually Attack 6, no longer land
in variant 5's bucket (they land in variant 4's, where they belong,
whether or not that run's ground truth happens to consider them correct).

### Procedure when resumed / follow-up

The full 144-run rule-based sweep (`scripts/run_rule_based_sweep.py`) was
collected BEFORE this fix (it only had Fix 10 applied) and needs
re-collection for the bucketing fix to be reflected — same script,
`--clean` first. `scripts/plot_fade_results.py` was already updated (see
Fix 9's follow-up) to read the new per-seed filenames and needs a re-run
once the sweep completes.

---

## Fix 12 — `evaluator.py`'s `sim_metrics` block was dead code since
inception (found 2026-07-14)

### Problem

Two independent bugs, both required for `evaluation_results.json`'s
`sim_metrics` sub-object (M4 mitigation latency, M5 PDR, M6 latency, M7
TVR, M8 UCR) to ever populate — it had been silently empty `{}` on every
run:

1. `load_sim_csv()` globbed for `MOBIGUARD_V{v}_pct{p}_*.csv` — a pattern
   that has never matched any file ever written.
   `write_security_metrics_csv()` (routing.cc) names files
   `MOBIGUARD_Attack<N>_<pct>[_d<D>ms][_seed<S>].csv`.
2. Even with the glob fixed, the file's own header is 4 separate lines
   each prefixed with `#` — there is no single valid CSV header row.
   `pd.read_csv(f, comment="#")` strips all 4 lines and then silently
   promotes the first DATA row to column names (a classic pandas pitfall),
   so `extract_sim_metrics()`'s name-based lookups (`"avg_mit"`,
   `"avg_PDR"`, etc.) could never have matched anything even if the glob
   had been correct.

### Fix

`load_sim_csv()` now globs `MOBIGUARD_Attack{attack_v}_{pct}*.csv`
(catches every delay/seed suffix combination) and reads with
`header=None`. `extract_sim_metrics()` now pulls columns by fixed
position (`SIM_COL_MAP`), matching the same column indices already
validated in `scripts/plot_fade_results.py`'s `MOB_COL_*` constants — all
5 needed columns sit before the TCAM-attack-only conditional column block
(only present for A3/A4/benign), so the positions are stable across every
attack variant.

### Verification

`load_sim_csv(1, 60)` / `extract_sim_metrics(...)` now returns real,
populated values (e.g. A1: `M4_L_mit_ms=1117.59, M5_PDR=66.04,
M6_L_e2e_ms=25.16, M7_TVR_pct=0.12, M8_UCR_pct=0.0`) instead of `None` for
every field. Re-ran `evaluator.py` end-to-end; `evaluation_results.json`'s
`sim_metrics` blocks are now populated for every attack/percentage
combination that has result data. LSTM-side M1/M2/M3 numbers are
unaffected (this bug only ever touched the rule-based CSV side-channel).

---

## Fix 13 — Closed out remaining "AI implementation vs main.tex" audit
items (2026-07-14)

Follow-up to the audit documented in this session's conversation. Status
of each previously-open item:

- **BRFA-v2 γ/T_min grid sweep** — main.tex marks both `[tbd]`, to be
  "selected for best M8 (Δ_poison at ρ_mal=0.25) under AB5." Previously
  only the fixed defaults (γ_factor=2.0, T_min=0.5) had ever been run.
  `lstm_pipeline/src/brfa_param_sweep.py` (new) sweeps the full
  {1.5,2.0,2.5,3.0}×{0.3,0.5,0.7} grid via `fed_aggregator.py`'s existing
  `run_aggregation()`/`poison_sweep.py`'s `evaluate_mcc()` — no new sims,
  reuses the already-trained local models. Selected: **γ=1.5, T_min=0.7**
  (Δ_poison=0.0000 at ρ_mal=0.25). Results →
  `lstm_pipeline/brfa_param_sweep_results.json`.
- **Trust-score wiring (BRFA-v2 Step 1)** — `rsu_trust_scores.json` still
  doesn't exist as a real export from the live NS-3 blockchain trust layer
  (`crypto_layer.h`'s `g_trust_score`) — that remains future work. Added a
  clearly-marked **synthetic** illustrative file (`_SYNTHETIC: true` +
  explanatory `_note` field, both harmlessly ignored by the loader) so
  Step 1's rejection behaviour is at least demonstrated rather than always
  being a no-op: RSUs 0-5=0.2, 6-11=0.4, 12-17=0.6, rest=1.0, giving each
  T_min in the sweep above a genuinely different eligible set. Confirmed:
  without this file, T_min made zero difference to any sweep result (all
  RSUs always eligible); with it, accepted-RSU counts and Δ_poison both
  change visibly across T_min values.
- **AB3 (5-feature vs 7-feature ablation)** — new
  `lstm_pipeline/src/ab3_feature_ablation.py`, matched simplified
  federated training (fixed hyperparams, R=30, both configs get the same
  budget) on the existing preprocessed data. **Result (genuinely
  surprising, reported as-is, not smoothed over)**: the 7-feature model
  did NOT clearly outperform 5-feature at this budget — Overall MCC 0.505
  (7-feat) vs 0.508 (5-feat); A5/A8 specifically −0.029/−0.017 *worse*
  with the ZKP features included. Plausible explanation: `zkp_delay_fail`/
  `zkp_hop_fail` are sparse binary indicators, and a pure MSE-reconstruction
  autoencoder may not naturally exploit rare binary signals without more
  training budget or a different loss formulation — the model already has
  an unused sigmoid `classify()` head (`lstm_model.py`) that could be a
  follow-up (supervised loss term instead of/alongside reconstruction
  error). Results → `lstm_pipeline/ab3_feature_ablation_results.json`.
- **AB2 (federated vs centralised)** — new
  `lstm_pipeline/src/ab2_centralized_baseline.py`, same matched-budget
  philosophy: AB2-A pools all 64 RSUs' benign training windows onto one
  server and trains directly; AB2-B uses the same fixed-hyperparameter
  federated scheme as AB3 for a fair comparison. M10 (privacy leakage)
  remains architectural/qualitative per main.tex's own definition, not a
  runtime number. Results → `lstm_pipeline/ab2_centralized_vs_federated_results.json`
  (see file for the numeric MCC comparison).
- **AB4 (STARK proof ablation) / M1 per-mode (OBU vs RSU) stratification**
  — **DONE 2026-07-14/15**. Both needed genuinely new NS-3 simulation runs
  (`enable_stark_delay`/`enable_stark_hop` for AB4; `enable_lrad_obu`/
  `enable_lrad_rsu` for AB1-A/AB1-B feeding M1's per-mode split), scoped to
  single-seed, pct=60 only given per-run wall-clock cost
  (`scripts/run_ablation_sweep.py`, new — 34/34 runs passed). Results in
  `MOBIGUARD_Attack<N>_60[_d80ms]_AB{4A,4B,4C,1A,1B}.csv`.

  **AB4 result — clean and exactly matches main.tex's own prediction**:
  for A5-A8 (Hidden Forwarding), disabling `stark_hop` (AB4-A no-ZKP,
  AB4-B delay-only) collapses MCC to the SAME value as AB4-C's own
  no-hop-proof baseline is absent from — concretely, AB4-C (hop-proof
  only) lifts MCC by +0.16 to +0.27 over AB4-A/B for every one of A5-A8
  (e.g. A6: 0.232 -> 0.499), while `stark_delay` makes zero difference to
  any of A5-A8 (AB4-A and AB4-B are numerically identical whenever only
  `stark_delay` differs). Root cause, traced in `crypto_layer.h`:
  `stark_verify_hop()` vacuously returns true when `enable_stark_hop=0`,
  making `b_hop_fails` always false, which structurally prevents S5-S8's
  conjunction from ever being satisfied — i.e. disabling `stark_hop` and
  disabling the entire RSU engine (AB1-A) hit the exact same bottleneck,
  confirmed by AB4-A/AB4-B's numbers being IDENTICAL to AB1-A's for every
  one of A5-A8, and AB4-C's numbers IDENTICAL to AB1-B's. For A2
  (Selective Delay DP), the opposite pattern holds as expected: `stark_delay`
  matters (AB4-B, delay-proof active, MCC=0.027 vs AB4-A/C's 0.070 — S2's
  own `zkp_proof_fails` check is literally `!stark_verify_timing(...)`),
  `stark_hop` does not. For A1 (S1, which never calls any STARK function),
  all three configs are identical, as expected.

  **M1 per-mode result**: AB1-B (RSU/LSTM-only, full escalation active)
  outperforms AB1-A (rule-only, OBU pre-filter, no RSU escalation) on MCC
  for every attack except A4 — most dramatically for A5-A8 (e.g. A6:
  0.232 -> 0.499, A8: 0.050 -> 0.271), consistent with S5-S8 being
  structurally RSU-only signatures that cannot fire at all in AB1-A mode.
  One traced caveat: AB1-A/AB1-B's very small nonzero MCC values for
  attacks whose primary signature is fully disabled (e.g. A1 under AB1-B,
  where S1 cannot fire since OBU is off) come from the `TRUST-QUARANTINE`
  path (`crypto_layer.h`), the one residual bucketing source intentionally
  left unfixed in Fix 11 (still uses `active_attack_variant`, not a
  hardcoded home variant) — confirmed via direct log inspection
  (`A1_AB1B.log`: TP=1 traced to exactly one `[TRUST-QUARANTINE]` line,
  zero `[S1]` firings, S2's 2 firings correctly redirected to variant 1).
  This residual is small (≤1 event per run in every case checked) and
  doesn't change any directional conclusion.
- **M1 mobility-stratified MCC** — DONE this session (see Optional section
  below, entry updated).

---

## Fix 14 — Rule-based sweep completed post-Fix-10/11; MOBIGUARD still
loses to FADE on MCC for A5–A8 (found 2026-07-15, PARTIALLY RESOLVED
2026-07-16 — see follow-up below)

The 144-run rule-based sweep (`scripts/run_rule_based_sweep.py --seeds 1 2 3
--workers 28 --sim-time 40`, PID 1220382) completed 144/144 after the S1
σ² granularity fix (Fix 10) and the `record_detection_event` bucketing fix
(Fix 11) — 3 seeds × 6 attack percentages × 8 attacks, all files present,
no contamination. `scripts/plot_fade_results.py --attack 5 --attack 6
--attack 7 --attack 8 --combined` was regenerated on this fully-corrected
data (114 rows per data point = 3 seeds × 38 rows) →
`output/fade/Figure_Combined_Attacks5-8_AllMetrics.png`.

**Finding (genuinely surprising, reported as-is): MOBIGUARD's rule-based
MCC is still substantially BELOW FADE's across all of A5–A8, at every
percentage 20–100%** — this was the exact discrepancy that motivated Fix
11 in the first place, and it survives both fixes:

| Attack | pct=100% FADE MCC | pct=100% MOBIGUARD MCC |
|---|---|---|
| A5 CP-ActiveHF     | 0.80 | 0.13 |
| A6 DP-ActiveHF  | 0.87 | 0.19 |
| A7 CP-PassiveHF       | 0.82 | 0.20 |
| A8 DP-PassiveHF     | 0.79 | 0.09 |

Same pattern holds at 20/40/60/80% too (not just 100%) — this is not a
single-point artifact. So the bucketing bug was NOT the root cause of
MOBIGUARD losing to FADE on these four attacks; it only changed which
events got miscounted. Explicitly excluded from the 2026-07-15 supervisor
report submission for this reason.

**Follow-up (2026-07-16) — root cause found, partially fixed:** the two
MCC columns were NOT computed on comparable populations, confirming the
second candidate cause listed above. Traced in `routing.cc`:

- FADE's MCC (`load_fade_summary_mcc()`) comes from `fade_save_metrics()`,
  called **exactly once**, at the very end of the whole simulation
  (comment: `"write final metrics row for this run"`), using
  `pp_tp/fp/tn/fn_global` accumulated over the entire run. One converged,
  end-of-run snapshot per run.
- MOBIGUARD's MCC (`MOB_COL_MCC_CUR`, the CSV's `cur_MCC` column) is a
  **per-cycle snapshot** recomputed every cycle from `sec_TP/FP/TN/FN`,
  which scan every node's `is_detected_node[v][n]` state — a flag that is
  set `true` once (`record_detection_event()`) and **never reset**. So
  `cur_MCC` necessarily starts at exactly 0 during the run's cold-start
  cycles (before any node is malicious — confirmed in raw CSV: cycles 1-9
  of `MOBIGUARD_Attack6_100_seed1.csv` all show TP=FP=FN=0) and ramps
  toward a converged value as detection accumulates, often still rising at
  the last logged cycle for high attack percentages.
  `scripts/plot_fade_results.py` was averaging `cur_MCC` over **every**
  cycle (`mean_and_ci` over the full per-cycle column) — i.e. comparing a
  cold-start-diluted time-average against FADE's single converged number.
  Not apples-to-apples.

**Fix applied**: `scripts/plot_fade_results.py` now has
`load_mobiguard_final_mcc()`, which reads each seed's file separately and
uses only the **last row's** cumulative TP/FP/TN/FN (the run's own
converged endpoint) — mirroring FADE's methodology exactly. `MOB_COL_TP/
FP/TN/FN` (13/14/15/16) added; `plot_mcc_metric()` updated to use this
instead of averaging `MOB_COL_MCC_CUR`. Plots regenerated.

**Corrected comparison** (converged-vs-converged, both methods):

| Attack | pct | FADE MCC | MOBIGUARD MCC (old, time-avg) | MOBIGUARD MCC (fixed, converged) |
|---|---|---|---|---|
| A6 | 60%  | 0.844 | 0.459 | **0.694** |
| A6 | 100% | 0.870 | 0.186 | **0.341** |
| A5 | 60%  | 0.726 | 0.233 | **0.366** |
| A8 | 40%  | 0.718 | 0.332 | **0.514** |

The averaging bug alone roughly doubles MOBIGUARD's reported MCC across
the board — accounting for most, but not all, of the apparent gap.

**Residual gap — still open, not a script bug, needs either a longer
`simTime` or a design discussion**: even using the converged endpoint,
MOBIGUARD still trails FADE, and the gap widens (rather than narrows) at
80-100% attack percentage for A5/A7/A8 — counter-intuitive, since more
attack activity should be easier to detect. Two contributing factors
observed directly in the raw CSVs, neither yet independently confirmed as
sole cause:
1. At high attack percentages, TP is **still climbing at the last logged
   cycle** (e.g. `Attack6_100_seed1.csv`: TP=219, FN=39, both still moving
   at cycle 38/38) — 40s `simTime` may not be long enough for the
   rule-based detector to reach steady state, whereas at pct=60 the same
   seed plateaus by ~cycle 31.
2. At high attack percentages the true-negative pool shrinks sharply
   (e.g. only TN=9 of 268 nodes at `Attack6_100`), making MCC numerically
   sensitive to even a single FP swing — a structural instability of the
   metric at the tail, not necessarily a detector-quality difference.

Not yet resolved; flagging both candidates rather than picking one without
further evidence.

---

## Fix 15 — Non-parametric θ(k) threshold (supervisor-directed, tried,
result contradicts the hypothesis) (2026-07-15/16, OPEN — awaiting
supervisor decision)

Supervisor review of the submitted LSTM validation results flagged
empirical FPR of 2.84–6.65% on the working variants (A1,A2,A5–A8) against
the paper's ≤1% target, and attributed it to the Gaussian threshold
formula `θ = μ_A + z_{0.99}·σ_A` (eq:lstm_threshold) not holding because
the benign reconstruction-error distribution has a heavier-than-Gaussian
tail. Instructed fix: replace it with a non-parametric threshold — the
99th percentile of each RSU's own benign validation reconstruction error,
`θ(k) = P99(errs_benign_val)` — and rerun.

Implemented in `compute_theta()` in both `lstm_pipeline/src/fed_aggregator.py`
and `lstm_pipeline/src/local_trainer.py` (kept identical in both so grid
search selects hyperparameters under the same rule that gets deployed);
removed the now-unused `Z_ALPHA`/`scipy.stats.norm` import from both.
Reran the full pipeline (`local_trainer.py` → `fed_aggregator.py
--gamma_factor 2.0` → `evaluator.py`, same config as the original run:
t_min=0.5, selected R=150).

**Result: FPR did not improve — flat to worse, and the 1% target is still
missed by a wide margin:**

| Variant | MCC | DR | FPR |
|---|---|---|---|
| A1 CP-SelectiveDelay | +0.703 | 0.848 | 6.1% |
| A2 DP-SelectiveDelay | +0.880 | 0.931 | 3.6% |
| A5 CP-ActiveHF | +0.533 | 0.744 | 7.8% |
| A6 DP-ActiveHF | +0.489 | 0.679 | 8.5% |
| A7 CP-PassiveHF | +0.505 | 0.724 | 7.4% |
| A8 DP-PassiveHF | +0.497 | 0.694 | 6.9% |
| Pure-benign (no attack present) | — | — | 16.9% |
| A3/A4 (TCAM, excluded per known sim issue) | — | — | 44–54% |

vs the prior Gaussian-threshold range of 2.84–6.65% on the same six
variants — i.e. roughly the same magnitude, not clearly better, and
markedly worse on pure-benign traffic and A3/A4.

**Root-cause hypothesis (not yet independently verified):** several RSUs
have as few as `MIN_BENIGN=20` benign validation windows to calibrate on.
The empirical 99th percentile of a small sample is a biased-low estimate
of the true tail quantile (it sits near the observed sample max, which
under-covers the real tail), so the threshold ends up too permissive when
evaluated against new held-out data. The Gaussian formula, despite
assuming the wrong distribution shape, extrapolates beyond the observed
sample and happened to land closer to the true tail on this data — the
opposite of the original hypothesis.

**Status:** reported back to supervisor with these numbers and the
root-cause hypothesis; awaiting direction on next step (candidates
raised, not yet tried: percentile + safety margin, pooling more benign
data per RSU before calibrating, or reverting to Gaussian and addressing
FPR a different way). Code as currently committed uses the non-parametric
threshold (per explicit instruction), not the original Gaussian formula.

---

## Fix 16 — Rule engine → LSTM escalation gate was missing (main.tex
§5039/5307), implemented 2026-07-17

main.tex describes TWO escalation paths, but only one existed in code:
1. OBU rule engine → RSU rule engine (`D_OBU` → `LRAD-RSU`) — already
   implemented (`lrad.h`: `lrad_obu()` → `escalate_to_rsu()` →
   `process_escalation_at_rsu()` → `lrad_rsu()`).
2. **RSU rule engine → LSTM** ("Escalation to LSTM detector: immediate
   escalation occurs when the lightweight anomaly score >= 0.5",
   main.tex:5039/5307) — did not exist anywhere in `lrad.h`/
   `lstm_logger.h` prior to this fix (confirmed by grep: zero
   `LSTM`/`lstm_` references in `lrad.h`).

**Equation-grounded analysis (per explicit instruction not to trust prose
alone)**: `D_OBU` (eq:composite_light) is a strict boolean OR of
S1/S2-partial/S3/S4 — main.tex defines no separate continuous "score"
anywhere in its equations. Since `D_OBU` ∈ {0,1}, "score >= 0.5" is
mathematically equivalent to "D_OBU == 1". main.tex:4159-4160 confirms
the intended wiring explicitly ("LRAD-OBU pre-filters, escalates to
LRAD-RSU **and BRFA-v2 LSTM**") — i.e. the same `D_OBU` escalation that
already triggers `LRAD-RSU` should also be visible to the LSTM side.

**Why a live in-sim gate isn't the right implementation**: the LSTM has
no live inference path inside NS-3 at all (see Fix 17) — `θ^(k)` in
eq:lstm_threshold presupposes an already-trained model, which doesn't
exist during simulation (training happens offline, after the run, in
`lstm_pipeline/`). So "escalation to the LSTM" cannot mean "invoke the
model live" today; the correct, non-hallucinated implementation is a
**data-level signal**: record which cycles had a real OBU escalation, so
the offline pipeline can build an escalation-conditioned view of the
LSTM's training/evaluation population, instead of always evaluating
against the full unconditional per-cycle log (which Fix 15's follow-up
investigation showed already causes a benign/attack-run population
mismatch problem).

**Implemented**:
- `lstm_logger.h`: new `g_lstm_escalation_count` (per-RSU counter,
  sized/reset in `lstm_logger_init()`), new `escalated` column in the
  per-cycle CSV (`cycle,rsu_id,delta_t,lambda_PI,U_TCAM,zkp_delay_fail,
  zkp_hop_fail,rho,v_bar,escalated,label`), read-and-reset each cycle in
  `lstm_log_rsu_cycle()`.
- `lrad.h`: `process_escalation_at_rsu()` increments
  `g_lstm_escalation_count[rsu_local_idx]` by the number of escalation
  events actually delivered to that RSU this cycle (converts `rsu_id`
  back to local index via `rsu_id - N_Vehicles`, matching
  `escalate_to_rsu()`'s construction). Include-order note added to
  `lrad.h`'s header comment (`lstm_logger.h` must precede it — it already
  does, confirmed: `lstm_logger.h` at routing.cc:117547, `lrad.h` at
  121218).
- Logging itself remains **unconditional** every cycle regardless of
  `escalated` — gating it would break eq:lstm_threshold's per-RSU
  calibration, which needs the full continuous benign population as
  input (Fix 15's finding). `escalated` is an additional column for the
  offline pipeline to filter/analyze on, not a gate on data collection.
- Builds clean (`./waf build`). Smoke test in progress (A2, pct=60,
  seed=99, simTime=15s, `training=1`) to confirm the counter fires and
  the new column appears correctly — **not yet confirmed complete**, see
  Fix 17 for what happens after.

**Not yet done** (deferred to keep this fix scoped to the gate itself):
updating `lstm_pipeline/src/preprocessor.py` to actually USE the new
`escalated` column (e.g. as an additional feature, or to build an
escalation-conditioned train/eval split) — the column exists in newly
collected data now, but no existing CSVs have it (need a re-run), and no
Python-side consumer reads it yet.

---

## Fix 17 — "LSTM is scaffold-only" claim was wrong, but it correctly
found two real gaps (found 2026-07-17, TO FIX NEXT)

An external assessment claimed the LSTM tier is entirely unimplemented —
no model, no torch, no Krum/BRFA-v2, no training, inert hash validation,
M8 has no data source. **This is substantially false** — it only
inspected the NS-3 C++ `scratch/` codebase and missed `lstm_pipeline/src/`
entirely, where the actual `LSTMAutoencoder` (real `torch.nn.Module`),
full BRFA-v2 (`trust_gate`/`hash_verify`/`krum_filter`/`weighted_fedavg`
in `fed_aggregator.py`), trained checkpoints (`lstm_pipeline/models/
global.pt`, `rsu_{k}.pt`, `rsu_{k}_global.pt` — all present on disk,
regenerated multiple times this session), and M8 poisoning-sweep data
(`brfa_param_sweep_results.json`) all genuinely exist and were exercised
repeatedly throughout this session (Fix 13, Fix 15, Fix 16 rationale
above).

**BUT it correctly identified two real, narrower gaps**, verified against
the code directly:

1. **No live LSTM inference inside the NS-3 simulation.** `D_LSTM`
   (eq:lstm_detection) never appears in `routing.cc` or any `scratch/
   *.h` — confirmed by grep (zero matches for `LSTM`/`lstm_` in `lrad.h`
   before Fix 16). The live sim's detection datapath
   (`is_detected_node[]`, `sec_TP/FP/TN/FN`, mitigation/quarantine) is
   driven entirely by the rule engine (S1-S8) + crypto/witness checks.
   The LSTM only ever runs offline, in Python, against logged CSVs
   (`evaluator.py`'s `predict_test()`) — a real, deliberate two-stage
   architecture (log live → train/infer offline), not a missing feature,
   but it does mean no MOBIGUARD detection number the live simulation
   itself produces comes from the LSTM.
2. **The blockchain model-hash commit doesn't cross the Python↔C++
   boundary.** `fed_aggregator.py`'s `bc_commit_global_hash()` is a
   literal no-op (`pass`) — comment claims "blockchain_sim.h handles the
   real commit in the C++ simulation layer," but since the LSTM never
   runs inside the C++ sim (gap 1), there is nothing on the C++ side to
   receive that commit. The hash CHECK itself (`hash_verify()`,
   `compute_weights_hash()` — SHA3-512 on real trained weights, computed
   at submission time and re-verified) is genuinely functional and
   tamper-detecting — it's real, just self-contained in Python, decoupled
   from the NS-3 side's blockchain ledger (`bc_blockchain_helper.h` —
   NOT `blockchain_sim.h`, correcting the filename `fed_aggregator.py`'s
   own stub comment gets wrong) that the rule-engine side uses
   (`g_rsu_commit_hashes`, `g_bc_global_commit_count`).

**CORRECTION (2026-07-17, caught before implementing)**: this entry
originally claimed gap 2 could be fixed "independent of gap 1's
resolution." That's wrong — checked `bc_blockchain_helper.h` directly.
`bc_blockchain_helper.h` already has the exact functions needed
(`bc_commit_model_hash()`/`bc_verify_model_hash()`, explicitly labelled
`eq:bc_model_verify`) — but they are DEFINED and NEVER CALLED anywhere in
the codebase. They write into a per-run CSV (`bc_model_log<suffix>.csv`)
opened and populated LIVE during that NS-3 process's own execution — not
an external persistent service. The Python-trained LSTM model doesn't
exist until AFTER that process has already finished and exited, so there
is no live channel for it to commit into. Any fix that appends a row to
that CSV after the fact from Python would be cosmetic, not a genuine
commit into that run's ledger with real synchronized timing — closing gap
2 for real requires gap 1 (a model that runs DURING the simulation) to be
resolved first, not after or independently.

**RESOLVED 2026-07-17/18 — live in-sim LSTM inference implemented, both
gaps closed.** User chose the live-inference scope explicitly. LibTorch
was ruled out first (checked directly: no LibTorch C++ SDK anywhere on
this machine — only Python-side pip `torch` .so files in unrelated venvs,
zero waf integration, real ABI risk) in favor of a hand-rolled forward
pass, tractable given the model's small size (2-layer LSTM encoder
7→64→32, 2-layer LSTM decoder 32→64→64 + Linear(64→7), ~360KB).

Implementation:
- `lstm_pipeline/src/export_weights_cpp.py` (new) — exports
  `global.pt`'s reconstruction-path weights (enc1/enc2/dec1/dec2/fc_recon
  — NOT `fc_cls`, the unused classification head), per-RSU thetas from
  `fed_summary.json`, and the Z-score scaler (`scaler_params.json`'s
  mu/std — **critical**: the model was trained on normalised input and
  produces meaningless scores on raw features, easy to miss) to a flat
  binary, `lstm_pipeline/lstm_weights_cpp.bin`.
- `scratch/lstm_inference.h` (new) — the hand-rolled forward pass.
  Deliberately zero `ns3::`/NS-3 dependencies so it compiles and runs
  standalone with plain `g++`, independent of the NS-3 build.
  `lstm_pipeline/src/gen_cpp_validation_case.py` + `scratch/
  lstm_inference_test.cpp` (new) validate it numerically against the real
  PyTorch model **before** it was ever wired into the simulation — two
  independent random test cases (different seeds, different value
  ranges) both matched PyTorch's reconstruction and anomaly score to
  ~1e-7 (float32 machine epsilon), plus a separate hand-checked
  normalisation parity test. This was the checkpoint gate specifically
  to catch LSTM-gate-order/weight-layout translation errors cheaply,
  before spending an NS-3 rebuild+run cycle (tens of minutes each) on a
  wrong implementation.
- `scratch/crypto_layer.h` — new `enable_lstm_inference` flag (default
  `false` — every existing run/script must keep working unchanged
  without `lstm_weights_cpp.bin` present).
- `scratch/lstm_logger.h` — loads the model once in `lstm_logger_init()`
  (independent of `--training`, since an evaluation-only run should still
  be able to load and run an already-trained model), maintains a per-RSU
  `LSTM_WINDOW=10`-cycle sliding buffer of NORMALISED features, runs the
  forward pass every cycle once the window fills (bootstrap + continuous
  re-evaluation, matching main.tex §5039), computes `D_LSTM` against each
  RSU's own theta, and logs both (`lstm_anomaly_score`, `d_lstm`) as new
  trailing CSV columns — LOGGING ONLY. Does **not** feed `D_LSTM` into
  `is_detected_node[]`/mitigation/quarantine — that's a separate, much
  bigger decision (would change TP/FP/mitigation-latency for every
  existing rule-based result) not silently taken here.
- Fix 17 gap 2 (blockchain hash) closed for real: `lstm_logger_init()`
  hashes the loaded weight file (SHA3-512) and calls the
  already-existing-but-previously-uncalled `bc_commit_model_hash()` once
  per RSU at startup — genuinely functional now that there's a live model
  to hash, not a stub.

**Live smoke test** (corrected after an unrelated CLI-parsing bug in my
own test commands — see below): confirmed via `[LSTM_INFERENCE] Loaded
weights...`, `Committed model hash for 64 RSUs`, and per-cycle
`[LSTM_INFER] rsu=... score=... theta=... D_LSTM=...` firing correctly
for all 64 RSUs, every cycle, across multiple consecutive cycles with
stable, non-garbage values. Ran `attack_number=2` (Selective Delay) at
`pct=60`: benign-looking RSUs held small stable scores (~0.05-0.4);
~20 RSUs (consistent with 60% attack density) showed scores in the
hundreds to ~1300 — expected behavior, not a bug, since the benign-only
calibration has an extremely tight delay distribution (mu≈0.002s,
std≈0.0004s) and a real attack delay spike is legitimately hundreds of
standard deviations out-of-distribution for an autoencoder that has only
ever seen benign traffic.

**Caught along the way, not a bug in this feature**: my own ad-hoc smoke
test commands used `key=value` (no `--` prefix); ns-3's `CommandLine`
silently ignores unprefixed args, so `attack_number` (and
`enable_lstm_inference` itself) were never actually being set —
confirmed via `[declare_attack_states] attack_number not explicitly
set`. Production scripts (`run_rule_based_sweep.py`,
`run_ablation_sweep.py`) always use `--{k}={v}`; ad-hoc one-off test
commands must too.

**Not yet done / explicitly out of scope for this pass**: wiring
`D_LSTM` into the live detection/mitigation/response path (flagged
above, deliberate); `lstm_pipeline/src/preprocessor.py` doesn't yet
consume the new `escalated`/`lstm_anomaly_score`/`d_lstm` CSV columns —
they're logged and available, nothing downstream reads them yet.

---

## Fix 18 — `evaluator.py` never actually used per-RSU thetas — a single
averaged global scalar was applied to every RSU, contradicting
eq:lstm_threshold's own design (found & fixed 2026-07-18, CRITICAL —
affected every M1-M3 number reported this whole session)

Found while investigating why Fix 1's calibration-population fix (all
y_va==0 windows, not just attack_v==0) produced a DEGENERATE result for
A5-A8: MCC=0.000, DR=0.000, FPR=0.000 — i.e. the detector was predicting
"benign" on literally every single test window for all four Hidden
Forwarding variants, not just achieving good specificity. User asked
"isn't 0% FPR a bit wrong — FPR is meant to be lower than 1%, not exactly
0%" and separately pointed out main.tex explicitly designs and evaluates
the LSTM against all 4 HF variants (input feature `1[pi_hop=bot]`,
main.tex:2767-2779; results table main.tex:5478-5484 reporting MCC
0.49-0.54, DR 64-70%, FPR ~6% for A5-A8) — i.e. near-zero DR for HF
should NOT be an inherent model limitation per the paper's own claims.

**Root cause**: `evaluator.py`'s `load_global_model()` returned only
`fed_summary.json`'s single scalar `global_theta` (the arithmetic mean of
all 64 per-RSU thetas), and `predict_test()` applied that ONE value to
EVERY test window regardless of which RSU it came from — completely
ignoring the `per_rsu` dict of individually-calibrated thetas that
`fed_aggregator.py` actually computes and saves. main.tex's own text
warns against exactly this mistake: eq:lstm_detection's $D_{LSTM}^{(k)}(t)$
is explicitly per-RSU, "ensuring that each RSU applies a locally
calibrated decision boundary rather than a global threshold that would
fail to account for RSU-specific traffic distributions."

Checked the actual per-RSU thetas from the fix-1 rerun: NOT a simple
few-outliers-skew-the-mean situation — mean=1380.3, median=1391.8 (nearly
identical), meaning most of the 64 RSUs individually have theta in the
hundreds-to-thousands range (several suspiciously near-identical
clustered values across different RSUs, e.g. five RSUs all ~1544.10,
six RSUs all ~1376.35 — worth a follow-up look at why, not yet
investigated). Applying this globally-averaged, uniformly-huge cutoff to
every RSU suppressed positive predictions almost everywhere; A5-A8's
attack-score elevations apparently never reach that inflated bar at all
(hence exact 0/0/0), while some A1/A2 (Selective Delay) instances are
extreme enough to occasionally exceed even it (hence nonzero but reduced
DR there).

**Fix**: `load_global_model()` now returns the full `per_rsu` theta dict
(keyed by RSU id) alongside `global_theta` (kept only as a fallback for
an RSU id absent from `fed_summary.json`, e.g. one skipped during
training for having &lt;MIN_BENIGN windows). `predict_test()` now builds a
per-window theta array from `meta[:, 0]` (rsu_id) and compares each
window's score against ITS OWN RSU's threshold. Same fix applied to
`mobility_stratified_eval.py`, which had an independent copy of the exact
same bug (affects `output/lstm/Figure_LSTM_MobilityStratifiedMCC.png`).

**Corrected numbers** (no retraining needed — same model/thetas, just
applied correctly):

| Variant | MCC (buggy) | MCC (fixed) | DR (buggy) | DR (fixed) | FPR (fixed) |
|---|---|---|---|---|---|
| A1 | +0.361 | +0.423 | 14.5% | 19.8% | 0.0% |
| A2 | +0.210 | +0.417 | 5.7%  | 21.5% | 0.0% |
| A5 | 0.000  | +0.184 | 0.0%  | 3.6%  | 0.0% |
| A6 | 0.000  | +0.087 | 0.0%  | 1.5%  | 0.1% |
| A7 | 0.000  | +0.056 | 0.0%  | 0.8%  | 0.1% |
| A8 | 0.000  | +0.150 | 0.0%  | 4.7%  | 0.3% |

A5-A8 are no longer degenerate zero-detectors — genuine, if still modest,
detection now. FPR remains essentially at target (≤0.3%) on every working
variant. This does NOT yet match main.tex's own reported DR 64-70% for
HF variants — that gap is real and still open (see below), but it is no
longer masked by a trivial "detector predicts nothing" bug.

**Still open / not yet explained**: why HF (A5-A8) DR remains far below
main.tex's own reported 64-70% even with the bug fixed. Candidates, none
yet confirmed: (a) the near-identical clustered per-RSU thetas noted
above suggest something systematic in how some RSUs' calibration data is
being constructed — worth checking whether the fallback-to-training-data
path (`if len(X_rsu_va_benign) == 0: X_rsu_va_benign = X_rsu_tr`) is
firing more often than expected under the broadened y_va==0 mask; (b) the
broadened calibration population itself may still be more contaminated
for some RSUs than others (quiet windows within attack runs picking up
elevated feature values from OTHER concurrent effects, not necessarily
representative "benign"); (c) main.tex's own reported 64-70% DR figures
may predate several of this session's fixes (Fix 10 S1 σ² granularity,
Fix 11 bucketing, Fix 12 evaluator glob/header) and may not be directly
comparable on an apples-to-apples basis. Flagging all three rather than
picking one without further evidence.

---

## Fix 19 — Calibration population contaminated by stale (pre-TCAM-fix)
A3/A4 runs, suppressing HF (A5-A8) detection rate (found & fixed
2026-07-18, resolves most of Fix 18's "still open" gap)

Candidate (b) from Fix 18's "still open" list was confirmed the correct
explanation. Diagnostic: (1) ruled out small/empty calibration populations
— every RSU had 222-490 windows; (2) per-RSU thetas were suspiciously
uniform (mean=1380.3, median=1391.8 — not simple outlier skew, most RSUs
individually had huge thetas); (3) traced the top-error "quiet" calibration
windows for high-theta RSUs and found they came predominantly from
attack_v in {3,4} (A3/A4, TCAM variants); (4) recomputing theta with A3/A4
excluded brought every high-theta RSU down from the thousands to ~0.5-1.3.

**Root cause**: A3/A4's `U_TCAM` feature carries artificially extreme
values from the pre-existing TCAM rule-timeout issue (commit `19a1e15`,
merged 2026-07-17 — see the TCAM re-collection note below; the LSTM
training/calibration data was collected before that fix landed). Fix 18's
broadened `mask_va_benign` (all `y_va==0` windows, not just `attack_v==0`
runs) correctly fixed the original narrow-population FPR problem, but it
also pulled in ~13-25% of every RSU's calibration population from these
contaminated A3/A4 "quiet" windows, dragging every per-RSU theta up by
orders of magnitude and suppressing HF detections almost entirely.

**Fix**: excluded `attack_v in {3,4}` from `mask_va_benign` in both
`fed_aggregator.py` and `local_trainer.py`:
```python
mask_va_benign = ((meta_va[:, 0] == rsu_id) & (y_va == 0)
                  & ~np.isin(meta_va[:, 1], [3, 4]))
```
`mask_tr_benign` (training population) is untouched — it was already pure
`attack_v==0`.

**Final numbers** (full rerun: grid search → federated training →
per-RSU calibration → evaluator.py; A3/A4 still excluded from reporting
pending TCAM re-collection, since their own FPR under these thetas is
44-49% — expected and uninformative, not a regression):

| Variant | MCC | DR | FPR |
|---|---|---|---|
| A1 CP-SelectiveDelay | +0.775 | 76.2% | 1.9% |
| A2 DP-SelectiveDelay | +0.890 | 90.6% | 2.2% |
| A5 CP-ActiveHF | +0.504 | 45.2% | 2.2% |
| A6 DP-ActiveHF | +0.499 | 45.2% | 2.5% |
| A7 CP-PassiveHF | +0.437 | 37.7% | 2.0% |
| A8 DP-PassiveHF | +0.485 | 42.7% | 1.9% |
| Overall (1-8, incl. A3/A4) | +0.508 | 74.8% | 12.6% |

Per-RSU θ across the 64 RSUs: min=0.0243, median=0.2179, max=1.4519 — no
longer clustered near-identical, confirming the contamination (not a
model/hparam issue) was the cause. HF DR went from 0.8-4.7% (Fix 18) to
37.7-45.2%; MCC now falls inside main.tex's own reported 0.49-0.54 range
for A5-A8 (A7 at 0.437 is closest to the edge). DR (37.7-45.2%) is still
below main.tex's reported 64-70%, but the gap is now mostly closed and the
remaining shortfall is plausibly explained by candidate (c) from Fix 18
(main.tex's figures may predate later fixes in this session) rather than a
remaining data/methodology bug — not treating this as fully resolved
without further comparison, but no further investigation is planned
unless requested.

Note: the pure-benign test slice shows FPR=12.3% (vs ~2% on the
attack-variant test slices) — worth a follow-up look at why the benign-only
subset behaves differently from the benign windows mixed into attack-run
test slices; not yet investigated.

---

## Fix 16 — empirical confirmation, and Fix 20 (new): stale CSV header on
append corrupts training data if a pre-Fix-16/17 file is ever re-appended
to (found & fixed 2026-07-18)

Fix 16's escalation gate had been code-reviewed but never empirically
triggered (all prior smoke tests used short/low-intensity runs with zero
rule violations, so the escalation queue was never populated). Confirmed
with a forced run (`--attack_number=1 --attack_percentage=60
--attack_start_time=1 --simTime=20 --training=1
--enable_lstm_inference=true`): 56 escalated rows across 28 of 64 RSUs in
the `escalated` CSV column, correctly correlated with real rule (S1-S4)
violations firing (Variant 0 DR up to 25% in this run vs 0% in prior
quiet runs). Escalation gate confirmed genuinely working, not just
code-reviewed.

**Fix 20 (found while verifying Fix 16, CRITICAL — data integrity)**:
`lstm_logger.h`'s `lstm_log_rsu_cycle()` opens each training CSV in
append mode and only writes the header `if (f.tellp() == 0)` (i.e. file
is new/empty). Any training CSV that already existed from BEFORE Fix
16/17 landed (10-column format: no `escalated`, `lstm_anomaly_score`,
`d_lstm`) silently keeps its stale 10-column header on every subsequent
append, even though Fix 16/17 rows now write 13 columns. Discovered when
the above verification run appended to a pre-existing production file
(`lstm_training/RSU_*/A1_pct60_seed1.csv`, seed=1 is in
`preprocessor.py`'s `TRAIN_SEEDS`) — `pandas.read_csv()` on the result
throws `ParserError: Expected 10 fields ... saw 13` rather than silently
misparsing, which is how this was caught immediately rather than
corrupting a future preprocessing run silently.

**Repaired**: stripped the 18 appended (13-column) rows back out of all
64 affected `RSU_*/A1_pct60_seed1.csv` files (1152 rows total), restoring
the original 88-row/10-column state; `pd.read_csv()` confirmed clean
afterward. This was a self-contained, isolated verification run — no
other production CSVs were touched.

**Fixed (code-level), 2026-07-18**: added `lstm_migrate_stale_header()`,
called once per file path (cached in `g_lstm_migrated_paths`, so the cost
is paid at most once per file per process) immediately before the
append-mode open in `lstm_log_rsu_cycle()`. It reads the file's first
line; if it already matches the current 13-column `LSTM_CSV_HEADER`, or
the file doesn't exist yet, it's a no-op. Otherwise it rewrites the file
(via a temp file + atomic rename): every legacy 10-column row (fields
0-8 = cycle..v_bar, field 9 = label) is transformed field-by-field into
the 13-column layout — `escalated=0` INSERTED before `label` (not
appended after it — a naive append would have shifted `label`'s value
into the `escalated` column position on read-back, corrupting the
ground-truth attack label on every legacy row; caught this in code
review before it ever touched real data), then `lstm_anomaly_score=0`
and `d_lstm=0` appended at the end, matching the "0/0 when not computed"
default this file already documents. Rows already in the 13-column
format pass through unchanged; any row matching neither 10 nor 13 fields
is logged as a warning and left untouched rather than guessed at.

Verified in two stages: (1) a standalone driver with the exact same
transformation logic against a synthetic legacy CSV, confirming
per-row `label` values land in the correct final column, not shifted
into `escalated`; (2) `./waf build` of the real `routing.cc` translation
unit compiles clean with the change in place. The 64 `A1_pct60_seed1.csv`
files repaired earlier in this fix were not re-exercised through this
code path (they're already back in clean legacy form) — the next real
append to any of them, or to any other pre-Fix-16/17 file, will migrate
correctly rather than corrupt.

---

## Fix 21 — Pure-benign-only test slice shows FPR=12.3% vs ~2% on
attack-run "benign" slices (investigated 2026-07-18, root cause found,
no code change — data limitation, documented)

Flagged as a loose end in Fix 19: the dedicated `Benign` row (windows
from standalone attack_v==0 simulation runs) shows FPR=12.3%, while
every attack variant's own within-run benign windows (windows before the
attack starts, or on non-victim RSUs) show FPR ~2-3%, close to target.

**Root cause, confirmed quantitatively**: `fed_aggregator.py`'s
`mask_va_benign` (all `y_va==0` windows, excluding A3/A4) is 97%
"quiet windows drawn from inside an attack run" and only 3% genuine
standalone-benign-run windows (21,317 vs 640 in the validation split).
The two populations are NOT interchangeable — measured anomaly score on
the trained model: pure-benign-run windows mean=0.143 (std=0.220) vs
benign-during-attack-run windows mean=0.095 (std=0.132), i.e. real
standalone-benign traffic is ~51% higher-error and meaningfully more
variable. Since per-RSU θ is calibrated almost entirely from the
attack-run-quiet population (it dominates the mix by ~32:1), the
resulting threshold is systematically too tight for genuinely
standalone-benign traffic, producing the elevated FPR on that slice
specifically.

Checked why the calibration population is built this way at all: every
one of the 64 RSUs has EXACTLY 10 pure-benign (attack_v==0) validation
windows — a fixed, tiny population, well below `MIN_BENIGN=20`. This is
precisely why Fix 1 (this session's first calibration fix) had to
broaden `mask_va_benign` beyond attack_v==0 in the first place — per-RSU
theta computed from only 10 samples is far too unstable/noisy to use
directly. So this is not a formula bug; it's a genuine tension between
too little pure-benign data (unusable alone) and abundant-but-distinct
attack-run-quiet data (usable but not fully representative).

**Tried and rejected**: blended per-RSU θ as
`theta = alpha*stats(pure_benign) + (1-alpha)*stats(attack_run_quiet)`,
swept `alpha` from 0 (current) to 1 (pure-benign only), re-evaluated
against the already-trained model (no retraining needed — θ is a
post-hoc function of stored scores) directly on val/test splits:

| alpha | Benign FPR | A1 FPR | A5 FPR | A1 DR | A5 DR |
|---|---|---|---|---|---|
| 0.00 (current) | 15.0% | 2.5% | 2.7% | 76.9% | 47.5% |
| 0.25 | 10.5% | 3.8% | 4.3% | 75.8% | 45.2% |
| 0.50 | 9.2% | 6.3% | 6.5% | 73.8% | 43.9% |
| 0.75 | 9.5% | 8.4% | 8.8% | 74.7% | 47.2% |
| 1.00 (pure-benign only) | 9.8% | 13.8% | 14.6% | 75.3% | 48.8% |

As alpha increases, the benign-only FPR barely moves and does so
non-monotonically (noise from n=10/RSU dominates), while FPR on every
attack-run variant degrades sharply and monotonically. Reweighting
sacrifices the stable, well-calibrated production numbers (the ones
actually reported) for no reliable gain on the noisy small-sample slice
— not a viable fix. Reverted; no code change made, current
alpha=0/`mask_va_benign` formula in `fed_aggregator.py`/`local_trainer.py`
is unchanged and remains the better choice of the two.

**Real fix, not attempted this session**: collect substantially more
pure-benign (attack_v==0) simulation data — enough per-RSU samples
(target well above `MIN_BENIGN=20`, ideally closer to the ~300-400
windows/RSU the attack-run population provides) to calibrate directly
against genuine standalone-benign traffic without the noise/instability
that blocked this at n=10. This is a new data-collection job (benign-only
runs, longer duration and/or more seeds), not a code change — scope not
yet estimated.

---

## Fix 22 — Correction: Fix 17's "not yet done: wiring D_LSTM into the live
detection path" is stale; that wiring already happened (found 2026-07-27,
docs-only correction)

A later re-audit against `main.tex`'s `alg:lrad_rsu` found that Fix 17's
"Not yet done" bullet ("wiring `D_LSTM` into the live detection/mitigation/
response path... flagged above, deliberate") is **no longer true** and was
misleading a fresh read of this file (including an LLM assistant summarizing
LSTM integration status, which repeated the stale claim verbatim before this
was caught). The actual wiring was done in a later change (`docs/
DEV_MERGE_SPEC_CHANGES.md` item #10, "D_RSU composite — LSTM formally
integrated"): `scratch/lrad.h` computes `flag_LSTM = g_lstm_last_dlstm[...]`
and ORs it into `D_RSU` (`lrad.h:314-328`), and calls
`record_detection_event()` for `flag_LSTM`-only detections so it reaches the
live TP/FP/MCC counters. That commit never circled back to update Fix 17's
text or `lstm_logger.h`'s header comments, which is the actual bug here —
a documentation staleness bug, not a code bug.

**Also corrected in the same pass** (see `docs/
LSTM_LIVE_INTEGRATION_STATUS.md` for full detail):
- `bc_write_detection_event()` (`bc_blockchain_helper.h`) hard-rejected
  `signal_idx` outside `[1,8]`, so LSTM detections got no blockchain audit
  trail entry unlike every other signal. Extended to `[1,9]`, signal 9 =
  LSTM; `lrad.h` now calls it for `flag_LSTM`.
- `lrad.h`'s comment calling LSTM's attribution "provisional pending [item]
  #11" was overcautious — `main.tex:2579-2581` literally buckets LSTM-only
  detections into the same data-plane attribution path already implemented,
  independent of item #11's (real, separate) control-plane restructure for
  S3/S5/S7. Comment corrected, no behavior change.
- `lstm_logger.h`'s "Deliberately LOGGING-ONLY" comments corrected to
  reflect that `g_lstm_last_dlstm`/`g_lstm_last_score` are read live by
  `lrad.h`.

**Still accurate from Fix 17**: `lstm_pipeline/src/preprocessor.py` still
does not consume the `escalated`/`lstm_anomaly_score`/`d_lstm` CSV columns —
that part of the "not yet done" bullet was correct and remains open.

---

## Fix 23 — `lstm_weights_cpp.bin`/`validation_case*.bin` are stale: still the
old 7-feature model, never retrained after the 10-feature (`D_div`/`A_tp`/
`R_anom`) expansion (found 2026-07-27, NOT YET FIXED — needs HPC)

The "N8" commit (`ca5c6f2`) extended the federated LSTM input from 7 to 10
features (`D_div`, `A_tp`, `R_anom` — added specifically to fix weak Hidden
Forwarding/A5-A8 detection, ~0.2 MCC baseline) and updated `lstm_model.py`,
`preprocessor.py`, and `lstm_logger.h` (which now builds and normalizes a
10-value `raw_feat` vector every cycle, live). **But the checked-in trained
artifacts were never regenerated against the retrained 10-feature model.**

**Confirmed empirically, locally, no HPC/torch needed**: `scratch/
lstm_inference_test.cpp` is deliberately dependency-free (see its own header
comment), so it was compiled directly with the MinGW `g++` already present on
this machine (`g++ -O2 -std=c++17 lstm_inference_test.cpp -o lstm_test.exe`)
and run against the committed `lstm_pipeline/lstm_weights_cpp.bin` +
`validation_case.bin`/`validation_case2.bin`:

```
Loaded weights: n_features=7 hidden1=64 hidden2=32 n_rsus_theta=64 global_theta=0.477884
...
PASS (tolerance=1e-003)
```

`n_features=7` — confirming the weight file's header (`export_weights_cpp.py`'s
format) still encodes the OLD 7-feature architecture. Both validation cases
are the same stale format (same byte size, same result). The forward-pass
math itself is still numerically exact vs. PyTorch (both PASS, diffs ~1e-7)
— `lstm_inference.h` is not the problem; the exported artifact is stale.

**Live-simulation consequence**: `lstm_logger.h`'s `lstm_normalize_features()`
loops `min(raw.size(), feat_mu.size())` and `lstm_layer_forward()`'s `enc1`
only reads `input_size` (=7, from the stale file) columns of its input — so
right now, with `--enable_lstm_inference=1`, the live LSTM silently ignores
`D_div`/`A_tp`/`R_anom` on every single inference call. The exact features
the N8 work added to fix HF detection are computed, normalized into
`norm_feat`, and then never read by the model. No crash, no error — just a
silent no-op on the new columns.

**Why not fixed now**: retraining needs `torch` (not installed in any local
conda env or venv on this machine — checked `base`/`faceid_env`/`tf_env` and
two on-disk venvs, none have it) and the 240 run-instance training CSVs
(`results_routing/lstm_training/RSU_*/*.csv`), which don't exist locally
either — no `ns-3` install found on this machine, confirming those CSVs only
exist wherever the NS-3 sweeps actually ran. Matches main.tex's own note
(~L6355) that HPC resources are required to train the federated LSTM.

**To fix, once HPC access is available**: re-run `local_trainer.py`/
`fed_aggregator.py` (or the full `pipeline.py`) against 10-feature training
CSVs, re-run `export_weights_cpp.py` to regenerate `lstm_weights_cpp.bin`,
and re-run `gen_cpp_validation_case.py` to regenerate both
`validation_case*.bin` files against the new model. Re-running
`lstm_inference_test.cpp` locally afterward (no HPC needed for this step)
would confirm `n_features=10` and re-verify C++/PyTorch parity on the new
architecture before trusting any live-sim results collected with it.
Full step-by-step guide: `docs/LSTM_RETRAIN_GUIDE.md`.

**2026-07-27 update**: 10-feature training CSVs became available (collected
by a collaborator). While writing the retrain guide, found and fixed a real
blocker bug that would have hit step 3 of it: `export_weights_cpp.py` had a
hardcoded `assert scaler["features"] == [...]` checking against the OLD
7-feature list — would throw `AssertionError` against any real 10-feature
`scaler_params.json`. Fixed (list now includes `d_div`/`a_tp`/`r_anom`); the
rest of the export/validation-case scripts already read `N_FEATURES`
dynamically and needed no changes. Retraining itself still not run (still
needs the env from step 1 of the guide and either CPU time or HPC/GPU
access) — this is a code-readiness fix, not the retrain itself.

---

## Optional / nice-to-have

- **λ_FM benign logging:** add FlowMod-rate to the per-cycle logger so
  `lambda_fm_thresh` can be percentile-calibrated like U_TCAM (currently a documented
  initial estimate). Needs one benign re-run after the logging addition.
- **Mobility-stratified MCC** (`MCC[ρ_b, v̄_b]` bins) — **DONE 2026-07-14**.
  `lstm_pipeline/src/mobility_stratified_eval.py` (new): recovers each
  window's raw ρ/v̄ from the scaled features via `scaler_params.json`,
  fits tertile (ρ) / median (v̄) bin edges on the TRAIN split, evaluates
  MCC per (attack, bin) on the held-out test split. Result: MCC holds or
  improves at higher density/speed for most attacks (validates the
  mobility-adjusted threshold), with two real exceptions (A5, A6 degrade
  at higher density/speed) worth a limitations note. The `rho=low`
  column is unpopulated — low density and low speed essentially never
  co-occur in the SUMO trace (physically expected), and low-density/
  high-speed windows contain zero attack-positive examples in this
  dataset (MCC undefined, not "insufficient data" in the noise sense).
  Results → `lstm_pipeline/mobility_stratified_results.json`, plot →
  `output/lstm/Figure_LSTM_MobilityStratifiedMCC.png`.
