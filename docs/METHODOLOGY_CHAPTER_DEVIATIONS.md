# Deviations Found — Careful Linear Read of the Methodology Chapter
**Date:** 2026-07-08
**Scope:** main.tex lines 1132-3435 (§System Architecture through §Multi-Controller
Zero-Trust Architecture), read sequentially, cross-checked against `scratch/*.h`,
`scratch/routing.cc`, and `blockchain/mobiguard-cc/*.go`. This is the direct follow-up to
[docs/SIMULATION_SETTINGS_DEVIATIONS.md](SIMULATION_SETTINGS_DEVIATIONS.md), completing the
"go through the whole main.tex file line by line" instruction for the Methodology chapter.

**Method note:** most of this chapter's mechanisms (S1/S2 signatures, STARK proof
mechanics, T_ref/eq:delay_updated, witness alerts, DKG, BRFA-v2) had already been verified
this session via targeted deep-dives. This pass re-read the chapter continuously start to
finish specifically to catch anything a targeted search would skip — the same method that
found 6 issues in the shorter Simulation Settings section. **Most of the chapter checked out
correctly** — S5–S8 detection code, the witness BFT quorum, the RSU flow-rule endorsement
quorum, and the trust/quarantine equations for vehicles/RSUs all match main.tex exactly, with
real cryptographic backing (not stubs) where the code claims it. One genuine new gap was
found, documented below.

---

## Finding 1: Controller trust score never receives its reward branch — `ctrl_trust_update_positive()` is dead code — FIXED (2026-07-08)

**Fix applied:** `transmit_delta_values()` (`routing.cc:118170-118195`, the once-per-cycle
FlowMod endorse→commit block) now branches on `_committed`: clean commits call
`ctrl_trust_update_positive(rsu_controller_assignment[N_Vehicles])` (the new reward call
site), failed commits still call `ctrl_trust_update_negative(...)` as before. Both branches
read the same `_committed` outcome from the same per-cycle endorsement round, so the reward
fires at the identical cadence the penalty already used — this is the natural per-cycle
"conflict evidence < f+1" checkpoint the equation's reward branch describes, requiring no new
evidence-counting infrastructure beyond what `bc_commit_flowmod()` already tracks. Original
analysis retained below for reference.

**Proposal (main.tex:3313-3322, eq:ctrl_trust_update):**
```
T_ci^(t+1) = min(1, T_ci^(t) + Δr^ctrl)   if conflict evidence < f+1
             max(0, T_ci^(t) - Δp^ctrl)   if conflict evidence >= f+1
```
This is an explicit two-branch update rule — a controller's trust score should be able to
both increase (reward branch, "conflict evidence < f+1") and decrease (penalty branch,
"conflict evidence >= f+1").

**Code (`crypto_layer.h:755-760`):**
```cpp
inline void ctrl_trust_update_positive(uint32_t ctrl) {
    if (!enable_controller_failover) return; // AB9-A: controller trust scoring inert
    if (ctrl >= N_Controllers || g_ctrl_revoked[ctrl]) return;
    double v = g_ctrl_trust_score[ctrl] + TRUST_DELTA_R_CTRL;
    g_ctrl_trust_score[ctrl] = (v < 1.0 ? v : 1.0);
}
```
This function is correctly implemented — properly gated on the AB9-A ablation flag, bounds
the score at 1.0, mirrors the vehicle-side `trust_update_positive()` exactly. **But it is
never called anywhere in the codebase** — confirmed via `grep -rn
"ctrl_trust_update_positive"` across `scratch/`, which returns only its own definition.

By contrast, `ctrl_trust_update_negative()` (crypto_layer.h:762-778) **is** called, from two
sites:
- `routing.cc:118169` — whenever a controller's FlowMod fails to collect `f+1` RSU
  endorsements (`bc_commit_flowmod()` returns false)
- `routing.cc:121249` — whenever the S5/S6 active-hidden-forwarding LRAD path detects an
  eavesdropper receiving a duplicate from an RSU attached to that controller

Both call sites fire **unconditionally on a single bad event** — there is no "count evidence,
compare to `f+1`" logic anywhere; each call is a direct, immediate `-Δp^ctrl` decrement. This
means the code's actual behavior is: *a controller's trust score starts at 1.0 and can only
ever go down, one strike at a time, with no recovery mechanism* — not the proposal's stated
per-timestep dual-branch comparison against a conflict-evidence count.

**Why this matters:**
- With `TRUST_DELTA_P_CTRL = 0.10` (crypto_layer.h:109) and `TRUST_T_MIN_CTRL = 0.50`
  (crypto_layer.h:108), a compromised controller is revoked after exactly **5** penalty
  events, cumulative over the *entire simulation run*, with no way to "earn back" trust
  between them — even widely spaced isolated incidents accumulate toward permanent
  revocation.
- For an **honest** controller (no CP attack active), this is harmless in the currently
  tested attack variants: `ctrl_trust_update_negative()` is only reachable via genuinely
  unauthorized FlowMods or confirmed active-HF duplication, neither of which an honest
  controller triggers, so its score simply stays at the 1.0 initial value
  (`crypto_layer.h:690`) for the whole run. The dead reward branch is therefore not currently
  producing an observable metrics discrepancy for the variants this session's other fixes
  focused on (Attacks 1, 5, 6).
- It **would** matter for any future evaluation that models a controller compromised only
  *intermittently* (e.g., an attacker that alternates malicious and honest FlowMod batches to
  evade detection) — the proposal's equation implies such a controller could recover trust
  during honest intervals; the current code cannot express that at all, since the recovery
  branch is simply unreachable.
- It also means **M5's `L_failover`/failover-event metrics can only ever be exercised by
  monotonic decay to revocation**, never by a controller that fluctuates near
  `T_min_ctrl` and is revoked/reinstated — again, not a bug for the attack variants currently
  simulated, but a real gap versus the equation as written, and worth knowing before anyone
  designs a new ablation or attack variant around intermittent controller compromise.

**Severity:** Medium — doesn't corrupt any currently-collected metric for the existing 8
attack variants (since honest controllers never reach the negative-update call sites), but is
a genuine, silent equation-fidelity gap: half of eq:ctrl_trust_update's case structure has no
code path that can ever execute.

**Fix scope:** decide what "conflict evidence < f+1" should mean operationally (e.g., call
`ctrl_trust_update_positive()` on a per-endorsement-cycle basis when a controller's FlowMod
batch commits cleanly with zero conflicts, mirroring how vehicle-side
`trust_update_positive()` fires on every clean packet verification in the LRAD-RSU path at
`routing.cc:121323-121324`), then wire that call site in alongside the existing
`transmit_delta_values()` FlowMod-commit block (routing.cc:118144-118171) — the natural place
to reward a controller whose FlowMod just cleanly committed.

---

## Everything else checked in this pass: no deviations found

For completeness, since the user's instruction was to review the whole chapter, the
following mechanisms were specifically re-verified line-by-line against their equations and
found to match:

- **Signatures S5, S6, S7, S8** (`s5_detection.h` – `s8_detection.h`): each implements its
  exact conjunction structure from eq:sig_s5 through eq:sig_s8, including the real
  ML-DSA-87 `sig_valid`/`stark_hop_ok` fields from `g_packet_crypto` where available (with a
  documented, clearly-marked fallback to ground-truth attack flags only when the crypto
  record hasn't been populated yet — not a silent shortcut).
- **Witness-based forwarding verification** (eq:dup_alert_cond, eq:nfa_sign, eq:da_sign,
  eq:bft_penalty): `witness_check_duplication()`, `witness_submit_duplication_alert()`, and
  `witness_submit_nfa_alert()` in `crypto_layer.h` perform real ML-DSA-87 signing and
  verification of alerts, pool them per target node, and gate the trust penalty on a real
  `2f+1` count of *cryptographically verified* alerts (`threshold = 2*WITNESS_F+1`, `WITNESS_F
  = 1` → threshold 3), matching main.tex exactly and consistent with the chaincode's own
  independent `2f+1=3` implementation (`blockchain/mobiguard-cc/alert.go`).
- **Multi-RSU FlowMod endorsement** (eq:endorsed_commit, eq:rsu_endorsement): confirmed real
  `f+1` quorum (`flowModEndorsementQuorum`, `blockchain/mobiguard-cc/types.go:35`) with real
  per-RSU ML-DSA-87 endorsement signatures, matching `test_synthetic.sh`'s own
  `f+1=2` walkthrough.
- **Vehicle/RSU trust score + quarantine** (eq:trust_update, eq:quarantine):
  `trust_update_positive`/`trust_update_negative` in `crypto_layer.h` correctly implement the
  `min(1,·)`/`max(0,·)`-bounded update with quarantine firing at `T_min = 0.50`, unlike the
  controller-side equivalent — this one's reward branch **is** correctly wired (called from
  `routing.cc:121323-121324` on every `hop_ok && timing_ok && g_batch_passed` success).
- **BRFA-v2** (alg:brfa_v2, eq:fed_robust): `lstm_pipeline/src/fed_aggregator.py` implements
  all four steps (trust gate → hash verify → Krum/coordinate-median filter → weighted
  aggregation) faithfully, including the `2f+1` abort condition on Step 1 and an already
  session-documented, reasoned edge-case fix for the `<2` candidate Krum degenerate case.
- **Dynamic RSU-controller assignment + failover** (eq:rsu_ctrl_assign, eq:ctrl_failover,
  eq:sc_revoke): `ctrl_reassign_rsus()` in `crypto_layer.h` correctly computes
  `argmin` zone-distance to the trusted-controller set excluding the just-revoked controller,
  matching the equations; this session's earlier M5 race-condition fix (monotonic
  `g_failover_max_ms`, documented at crypto_layer.h:809-824) remains correctly in place.
- **DKG key rotation** (eq:key_rotation_trigger, eq:vk_commit_rotated): confirmed
  `dkg_rotate_keys()` is called from `trust_update_negative()` exactly when a revoked node is
  an RSU (`node >= N_Vehicles && node < N_Vehicles + N_RSUs`), matching the trigger's
  `T_rj < T_min ∧ rj ∈ P_DKG^current` condition, gated correctly behind the AB11-A ablation
  flag.
- **LRAD-OBU / LRAD-RSU composite dispatchers** (alg:lrad_obu, alg:lrad_rsu,
  eq:composite_light): `scratch/lrad.h`'s `lrad_obu()` and `lrad_rsu()` were re-checked
  explicitly (not just the individual `s1`–`s8_detection.h` files they call into). Both
  correctly compute `D_OBU`/`D_RSU` as the OR of their four/five constituent flags exactly as
  in the pseudocode, gate `BC.Write`/`BTMM` inside the `D_RSU` block per alg:lrad_rsu, and are
  wired into `routing.cc:121352-121390` with the correct vehicle-hop-vs-RSU-hop dispatch and
  the 1ms OBU→RSU escalation delay. `lrad_rsu()`'s BTMM call reuses each fired signature's own
  underlying `sig_valid`/`stark_hop_ok` field rather than recomputing independently, which
  mirrors alg:lrad_rsu's own self-consistent design (BTMM is invoked with the same packet's
  σ/π_delay/π_hop that just failed) — checked that this cannot let a node be rewarded in the
  same call where it was just flagged, and it can't. One narrow, low-severity note: the BTMM
  call is skipped (not just defaulted-negative) when no crypto record exists yet for that
  sender/packet (`have_crypto == false`) — the detection event is still logged via
  `bc_write_detection_event`, but no trust-score consequence follows in that edge case. Not
  worth a standalone fix; noted for completeness.
- **Cryptographic pipeline structural claims** (Algorithm FCIP, §Hybrid Cryptographic
  Integrity Layer): the ML-DSA-87 signing, STARK proof generation/verification call sequence,
  and the `O_crypto`/`O_full`/`O_batch` overhead equations were re-read here; these already
  have a documented, known gap (O_crypto's 64-byte SHA3-512 commitment vs the proposal's
  "≤100KB per STARK proof" figure) reported earlier this session under M7 — re-confirmed
  present, not re-analyzed further here since it's already tracked.

---

## Summary table

| # | Finding | Severity | Fix scope |
|---|---|---|---|
| 1 | `ctrl_trust_update_positive()` defined but never called — controller trust can only decay, never recover, contradicting eq:ctrl_trust_update's reward branch | Medium | **FIXED** — reward call site wired into the clean-FlowMod-commit path in `transmit_delta_values()` |

Combined with [docs/SIMULATION_SETTINGS_DEVIATIONS.md](SIMULATION_SETTINGS_DEVIATIONS.md)'s 6
findings and the previously-tracked M7 STARK-overhead gap (O_crypto size, missing T_STARK
timing component — see `docs/METRICS_DEVIATIONS_FROM_PROPOSAL.md`), this completes a full
line-by-line pass of main.tex's technical content: Introduction/Literature Review (previously
covered by `docs/SECTION_VERIFICATION_REPORT.md`), the entire Methodology chapter (this
document), and Simulation Settings/Results/Timeline/Conclusion
(`SIMULATION_SETTINGS_DEVIATIONS.md`). The Performance Metrics and Ablation Study sections
have their own dedicated, already-thorough tracking documents
(`METRICS_VERIFICATION_REPORT.md`, `METRICS_DEVIATIONS_FROM_PROPOSAL.md`).
