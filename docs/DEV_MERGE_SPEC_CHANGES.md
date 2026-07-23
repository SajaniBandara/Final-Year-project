# dev → S13 main.tex Merge: Spec Changes to Reconcile

Source: commit `9397820` "chore: main.tex updated" (Apsari Udithara, dev branch),
merged into S13 at `7171454` (trivial merge, S13 never touched `docs/main.tex`,
so the merged file is byte-identical to dev's version — no conflicts, nothing
lost). Diff verified line-by-line against `19a1e15..9397820` (all 27 hunks
read in full). This file catalogs every substantive (non-cosmetic) change and
tracks reconciling `scratch/*.{cc,h}` and the LSTM pipeline against the new
spec. Cosmetic-only hunks (acronym wrapping, `\eqref`→`\ref` consistency,
whitespace) are omitted.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## 1. Signature S1 — new selectivity conjunct
`main.tex` eq:rule_s1 / eq:sig_s1 (~L1930, ~L2210, ~L2270 post-merge)

S1 now requires a third condition:
```
f_S1(p,r,t) = [δ_p > δ̄_r(t)+kσ_r(t)] ∧ [Priority(p)=High]
              ∧ [δ_best(r,t) ≤ δ̄_r(t)+kσ_r(t)]
```
`δ_best(r,t)` = mean per-hop delay of best-effort (non-high-priority) traffic
at RSU `r`. Rationale: genuine congestion raises delay for *all* classes, so
the new conjunct evaluates false under congestion and S1 no longer fires —
this is the congestion/false-positive filter the old 2-conjunct version
lacked.

- [ ] Implement `δ_best(r,t)` tracking (per-RSU EWMA or windowed mean of
      best-effort packet delay) in `scratch/s1_detection.h`.
- [ ] Add third conjunct to the S1 flag computation.
- [ ] Re-run A1/A2 sweep to check FPR impact (should drop further given the
      new congestion filter).

## 2. TCAM anomalous-rate estimator — now speed-conditioned
`main.tex` eq:density_normalized_rate (~L1586)

Old: `λ̂_a(t) = λ_obs(t) − E[λ_l(t) | ρ(t)]` (density only).
New: `λ̂_a(t) = λ_obs(t) − E[λ_l(t) | ρ(t), v̄(t)]`, justified via Little's
Law (`λ_l ∝ ρ·v̄`), estimated by **OLS regression** of `λ_obs` on `ρ·v̄` from
benign SUMO traces (was a lookup/conditional-expectation table keyed on ρ
alone).

- [ ] Locate current `λ̂_a` estimator in `scratch/tcam_detection.h` /
      `tcam_flow_generator.h`.
- [ ] Add `v̄(t)` as a second regressor; refit via OLS on benign-only traces.

## 3/4 UPDATE (2026-07-23 pull, commits c580490 + 706b44a)
S3/S4 have been reimplemented by Nipuni (code, `706b44a`) and documented by
Apsari (main.tex, `c580490`) — **superseding items #3/#4 below in
substance**, though with two confirmed deviations from main.tex's own
literal equations and one likely typo:

- **S3** (`tcam_detection.h` `ComputeTcamDetection()`): now gates on
  `f_unauth` alone (`unauth_count > 0`, sourced from
  `TcamEntry::authorized`, set at install by `tcam_flowmod_authorized()` —
  an f+1 endorsement-quorum check keyed on FlowMod fid provenance, not
  `is_malicious`). The rate term (`λ̂_a`) is explicitly demoted to
  reporting-only. **Mismatch**: main.tex's own updated `eq:rule_s3`
  (post `c580490`) still requires a second mandatory conjunct,
  `∄v: flow(r) ∈ F_active(v)` — the code's `flag_s3` line
  (`tcam_detection.h`, "7. S4" comment block) implements only
  `unauth_count > 0`, no active-flow check at all.
- **S4**: now `U_TCAM(r,t) > U_thresh` alone (`tcam_util_thresh`), with
  `v_atk = argmax λ_PI` computed only for attribution, not gating.
  Threshold hardcoded to **0.213** (calibrated to real benign p99,
  `routing.cc` comment: "benign util p99=0.213 (max=0.289)... gives ~91%
  TPR at ~1% benign FPR"). **Mismatch**: main.tex's own updated
  `eq:rule_s4` text still lists `U_thresh` as
  `[tbd: {0.5, 0.6, 0.7, 0.8}]` — an unresolved sweep placeholder that
  doesn't even include the value actually calibrated and shipped in code.
- Both deviations from the *original* literal equations (dropping the
  rate-AND-term) are explicitly, deliberately flagged in code comments
  with empirical justification (rate-based S3/S4 measured at ~2-3% DR
  under realistic mobility due to attack/benign rate overlap — a real,
  documented finding, not an oversight). The two *doc vs. code* mismatches
  above (S3's missing active-flow conjunct, S4's stale threshold sweep)
  are NOT flagged anywhere and look like `c580490` not fully catching up
  to `706b44a`'s exact final implementation — worth a fix pass.
- Likely typo introduced in `c580490`: `main.tex` §sec:rule_based's
  section title changed from "Lightweight Rule-Based Detection Engine" to
  **"the anomalous Rule-Based Detection Engine"** — reads like an
  accidental bad edit, not an intentional rename.
- **Still not done** (unaffected by this pull): S3/S4 remain evaluated at
  OBU-side too, via `lrad_tcam_snapshot()` in `lrad.h` — a THIRD,
  independent, still-stale implementation (hardcoded `lambda_hat_a>10.0`,
  `lambda_pi>15.0`, `tcam_util>0.80`, untouched by either commit). Items
  #5/#6 (shrink `D_OBU` to S1/S2p only, move S3/S4 to RSU-only) would
  retire this stale copy entirely — still pending.

## 3. Signature S3 — redefined (TCAM control-plane)
`main.tex` eq:rule_s3 (~L1886), eq:sig_s3

Old: `f_S3,S4(r,t) = [λ̂_a > λ_thresh] ∧ [U_TCAM > U_thresh]` (joint
rate+utilization, evaluable at OBU).
New: `f_S3(r,t) = [λ̂_a(r,t) > λ_thresh] ∧ [f_unauth(r,t)=1]` — `U_TCAM` is
**dropped** as a mandatory conjunct (rationale in main.tex: requiring it
delays detection until the table is already partially filled); replaced by
the blockchain-endorsement-failure flag `f_unauth` (eq:unauth_flowmod).
**S3 moves from OBU-evaluable to RSU-only.**

- [ ] Remove `U_TCAM` conjunct from S3 in `tcam_detection.h`.
- [ ] Wire `f_unauth(r,t)` (see #7 below) into S3.
- [ ] Move S3 evaluation out of the OBU-side path into RSU-side.
- [ ] **High priority**: this directly affects the current A3 FPR problem
      (structural TCAM over-flagging documented in `PENDING_FIXES.md` Fix
      19/21) — the ground-truth labelling issue may partly resolve once S3
      no longer keys off raw `U_TCAM` persistence.

## 4. Signature S4 — redefined (TCAM data-plane)
`main.tex` eq:rule_s4 (~L1886)

New: `v_atk = argmax_v λ_PI(v,r,t)` (highest-flooding source vehicle);
`f_S4(v_atk,r,t) = [λ_PI(v_atk,r,t) > λ_PI,thresh]`. `U_TCAM` dropped as
mandatory conjunct here too (corroborating only). **S4 moves from
OBU-evaluable to RSU-only.**

- [ ] Implement per-source `λ_PI` tracking and `argmax` in
      `tcam_detection.h`.
- [ ] Remove `U_TCAM` conjunct; move to RSU-only evaluation.
- [ ] Same A4 FPR relevance as #3.

## 5. D_OBU composite — shrinks to 2 terms
`main.tex` eq:composite_light (~L2334)

`D_OBU = f_S1 ∨ f_S2p` only (was `f_S1 ∨ f_S2p ∨ f_S3 ∨ f_S4`), since S3/S4
now need RSU-only observables (FlowMod rate, per-source PACKET_IN, TCAM
state). New: on `D_OBU=1`, the OBU now also calls `HOLD_FORWARD(v,r)`
(local quarantine, see #6) before escalating.

- [ ] Update `routing.cc`'s OBU-side composite decision (~L121655, "OBU
      path: evaluate S1, S2-partial, S3, S4" comment is now stale — S3/S4
      move to RSU).

## 6. New: OBU local quarantine action
`main.tex` eq:local_quarantine (new)

```
HOLD_FORWARD(v,r) ⇒ fwd_state(v)=Hold until RSU.Confirm(v,r) ∨ t > t_detect+T_hold
```
On `D_OBU=1`, the OBU suspends forwarding of the flagged flow for up to
`T_hold` pending RSU confirmation, rather than forwarding-while-escalating.

- [ ] Implement `HOLD_FORWARD`/`T_hold` state machine at the OBU.
- [ ] Implement `RSU.Confirm(v,r)` release path (ties into #9's
      `RSU.Confirm` call in the RSU algorithm).

## 7. f_unauth — reinterpreted as a prevention gate, not just a detector
`main.tex` eq:unauth_flowmod (~L3409)

Previously purely a detection flag (logged to blockchain, contributed to
Attacks 1/3/5/7 detection). Now: an RSU that evaluates `f_unauth(r_k,t)=1`
**rejects/does not install** the FlowMod at all — converts detection into
prevention. Still logged for audit (new `eq:flowmod_log`, referenced but its
own equation body wasn't in this diff — check if it already exists
elsewhere in main.tex).

- [ ] Add flow-table install gate: reject FlowMod install when `f_unauth=1`
      instead of installing-then-flagging.
- [ ] Verify this doesn't break existing TCAM-exhaustion attack modeling in
      `tcam_attack_helper.h` (if the malicious FlowMod is now never
      installed, does the A3/A4 attack simulation still make sense as
      currently modeled?). **Needs careful thought before implementing** —
      flag for discussion, don't blindly implement.

## 8. New: blockchain packet receipt log (cross-RSU dedup for S6–S8)
`main.tex` eq:packet_receipt_log (new, ~L3409)

Every RSU now logs every packet reception to the RSU-chain immediately:
`BC.LogReceipt(H(p), dst, r_k, ts_recv, MLDSA.Verify(copy))`. Any RSU can
query `BC.QueryReceipt(H(p), d', W)` to check cross-RSU duplication without
direct RSU-to-RSU channels. `msg_id` is replaced by `H(p)` (SHA3-512 packet
hash) as the universal packet identity throughout S5–S8.

- [ ] Implement `BC.LogReceipt` / `BC.QueryReceipt` in the blockchain layer
      code.
- [ ] Switch S5–S8 duplicate-detection logic from local `msg_id` lookup to
      `H(p)` + blockchain receipt query.

## 9. Signatures S5–S8 — reworked conditions
`main.tex` eq:sig_s5/s6/s7/s8 (~L1930-2060)

- **S5** (active HF, control-plane): gains a 4th conjunct, `BatchVerify=0`
  (aggregate signature failure at the batch level, not just the individual
  copy).
- **S6** (active HF, data-plane): now explicitly requires
  `∄ FM(r): dst=d'` (FlowMod-absence) to disambiguate from S5 — main.tex
  notes that without this conjunct S6 would also fire on S5 events.
- **S7/S8** (passive HF): gain a `CopyVerify_d'` term (blockchain-retrieved
  MLDSA verification result at `d'`), rather than purely local witness
  volume/hop-proof checks.
- New attacker-isolation step after `BatchVerify` failure: linear fallback
  scan `v_atk,copy = argmin_i{i : MLDSA.Verify(σ_i,pk_i,m_i)=0}`
  (eq:batch_fallback) to find the *specific* failing hop, since batch
  rejection alone doesn't identify which node failed.

- [ ] Update S5–S8 flag logic per the new conjuncts.
- [ ] Implement `eq:batch_fallback` per-signature isolation scan (O(n),
      only runs on batch-verify failure).

## 10. D_RSU composite — LSTM formally integrated + S3/S4 added
`main.tex` (~L2334, algorithm `alg:lrad_rsu`)

Old: `D_RSU = f_S2f ∨ f_S5 ∨ f_S6 ∨ f_S7 ∨ f_S8` (5 terms).
New: `D_RSU = f_S2f ∨ f_S3 ∨ f_S4 ∨ f_S5 ∨ f_S6 ∨ f_S7 ∨ f_S8 ∨ flag_LSTM`
(8 terms), where `flag_LSTM = D_LSTM^(k)` (new eq:lstm_detection ref) — the
federated LSTM's per-RSU anomaly output is now an explicit OR'd term in the
system-level detection decision, not a separate side-channel.

- [ ] **Directly relevant to current work**: check whether `routing.cc`'s
      Fix-16 escalation gate / `evaluator.py`'s M1-M3 should be recomputed
      against this composite `D_RSU` (rule engine ∨ LSTM) rather than
      LSTM-only, if we want a number that matches what main.tex now
      specifies as *the* system detection decision.
- [ ] Add S3/S4 flags into the RSU-side composite (depends on #3/#4).

## 11. New: plane-based attacker attribution & mitigation routing
`main.tex` algorithm `alg:lrad_rsu`, `alg:btmm` (heavily rewritten)

- Control-plane flags (S3, S5, S7) → attribute to assigned controller
  `c_atk = c*(r,t)` (eq:rsu_ctrl_assign) → `BTMM(c_atk, ctrl-plane)`.
  S5 additionally dual-attributes: also penalizes the forwarding node found
  via `v_atk,copy` (#9's fallback scan).
- Data-plane flags (S2, S4, S6, S8) → attribute to vehicle/RSU
  (`v_atk` for S4, else `v`) → `BTMM(v_report, data-plane)`.
- `BTMM` signature changed: `BTMM(node, attack_plane)` instead of
  `BTMM(v, σ, π_delay, π_hop, {pk_i}, {m_i})` — now branches internally on
  `attack_plane` into a controller-trust path vs. the original
  batch/STARK-verify node-trust path.
- New RSU-side call `RSU.Confirm(v,r)` to release the OBU's `HOLD_FORWARD`
  (#6) once full-mode analysis clears the node.

- [ ] Implement `c*(r,t)` controller-assignment lookup if not already
      present (check `eq:rsu_ctrl_assign` — likely already exists given
      multi-controller trust section predates this diff).
- [ ] Restructure `BTMM` call sites to the new `(node, attack_plane)`
      signature.
- [ ] Implement `RSU.Confirm` → `HOLD_FORWARD` release.

## 12. New: controller "delay evidence" channel
`main.tex` eq:delay_evidence, eq:ctrl_trust_update (~L3701)

Previously controller trust only decremented on *conflict evidence*
(unauthorized FlowMods, `f_unauth`). New: also decrements on **delay
evidence** — `E_delay(c_i,t) = |{r_k ∈ R_{c_i}(t) : f_S1(r_k,t)=1}|`,
requiring `f+1` independent RSUs assigned to the same controller to
independently detect S1 before it counts (BFT-consistent, prevents a single
compromised RSU from falsely accusing a controller). Rationale given in
main.tex: closes the gap where a timing-manipulating controller issuing
*topologically valid* FlowMods (zero conflict evidence) was never
penalized.

- [ ] Implement `E_delay(c_i,t)` counter (needs S1-per-RSU-per-controller
      tracking).
- [ ] Update controller trust update rule to decrement on
      `conflict_evidence≥f+1 ∨ E_delay≥f+1`.

## 13. Witness BFT penalty — dedup by distinct vehicle
`main.tex` eq:bft_penalty (~L2608)

Old: cardinality was over the raw union of alert messages
(`α_w ∪ β_w`). New: cardinality is over **distinct witness vehicles** `w`
that each submitted ≥1 valid alert for the same `(v_i, p)` event — smart
contract deduplicates by `(w, v_i, H(p))` before counting. Prevents one
vehicle submitting multiple alerts from unilaterally crossing `2f+1`.

- [ ] Check current witness/BFT penalty implementation for whether it
      already dedups by vehicle or counts raw alerts — likely a real bug
      fix if the current code counts raw messages.

## 14. Minor / textual only (no code impact expected)
- `sec:lstm_validation` intro: "all 9 variants" → "all 8 attack variants
  plus benign baseline runs" (wording only, same data).
- Ablation section: `eq:nfwd_detect` reclassified as belonging to the
  Selective-Time-Delay (1-4) ablation scope, explicitly excluded from the
  witness-mechanism (7-8) ablation's component list.
- Dual-mode summary table (~L5446): signature-coverage column text updated
  to match #3/#4/#5 (S3/S4 now RSU-side).
- New acronyms: OLS, UCR, FlowMod, BFT, FTISCON, BlockREV, GPS.
- New symbol-table rows: `δ_best`, `E_delay`, `T_hold`, `H(p)`,
  `BC.QueryReceipt`, `v_atk,copy`.

---

## Suggested implementation order
1. #1 (S1 selectivity) — smallest, self-contained, improves FPR.
2. #3/#4 (S3/S4 redefinition) — highest relevance to the open A3/A4 FPR
   investigation, moderate scope.
3. #5/#6 (D_OBU shrink + HOLD_FORWARD) — depends on #3/#4 being RSU-only.
4. #10 (D_RSU composite + LSTM formal integration) — needed to report a
   spec-accurate combined MCC/DR/FPR number.
5. #8/#9 (blockchain receipt log + S5-S8 rework) — larger, touches crypto
   layer.
6. #11/#12/#13 (BTMM restructure, controller delay evidence, witness
   dedup) — largest scope, blockchain/trust-management layer.
7. #7 (f_unauth prevention gate) — deliberately last; needs a design
   discussion first since it changes what "attack success" even means for
   A1/A3/A5/A7 in the simulator.
