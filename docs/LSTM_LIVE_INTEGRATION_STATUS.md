# LSTM Live Integration — Status & Fix Plan (2026-07-27)

Triggered by a re-audit of the live in-sim federated-LSTM path against
`main.tex`'s `alg:lrad_rsu`/`sec:fed_lstm`. An earlier verbal summary in this
session incorrectly claimed `D_LSTM` was not wired into the detection
decision at all — that was wrong (based on reading `lstm_logger.h`'s stale
comments and `PENDING_FIXES.md` Fix 17 without checking `lrad.h` directly).
This doc corrects the record and tracks the small set of items that are
genuinely still open.

## Corrected findings

1. **`D_LSTM` → `D_RSU` wiring: already done.** `scratch/lrad.h:314-328`
   computes `flag_LSTM` from `g_lstm_last_dlstm[]` and ORs it into `D_RSU`
   exactly per `alg:lrad_rsu`. `record_detection_event()` is called for
   `flag_LSTM`-only detections (`lrad.h:380-387`), so it counts toward the
   live TP/FP/MCC numbers (`is_detected_node[][]`). This matches
   `docs/DEV_MERGE_SPEC_CHANGES.md` item #10, implemented but never checked
   off there.

2. **Escalation gating: not a gap.** `main.tex:5745`'s "escalation to LSTM
   detector at score ≥ 0.5" is intentionally implemented as unconditional
   per-cycle inference + a separate logged `escalated` flag, not as a literal
   gate on whether inference runs. `docs/PENDING_FIXES.md` Fix 16 already
   reasons through this: `D_OBU` is boolean so "score ≥ 0.5" ≡ "D_OBU==1",
   and gating the log would break `θ^(k)` calibration, which needs the full
   continuous benign population. No change needed.

3. **Plane-based attribution for LSTM: already correct, not "provisional".**
   `main.tex:2579-2581`'s comment on the composite-decision `Else` branch
   reads literally: *"Data-plane or LSTM: attacker is vehicle/RSU"* — i.e.
   the paper itself buckets LSTM-only detections into the data-plane
   attribution path (attribute to `v`/`prev_sender`), not the control-plane
   `c_atk` path used by S3/S5/S7. `lrad.h:370-373`'s comment calling this
   "provisional pending [item] #11" is overly cautious: item #11 (full
   plane-based `BTMM(node, attack_plane)` restructure) is a real, separate,
   much larger piece of work for S3/S5/S7's controller-attribution path, but
   it adds no additional requirement for LSTM specifically — LSTM's current
   data-plane-style attribution already matches the algorithm as written.
   **Action: correct the misleading comment, no behavioral change.**

4. **Genuinely missing: blockchain audit-trail write for LSTM detections.**
   `bc_write_detection_event()` (`scratch/bc_blockchain_helper.h:493`) hard-
   rejects `signal_idx` outside `[1,8]`, so `lrad.h` deliberately skips
   calling it for `flag_LSTM` (would need signal `9`). Every other signal
   (S1/S2/S3/S4/S5/S6/S7/S8) gets a blockchain-logged detection event;
   LSTM-triggered detections currently do not. **Action: extend the valid
   range to include signal 9 and call it from `lrad.h`.**

5. **Stale documentation.** `lstm_logger.h`'s header comment (lines ~51-55)
   and the block comment above the inference call (lines ~555-567) still
   say live inference is "logging-only" and does not feed detection/
   mitigation — contradicted by `lrad.h`. `PENDING_FIXES.md` Fix 17's
   "Not yet done" bullet says the same. **Action: correct both, without
   rewriting the historical fix write-ups (append a dated correction
   instead of editing history).** `docs/DEV_MERGE_SPEC_CHANGES.md` item #10
   checkboxes are unchecked despite being done — mark resolved.

## Fix checklist

- [x] Extend `bc_write_detection_event()` signal range from `[1,8]` to
      `[1,9]` (`scratch/bc_blockchain_helper.h`).
- [x] Call `bc_write_detection_event(rsu, prev_sender, 9, t_now)` for
      `flag_LSTM` in `scratch/lrad.h`; remove the now-incorrect "deliberately
      not called" comment.
- [x] Correct the "provisional pending #11" comment in `lrad.h` to state
      LSTM's data-plane attribution is already spec-correct.
- [x] Correct stale "logging-only" comments in `scratch/lstm_logger.h`.
- [x] Append a dated correction note to `docs/PENDING_FIXES.md` (new Fix 22)
      rather than rewriting Fix 16/17's original text.
- [x] Mark `docs/DEV_MERGE_SPEC_CHANGES.md` item #10 resolved with notes on
      why the two sub-bullets don't require further LSTM-specific work.

## Explicitly out of scope here

- Item #11's full `BTMM(node, attack_plane)` restructure for S3/S5/S7
  control-plane attribution — real, tracked separately, unrelated to LSTM.
- Items #1-#9, #12-#13 in `DEV_MERGE_SPEC_CHANGES.md` — rule-engine (S1/S3/
  S4), `f_unauth` prevention gate, blockchain receipt log, controller delay
  evidence, witness dedup — none of these are LSTM-specific.
- `evaluator.py`'s M1-M3 metrics remain LSTM-only by design (`sec:
  lstm_validation`'s Table `lstm_detection` is explicitly measuring
  standalone LSTM detector quality, matching ablation arm AB1-B — it is not
  supposed to reflect the composite `D_RSU`).
