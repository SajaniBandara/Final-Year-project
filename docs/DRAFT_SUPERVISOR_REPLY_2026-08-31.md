# Draft reply to supervisor — 2026-08-31

> Draft for review before sending. Every number below was measured tonight on
> the HPC machine; file:line references are to the current `n11` tree.

---

Thanks — agreed on the priority order, with one significant correction that
makes the top item cheaper than it looks.

## 1. Quarantine enforcement is already implemented — what's missing is validation, not code

The enforcement point you're asking for was written on 2026-08-30 and is in the
tree now, behind `--enable_quarantine_enforcement` (default OFF). The guard is
`quarantine_blocks()` (`crypto_layer.h:554`) and it is already wired into the
three data-path actions you named:

| action | call site |
|---|---|
| schedule a hidden duplicate | `routing.cc:121644`, `routing.cc:121740` |
| forward / flow source | `routing.cc:121825` |
| TCAM attack injection | `tcam_attack_helper.h:784` |

The diagnosis in its header comment is your figure verbatim — "of 43 quarantined
RSUs, 39 kept scheduling hidden duplicates afterwards — 1,329 post-quarantine
firing cycles." That measurement is what prompted the fix; it just landed behind
a default-OFF flag so prior results stay reproducible, and no run since has
turned it on.

So items 2 (fix it) is done, and the real work is items 1 and 3 — scoping and
validation. Answering your two scoping questions directly:

**Is the RSU-side path unenforced for every attack type, or HF-specific?**
It was unenforced for *all* of them, and the new guard is likewise variant-blind
— it keys on node id, not attack type. The A4 case additionally needed the
attacking *vehicle's* trust decremented on S4, which is a separate fix committed
today (`7cd6b5a`). Note that makes pre-2026-08-31 A4 numbers non-comparable.

**Does the vehicle-side hold path actually stop forwarding, or is it decorative?**
It is implemented, not decorative: `enable_local_quarantine` (added 2026-08-06)
has real hold, release-on-confirm and T_hold-expiry logic
(`crypto_layer.h:294-331`), called from `lrad.h:862` on the `D_OBU=1` branch as
`alg:lrad_obu` specifies. It has simply never been switched on, so both of its
release counters read zero on every run to date. Validation is the gap, not
implementation.

**On `T_hold`.** main.tex defines it only symbolically (symbol table 1274,
eq:local_quarantine 2371/2377) with no number, and the simulator's 0.1 s was a
placeholder. Rather than ask you to pick a constant, we have made it
measurable — the mechanism bounds it from both sides:

- **Lower bound:** the hold must outlast the RSU.Confirm round trip or a real
  attacker resumes forwarding before confirmation lands. `escalate_to_rsu()`
  schedules RSU processing exactly 1 ms out (`lrad.h:746`) and that handler
  calls `rsu_confirm_release()` (`lrad.h:687`), so the floor is ~1 ms + jitter.
- **Upper bound:** `T_hold` is the latency penalty paid by any vehicle held in
  *error*, so oversizing it degrades delivery in proportion to the OBU
  false-positive rate.

That gives a criterion needing no arbitrary choice: **the smallest T_hold at
which releases are dominated by RSU.Confirm rather than timeout expiry.** The
counters that decide it already exist (`g_fwd_release_confirm` /
`g_fwd_release_timeout`), and `scripts/sweep_t_hold.py` runs the sweep and
applies the criterion. We will report the measured value with the validation.

The only question genuinely for you: are you happy with an empirically selected
T_hold reported as such, or do you want a value fixed in main.tex first?

**One correction to our own inventory.** `DEFAULT_OFF_FIXES_AND_PRIORITIES_2026-08-31.md`
states "VERIFIED-IN-CODE: five of the eight are not CLI-settable" and that they
need a source edit plus rebuild. **That is wrong — all eight are CLI-settable.**
Verified against the built binary's `--PrintHelp` tonight. This matters for
sequencing: turning enforcement on is a change to the run command, not a code
change, so item 1 can start immediately and in parallel as you wanted.

**M4 — agreed, we will not report it until enforcement is on.** Related: there is
also an `enable_corrected_lmit` flag (default OFF) whose comment records a **2.6×
inflation** in the uncorrected M4. Both need to be on before any M4 number is
meaningful, so the eventual rerun should enable the pair, not just enforcement.

**A8's rise-and-fall (item 11) — you were right, and it is already diagnosed and
fixed.** Your reasoning was correct: with enforcement off, that fall cannot have
been mitigation. The mechanism turned out to be a measurement artefact in UCR
itself, found and fixed today in commit `cd6d626`:

The dedup set keyed on `(flow_id, packet_id)` instead of the `H(p)` SHA3-512
packet identity that main.tex:1306 specifies. **Both components are
cycle-scoped**, so the pair repeated every cycle and the set capped at ~32
entries for an entire 300 s run — saturating the numerator to zero from about
t = 100 s. The published "fall" was the metric running out of identifiers.

Two things make this conclusive rather than plausible:

- it reproduces identically with **quarantine enforcement OFF across 5 seeds**,
  so it was never mitigation-dependent
- **interception volume actually PEAKS at t = 140–160 s**, long after UCR reads
  zero — the true curve does not fall where the published one does

A second defect sat behind it: once identity was fixed, UCR clamped at the
opposite rail (1,238 distinct eavesdropped packets against a denominator of 778,
exceeding 1 in 37 of 58 cycles) because `|P_total|` used `sum(f_size)`, a
smaller population than the numerator draws from. Both are fixed.

**So the item-11 curve must be re-run and the old one withdrawn** — it is not
merely unvalidated, it is wrong. Tonight's binary already includes both fixes.

## 2. Correction: the per-variant recalibration gives 0.495 on A6, not 0.707

We ran the combined pass (latch + per-variant recalibration together, as
approved). The A6 improvement is real but smaller than the 0.707 in circulation:

| A6 | before | after |
|---|---|---|
| FPR | 75.3% | **4.1%** — better than the 8.3% predicted |
| MCC | 0.301 | **0.495** — not 0.707 |

We would rather correct this now than have 0.707 reach a table.

## 3. Which variant binds theta_HF^(k) — your instinct was right

It is **not** always A6:

| binder | RSUs |
|---|---|
| A6 | 34 / 64 |
| A5 | 11 / 64 |
| A8 | 8 / 64 |
| A7 | 5 / 64 |
| no fittable cell (fallback) | 6 / 64 |

188 of 256 (variant, RSU) cells had enough quiet windows to fit; 68 did not.

## 4. Combined A5–A8 under the single deployed threshold

Latched label, `theta_HF^(k) = max_v theta_v,k`, variant-blind in application:

| variant | DR | FPR | MCC |
|---|---|---|---|
| A5 | 10.5% | 0.3% | 0.227 |
| A6 | 55.8% | 4.1% | 0.495 |
| A7 | 10.4% | 0.2% | 0.227 |
| A8 | 18.0% | 0.5% | 0.261 |

Per-variant thresholds are kept as a separate labelled diagnostic table, as you
specified, and are not presented as deployed performance.

## 5. The stale-calibration artefact you warned about is in our current baseline

Your warning about "comparing a new ground truth against a stale calibration and
mistaking the mismatch for a real regression" applies to the baseline we have
been comparing against, and we nearly reported the artefact.

`calibrate_hf_theta.py:56` fits the pooled `theta_hf` on **`y_binary`**, while
everything downstream scores **`y_indep`**. Under the HF spike criterion almost
every A5/A6 window is positive, so those variants contribute **zero** quiet
windows: the stored calibration pool is 87 windows with A5 = 0 and A6 = 0. The
resulting threshold (0.7895) is not conservative, it is *accidentally permissive*
— which is what produces both A5/A7's flattering DR and A6's 75% FPR.

Measured against that stale baseline, per-variant max appears to hurt A5, A7 and
A8. Refit the pooled threshold on the same latched label (32,497 quiet windows,
all four variants represented, `theta_hf` → 2.1114) and the picture inverts —
per-variant max wins on **all four**:

| variant | pooled, fairly refit | per-variant max |
|---|---|---|
| A5 | 0.135 | **0.227** |
| A6 | 0.376 | **0.495** |
| A7 | 0.133 | **0.227** |
| A8 | 0.196 | **0.261** |
| mean | 0.210 | **0.303** |

So the construction you specified is vindicated — but only once the baseline is
calibrated against the label it is scored on. We suggest retiring
`hf_theta.json` in its current form rather than leaving a threshold fit on one
label and scored on another.

## 6. Latch reset boundary — flagged, and now actionable

Agreed, and worth stating plainly: the end-of-run boundary is correct *only*
because the compromised state currently never ends. The moment enforcement is
on, that premise is false and the boundary should move to quarantine time per
`eq:local_quarantine`. Since the enforcement code already exists, this is
immediate rather than hypothetical — we will move the boundary in the same pass
that enables enforcement, and will not re-report latched numbers across that
change without saying which side of it they came from.

## 7. One further finding on FPR

Independently of the above: 71% of M1's false positives come from the LSTM term
in the `D_RSU` OR-composite. Excluding it moves FPR 53.3% → 15.3% and *raises*
MCC 0.435 → 0.565 despite losing recall. A5–A8 currently run at DR 100% /
FPR 73–82% — a detector that is nearly always on.

The codebase already treats soft LSTM-only hits as untrustworthy in two places
(blocked from the BTMM trust gate, `lrad.h:571`; withheld from the per-node
confusion matrix, `lrad.h:628`) but still admits them to the score M1 reports.
We have a one-line fix behind `--require_lstm_high_conf` and will report it with
the calibration results.

---

**Sending back next:** quarantine enforcement validation (post-quarantine firing
cycles with the flag on), the measured `T_hold` from the sweep above, the
re-run A8 curve on the corrected UCR, the classifier-head vs autoencoder
comparison, and the persistence-threshold sweep.

**One decision we need from you:** whether an empirically selected `T_hold`,
reported with its selection criterion, is acceptable — or whether you want a
value fixed in main.tex first. Nothing else above is blocked on you.
