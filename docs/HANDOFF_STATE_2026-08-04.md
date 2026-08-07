# Project State & Next Steps — 2026-08-04

**Read this first.** It is the whole picture: what was broken, what is fixed,
what is still open, and what to do next in what order.

Companion doc: [`Q1Q6_ABLATION_RUNBOOK.md`](Q1Q6_ABLATION_RUNBOOK.md) — how to
actually run the ablation on the cluster.

---

## 1. One-paragraph summary

A supervisor audit found that several LSTM input features and training labels
were silently wrong for the data-plane attack variants. All of those are now
fixed and verified. Separately, the tooling needed to run the supervisor's
Q1–Q6 component-isolation ablation did not exist — three CLI flags were missing
and there was no runner. Those now exist. **The ablation has not yet been run to
completion**; it was abandoned locally on wall-clock grounds and is packaged for
the cluster. One calibration parameter (β) is still unresolved and is now known
to have a deeper problem than first thought (§5.1).

---

## 2. What was broken, and why it mattered

### 2.1 `zkp_delay_fail` / `zkp_hop_fail` were dead for DP variants — FIXED

`stark_update_meta()` keyed the LSTM counters on `signer`. Those counters are
only ever *read* by RSU index. For the data-plane variants (A2/A4/A6/A8) the
signer is very often a **vehicle**, so every increment was written under a key
nothing reads.

Measured by matched A/B (A2, p=60, 30 s, seed 7, identical params, only the
attribution changed):

| | RSUs with nonzero | RSU-cycles |
|---|---|---|
| Before | **0 / 64** | **0** |
| After | 37 / 64 | 187 |

Not "small" — **identically zero across all 1792 training rows**. A constant
column contributes no gradient, so the LSTM never saw this feature for A2.

### 2.2 A2, A6, A8 training labels were corrupt — FIXED

`declare_attackers()` / `hf_declare_malicious_rsus()` mark the attacker on its
**own** node index. The LSTM label reads `is_malicious_node[variant][rsu_idx]`,
indexed **by RSU**. So whenever the attacker was a vehicle, every RSU row read
`label = 0` for the whole run despite the attack firing.

* **A2** — fixed, and the fix is load-bearing: RSUs with ≥1 positive went
  **38 → 54 of 64** (158 attackers drawn: 38 RSU, 120 vehicle).
* **A6/A8** — fixed, but measured **inert**: across p=40 % and p=20 %, all 91
  malicious vehicles resolved to a covering RSU (0 unmapped) yet every covering
  RSU was *already* directly malicious. Cause: A6/A8 draw attackers from the
  **on-path** pool, which structurally places vehicle relays in on-path RSU
  zones. Supervisor confirmed this is intended and physically necessary (an
  off-path node cannot forward traffic it never sees). Kept as defensive code.
* **A5/A7** deliberately excluded — control-plane, attacker pool is
  RSUs/controllers, so the case cannot arise.

> The fix belongs in `lstm_logger.h` (the label consumer), **not** in
> `declare_attackers()`. The attacker-side assignment is correct for the S1–S8
> confusion matrix, which attributes to `prev_sender`. Changing it would break
> the one consumer that works.

### 2.3 S3/S4 existed twice, one of them contradicting the paper — FIXED

There were two parallel implementations: an OBU-side one folded into `D_OBU`,
and the RSU-cycle one in `tcam_detection.h` that actually feeds
`is_detected_node[][]` and therefore every DR/FPR number reported.

The OBU-side one contradicted `eq:composite_light` (main.tex:2354-2357), which
defines `D_OBU = f_S1 ∨ f_S2p`, and main.tex:2364-2368, which states S3/S4
require RSU-only observables. Its formula matched neither `eq:rule_s3` nor
`eq:rule_s4`. Removed. S3/S4 now exist once, in the spec-correct place.

### 2.4 Q1–Q6 could not be run at all — FIXED

`g_disable_s5_s6` and `g_disable_s7_s8` **did not exist**. Without them a
"disabled" S7/S8 still fed `D_RSU`, the BTMM trust penalty and the BC.Write
record, so Q2 and Q4 could not isolate anything. Added, along with
`g_disable_s3_s4`.

**Note the deliberate asymmetry — do not "fix" it:**

* `g_disable_s5_s6` / `g_disable_s7_s8` gate the **signature computation**.
* `g_disable_s3_s4` gates **only the confusion-matrix recording**, because
  `flag_s3`/`flag_s4` still publish the `eq:lstm_gate` (main.tex:3317-3326)
  LSTM suppression signal. That gate's rationale is *structural* — TCAM residual
  occupancy — so it must stay live even while S3/S4's output is off. Gating the
  flag would silently un-suppress the LSTM in Q3, the run meant to isolate it.

### 2.5 Q4 was being measured with the wrong instrument — FIXED

Q4 appeared to violate the expected pattern (A5 showed TP=32 where 0 is
required). It does not. In Q4 every signature is disabled and the witness never
calls `record_detection_event()` directly — it reaches the confusion matrix only
via `trust_update_negative()` → quarantine → `record_detection_event()`
(`crypto_layer.h:1070-1074`). So the generic matrix in Q4 measures *quarantine*,
not *witness detection*.

Read from the witness's own M12/WAP-R counters:

| Q4 | generic TP | **TP_W** | FP_W | FN_W | precision | recall |
|---|---|---|---|---|---|---|
| A3 | 0 | **0** | 0 | 0 | – | – |
| A5 | 32 ← artefact | **0** ✅ | 0 | 0 | – | – |
| A7 | 27 | **37** | 202 | 2 | 15.5 % | 94.9 % |
| A8 | 37 | **102** | 70 | 56 | 59.3 % | 64.6 % |

A5 is `TP_W = 0` — the witness detected nothing. The expected pattern holds.
`--analyse` now prints this block automatically.

---

## 3. Verification criterion — corrected

The supervisor's original Item 2 criterion was wrong and has been amended:

| Variant family | Verify | Why |
|---|---|---|
| **A2, A4** (delay / TCAM) | `zkp_delay_fail` | `eq:stark_delay_verify` ties π_delay to S1/S2 |
| **A6, A8** (hidden forwarding) | `zkp_hop_fail` | `eq:stark_hop` encodes next-hop policy compliance |

`zkp_hop_fail = 0` on A2/A4 is **spec-correct, not a failed fix** — a delay
attack forwards along the authorised path, so π_hop never fails. Confirmed: A6
@ p=40 % shows `zkp_hop_fail` at 39/64 RSUs.

---

## 4. Do this next, in this order

### Step 1 — Run Q1–Q6 on the cluster ▶ READY NOW

Follow [`Q1Q6_ABLATION_RUNBOOK.md`](Q1Q6_ABLATION_RUNBOOK.md). **Run Q4 first**
(8 runs, not 48) — it is the supervisor's stop condition.

Sizing: ~60 min per run; wall ≈ `ceil(48 / workers) × 60 min`. ~3 h at 16
workers. Do not run this on a laptop — 8-core local runs hit 93–97 °C and ~6 h.

`NS3_DIR` already defaults to the cluster path, so it runs unmodified there.

**Blocking:** nothing.

### Step 2 — Report Q1–Q6 results

`--analyse` produces everything the supervisor asked for: per-variant
TP/FP/FN/TN, MCC, the cumulative-addition MCC table, the LSTM suppression count
for Q3/Q6, and the witness-native counters. Check against the expected pattern
in runbook §4 and report any violation with exact numbers **before** proceeding.

**Mandatory caveat, printed automatically — do not drop it:** the LSTM in the
repo is pre-retrain and was trained with `zkp_delay_fail` dead for A2 and A6/A8
labels corrupt. **Q3/Q6 LSTM numbers are lower bounds, not final figures.**

### Step 3 — β calibration ⚠ SEE §5.1 FIRST

Blocked on the 300 s × 5-seed benign baseline. The window-decoupling fix is
done, but a **deeper problem was found** — read §5.1 before running it.

### Step 4 — LSTM retrain (needs supervisor authorisation)

Only after Q1–Q6 confirms wiring. Requires regenerating training data with the
fixed attribution and labels. **All previously collected A2/A6/A8 training data
is stale and must not be used.**

### Step 5 — Re-run AB3 (`lstm_pipeline/src/ab3_feature_ablation.py`)

AB3 compares a 5-feature baseline against 7 features (adding
`zkp_delay_fail`, `zkp_hop_fail`) and currently concludes the ZKP features add
nothing:

```
A1 +0.0081   A5 -0.0294
A2 -0.0030   A6 -0.0056
A3 -0.0038   A7 +0.0012
A4 -0.0002   A8 -0.0167      Overall -0.0030
```

That conclusion is **invalid**. `zkp_delay_fail` was identically zero, so AB3-B
was "5 features vs 5 features + 2 dead columns". Must be regenerated after the
retrain. It is offline and cheap (no ns-3 runs), it just has to happen *after*.

### Step 6 — Full 240-run sweep

Blocked on β (Step 3) per the supervisor.

### Step 7 — Paper edit ✅ DONE (2026-08-05)

Supervisor agreed to add one sentence to the attacker-allocation paragraph
(main.tex:5382-5388) documenting the **on-path spatial constraint** for A5–A8.
The paragraph currently specifies attacker *count* and *plane* but no spatial
rule; the on-path constraint exists only in code.

Added, immediately after the existing paragraph (verified against
`hf_attack_helper.h:383-386`'s on-path RSU/vehicle selection logic before
writing it): *"For Hidden Forwarding (Variants~5--8), attacker candidates are
additionally restricted to nodes lying on an active flow's routing path, since
an off-path node can neither observe nor duplicate traffic it never relays."*
Not yet committed — still a working-tree change in `docs/main.tex`.

---

## 5. Open issues

### 5.1 ⚠ The β convergence criterion may be fundamentally broken

The supervisor's fix (decouple the stability window from the 22 s ceiling) is
implemented in `rule_calibrator.py`. But investigating it surfaced a worse
problem.

`ewma_convergence_time()` declares convergence when σ²(t) sits within **1 %** of
its final value for N consecutive cycles. On realistic noisy input **that never
happens** — the EWMA variance of a fluctuating delay series is itself a
fluctuating series. Measured on synthetic stationary white noise, no β in
`{0.7, 0.8, 0.9, 0.95}` converges at 1 %; only β=0.99 does.

The old code **hid this**: on failure it returned `len(series)`, so a
non-converging β was scored as if it converged at the last cycle. Every
non-converging β then tied and `min()` picked arbitrarily.

⇒ **The β = 0.8 currently compiled into `s1_detection.h:79` may be meaningless.**
Its comment still cites the superseded 9 s criterion.

The module now returns `inf` and **rejects** rather than silently ranking, so
this is visible instead of producing a confident wrong answer. If the real
benign baseline also yields "no β converges", the criterion itself needs
rethinking. The principled alternative is the EWMA effective window
`N_eff = 1/(1-β)` (β=0.9 → 10 cycles, β=0.95 → 20), which is deterministic and
lands naturally inside the 9–22 s band.

**This is a spec decision, not an implementation one. Raise with the supervisor.**

Also note: `--s1_beta`'s CLI help says "default 0.9" while the actual default is
0.8 (`routing.cc:141926` vs `s1_detection.h:79`).

### 5.2 A7 witness precision is poor

94.9 % recall against 15.5 % precision — the witness finds nearly everything and
misattributes most of it. That is a property of the 2f+1 BFT threshold
(`--witness_f`), not a detection failure. A8 is better balanced (59.3 / 64.6).
Supervisor judgement needed.

### 5.3 `zkp_delay_fail` cannot be forced to zero

Under `--disable_crypto`, `zkp_hop_fail` zeroes out (`stark_verify_hop`
short-circuits) but `zkp_delay_fail` does not — it derives from a raw wall-clock
comparison at `routing.cc:121884` with no crypto gate. Consequence: **Q3 runs on
9 effective features, not 8.** State this when reporting Q3.

### 5.4 `f_unauth` / `¬b_batch` are paper-code divergences (accepted)

Documented at the S5 detection site. `f_unauth` is implemented via the
FlowMod-endorsement proxy; `¬b_batch` is unreachable because crypto is modeled
rather than computed. Supervisor accepted both as simulation modeling notes.
**Do not "fix" — changing either breaks S5.**

---

## 6. Working with this repo — practical gotchas

* **Never commit local path swaps.** `routing.cc` stores cluster paths
  intentionally. On a dev laptop: `scripts/local_path_swap.sh local` before
  running, `... hpc` before any `git add`. Check with `... status`. On the
  cluster no swapping is needed. A `git stash pop` once auto-staged local paths
  across 25 files — check `git diff --cached | grep /home/<user>/` before
  committing.
* **Edit the real source.** `scratch/routing/` in the ns-3 tree is
  symlinks/copies of `~/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/scratch/`.
  Edits to the former are silently lost.
* **Build via the launcher**, not plain `./waf build` — the latter does not copy
  the `.py` helpers and the sim aborts mid-run with "Solution not found":
  ```bash
  python3 scripts/run_std_attacks.py --build
  ```
* **The security-metrics CSV header is multi-line.** Several `#`-prefixed lines,
  so `csv.DictReader` sees only the first 7 names while rows carry ~52 fields.
  Parse **positionally**. Column order is `TP, FP, TN, FN` — TN before FN. A
  9-column TCAM block is inserted only for attacks 3/4, shifting everything
  after it.
* **Result files collide.** `write_security_metrics_csv()` names by
  `(attack_number, pct)` only. The ablation runner therefore uses one sequential
  lane per attack and renames immediately. Do not parallelise within a lane.
* **Clear stale lane logs** before re-runs — the LSTM suppression count is
  parsed from them.
* Branch is `S15`. **Do not push to `dev`** — PR only.

---

## 7. Commit trail

| Commit | Contents |
|---|---|
| `bc9775f` | Ablation isolation flags, S3/S4 dedup, A2 label ground truth |
| `7307662` | zkp attribution for DP variants, A6/A8 labels, Q1–Q6 runner |
| `01dc9f6` | HPC runbook; analyser CSV parsing fix |
| `eeb84eb` | Witness-native counters for Q4; resolves apparent A5 violation |
| *this* | β window decoupling + criterion issue; this handoff doc |
