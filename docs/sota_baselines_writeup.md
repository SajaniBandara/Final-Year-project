# SFTO-Guard and TAP — mechanism write-up (for related work + what to adapt)

Written from the in-sim reproductions in this repo (sfto_detection.h, tap_detection.h) and
the source papers. Framed as related-work explanation, with a synthesis at the end on what
is worth adapting into Proposed's own design (S3/S4, S1/S2) — adapting the *principle*, not
copying the method.

## SFTO-Guard (Tang et al., 2023) — slow-rate flow-table-overflow detector

**Signal.** Per-RSU flow-table *occupancy*: the number of installed rules at a switch/RSU
as a fraction of its TCAM capacity, `occ(t) = rule_count(t) / capacity`. This is a
control-plane/data-plane resource signal — it does not look at packet timing or content,
only at how full each switch's rule table is and how fast it is filling.

**Core detection logic — prediction, not instantaneous threshold.** SFTO's key idea is that
a slow-rate overflow attack fills the table gradually, so an instantaneous "is it full yet"
test fires too late (only once the table is already saturated and legitimate flows are
already being dropped). Instead SFTO *forecasts* occupancy a short horizon ahead from the
recent install rate and alarms when the *forecast* crosses a capacity fraction:

- Per-cycle install rate `growth(t) = rule_count(t) − rule_count(t−1)`, smoothed by an EWMA
  `g_ewma = β·g_ewma + (1−β)·max(growth,0)` (β ≈ 0.70 — heavier weight on history, so a
  single noisy cycle does not trigger).
- Predicted occupancy H cycles ahead: `occ_pred = occ + H · g_ewma / capacity` (H ≈ 10).
- **Alarm** (latched per RSU) when `g_ewma > 0` (table actively growing) *and*
  `occ_pred ≥ θ`.

**Decision boundary.** A *static* capacity-fraction threshold θ (the paper uses θ = 0.90).
It is deliberately static and global — the paper's stated design. Its known weakness is
false positives at high legitimate density, where benign flows also grow the table toward θ.

**Preprocessing / windowing / smoothing.** Occupancy sampled once per measurement cycle
(≈ the rule hard-timeout window); the EWMA is the only smoothing; the H-cycle look-ahead is
the "windowing." The alarm is *latched* per RSU (once an RSU trips, it stays flagged) — so
scoring is naturally **per-RSU** (did this RSU ever forecast overflow), not per-packet or
per-window.

## TAP (Arsalan & Rehman, FIT 2018) — timing-anchored forwarding-delay detector

**Signal.** Per-hop packet *timing*: for each forwarded packet, the observed receive/forward
time `v` at the next hop versus the *claimed* forward timestamp `PPAT` the previous hop
asserted (carried in the packet). The signal is the deviation `|v − PPAT|`.

**Core detection logic — exact-equality / near-zero-tolerance rule.** TAP assumes an honest
forwarder's claimed and observed timing agree up to clock precision, so *any* deviation
beyond a tiny epsilon means the packet was held (delayed) or its timestamp fabricated:
`if |v − PPAT| > margin → flag the sender as an attacker`. The flagged node is added to a
Controller Defaulter List (latched blacklist). There is no learned model — it is a single
deterministic timing-threshold rule, per the paper's Algorithm 1.

**Decision boundary.** A *static* margin, essentially a floating-point epsilon (≈ 1 µs in the
paper's exact-equality intent). This makes TAP extremely sensitive: any real network jitter
above ~1 µs trips it, which is why its false-positive rate is high on realistic traffic
(benign per-hop jitter here has p99 ≈ 6 ms ≫ 1 µs).

**Preprocessing / windowing / smoothing.** PPAT is extracted from the packet tag and
clock-offset-anchored to the receiver; the decision is **per-packet** with **no smoothing or
windowing** — a single deviating packet flags the sender. Detection is latched per node.

## What's worth adapting into Proposed (principle, not copy)

1. **Predictive occupancy for S3/S4 (from SFTO) — hypothesis TESTED, does not hold at tested
   intensities.** The initial hypothesis was that SFTO's forecast (`occ + H·rate`) is what
   lets it out-detect S4 on A4 (SFTO A4 ≈ 0.96 vs Proposed S4 ≈ 0.68–0.72 per-RSU, see
   phantom_seed1_results.md), so adapting a rate/trend term into S4 would be the most promising
   change. Directly testing that (S4t grid, empirical section below) does **not** bear it out at
   p60: the predictive term adds zero coverage over plain occupancy S4 and fires later, because
   the fill is fast enough that raw occupancy crosses S4's threshold before any forecast does.
   Two consequences: (a) the predictive term is a *slow-rate* mechanism → future-work / low-
   penetration sweep, not a general S4 upgrade; (b) since the predictive term does **not**
   reproduce SFTO's A4 advantage under our per-window metric, the remaining SFTO-vs-S4 gap is
   most likely a **scoring-convention** effect (SFTO's latched per-RSU scoring vs our per-window
   M1 — point 4) rather than the forecast itself. Isolating that requires re-scoring SFTO under
   the window metric like-for-like; flagged as the open question.
2. **Per-RSU (local) calibration — TESTED, does NOT help (see empirical section below).**
   The hypothesis was that a single pooled U_thresh over-flags high-baseline RSUs and
   under-detects low-baseline ones, so fitting the benign percentile *per RSU* would help.
   Measured, it did the opposite: S4-only MCC fell 0.637→0.591 and FPR rose 0%→7.6%. The
   pooled θ=0.121 already sits above every benign RSU's occupancy (0% FPR) while detecting
   70.6%; per-RSU benign-p99 is very low for most RSUs (median 0.022, 47/64 below the pooled
   value) so it only adds false positives on low-traffic RSUs. **So per-RSU calibration is not
   the source of SFTO's A4 advantage** — and neither is the predictive term at tested
   intensities (point 1). Do not bother with per-RSU static thresholds; the unexplained gap
   points to scoring convention (point 4), which is the open question to resolve.
3. **From TAP — what NOT to copy:** the exact-equality margin. TAP shows that a too-tight,
   un-calibrated static timing threshold is the direct cause of high FPR. Proposed's S1/S2
   already use a benign-percentile / EWMA baseline, which is the correct fix TAP lacks — worth
   stating as the contrast (Proposed already does the calibrated version of TAP's idea).
4. **Latched vs windowed scoring** is a metric choice, not a detector improvement — noted so
   we compare like-for-like (see the per-RSU re-score in phantom_seed1_results.md).

## Empirical: per-RSU S4 calibration + per-link S2 variance (A4 @60%, seed 1, crypto-off)

Both runs identical config; only the S4 threshold source differs (pooled global vs per-RSU
benign-p99 file). Scored with scripts/m1_local.py, RSU mode, 30s warmup, 10s dedup blocks.

**S4 calibration — per-window composite (`score`, all detectors):**

| arm | MCC | DR | FPR | TP | FP | FN |
|-----|-----|----|-----|----|----|----|
| before — pooled θ=0.121 | 0.6554 | 86.7% | 18.6% | 1033 | 88 | 158 |
| after  — per-RSU benign-p99 | 0.6153 | 88.1% | 25.8% | 1049 | 122 | 142 |

**S4 calibration — S4-only (`score_primary`, isolates the changed signature):**

| arm | MCC | DR | FPR | TP | FP | FN |
|-----|-----|----|-----|----|----|----|
| before — pooled θ=0.121 | **0.6370** | 70.6% | **0.0%** | 841 | 0 | 350 |
| after  — per-RSU benign-p99 | 0.5910 | 72.9% | 7.6% | 868 | 36 | 323 |

Per-RSU calibration **hurt** on both the S4-only and composite metric: +2.3pp detection but
36 new false positives (FPR 0→7.6% on S4-only). Mechanism: per-RSU benign-p99 is low for most
RSUs (min 0.000, median 0.022, max 0.499; 47/64 below the pooled 0.121, 30 below 0.02, 2 at
zero). Under attack, low-traffic RSUs pick up modest legitimate occupancy that now exceeds
their tiny thresholds. The pooled 0.121 already sits above all benign RSU occupancy, so it
achieves 0% FPR *and* 70.6% detection; per-RSU refinement only adds noise. **Conclusion: keep
the pooled S4 threshold; SFTO's edge on A4 is its predictive term, not per-RSU calibration.**

## Empirical: predictive S4 term (S4t) grid search (A4 @60%, seed 1)

Per the S4t spec: `Δo_t = o_t−o_(t−1)`; `g_t = α·Δo_t + (1−α)·g_(t−1)`, `g_0=0`;
`ô_(t+H) = o_t + H·g_t`; S4t fires when `ô_(t+H) > θ`, with θ = pooled benign p99 of
`ô_(t+H)`. Grid α∈{0.1,0.2,0.3,0.4,0.5}, H∈{1,2,3,5,8}. Computed offline from the
per-RSU per-cycle occupancy traces of the existing benign and A4 runs, scored with the
real scripts/m1_local.py (score_primary, RSU, 30s warmup, 10s dedup) — identical
semantics to every other M1 number. S4t is scored both alone and unioned with the
existing S4 (the composite fold-in ORs the TCAM flags, so S4∪S4t is how it would feed in).

Result — **nothing in the grid moves the composite:**
- All 25 combos: **FPR 0.0%** (θ = benign p99).
- **S4t alone**: MCC 0.556–0.563 (best α=0.1,H=8 → 0.5633) — *worse* than S4-alone 0.6370.
- **S4∪S4t**: **exactly 0.6370, DR 70.6%, TP 841, FP 0 for every combo** — byte-identical
  to S4 alone. S4t's detections are a strict subset of S4's (union TP = S4-alone TP = 841),
  so the predictive term adds zero window-level coverage.
- **Latency** (the SFTO early-warning rationale): S4t fires **+11.1 cycles *later*** on
  average (42.76 vs 31.63) and on **fewer** victim RSUs (38 vs 43) than plain S4.

**Why:** at 60% penetration the TCAM fill is *fast*. Raw occupancy crosses S4's static
0.121 early (cycle ~31); the forecast `o+H·g` must reach its benign-p99 threshold (~0.39–0.49,
inflated by the growth term) which it hits *later*, not earlier. SFTO's predictive advantage
requires a genuinely *slow-rate* fill where occupancy creeps up without sharply crossing a
static threshold — not the regime we test at p60. So at these intensities plain occupancy S4
is already at the detection ceiling and the predictive term cannot help.

**Recommendation:** do not adopt S4t into the composite at tested intensities — it changes no
number (Q6/A3/A4 provably unchanged, since S4∪S4t = S4). The predictive term belongs in the
*sweep + future-work* framing: evaluate it at low penetration / slow-rate fill (the Exp-1
penetration axis, e.g. p20, or a rate-limited A4 variant), which is the regime where a forecast
earns its keep. This also refines the write-up's point 1 above: the predictive term is a
slow-rate mechanism, not a general S4 upgrade.

**S2 — does benign hop-delay vary meaningfully by link?** Benign run, 38,727 samples over 261
distinct link sources. Pooled hop-delay p50=2.09ms, p90=3.22ms, p99=5.40ms, max=10.3ms.
Per-link (245 links ≥30 samples): per-link mean 2.02–2.73ms; per-link p99 2.36–9.42ms (≈4×
spread, stdev ~0.96ms). So there is *some* per-link variance, but it is trivial versus the
detection margin: every link's benign delay is ≤10.3ms while the attack injects 55–200ms and
the threshold (default 50ms, or recalibrated benign-p99 ≈5.4ms) sits far above every link's
benign delay and far below the attack. A single global threshold separates benign from attack
on every link. **Conclusion: per-link S2 calibration is not warranted** — unlike S4, whose
per-RSU occupancy baselines overlap the attack-induced occupancy range, S2's per-link delay
baselines are all clustered well below the decision boundary.

## A1 S1-attribution — known limitation / future work (2026-10-01)

**Status: documented, not fixed. A1 reported at composite MCC 0.647 (3-seed mean, sd 0.0014).**

S1 is a clean detector: 99.9% of its A1 firings are on the ~100 ms injected attack
delay, 0% on benign-sized delays — its true benign FPR is ~0%. A1's composite FPR of
22.5% is therefore **not benign noise**: the control-plane attack's delay propagates
multi-hop, and S1 correctly detects it at honest *downstream* RSUs that the ground truth
(RSUs under compromised controllers) does not credit. Those real detections are scored as
false positives, depressing both MCC (0.647) and the apparent FPR (22.5%).

**Fix attempted and reverted (2026-09-30):** attributing S1's mark to the immediate
previous hop's covering RSU (`dw_attribute_accused(prev_sender)`, the A2-style fix) made
A1 *worse* (0.647 → 0.499, FP 295 → 335) — because the CP delay is multi-hop, so
`prev_sender` is not the injecting node. Reverted.

**Correct fix (future work):** walk each delayed safety-critical packet's path and use the
per-hop witness/STARK timestamps (`claimed_forward_timestamp(node,flow,pkt)` is queryable
for any hop; the full path is in `proposed_routing_tables`) to localize the hop where the
incoming-vs-outgoing delay spikes, and attribute S1's detection to *that* hop's covering
RSU. Estimated ceiling if done: A1 toward ~0.9 with FPR dropping toward A2's ~7%. Does not
change the headline SOTA table, where A1 is reported at 0.647 with this FPR caveat stated.
