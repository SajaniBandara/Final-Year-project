# Mobility Amplification — Implementation Plan

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

## 0. Why this document exists

Supervisor (Nilmantha Sir, 21/07/2026):

> "Make sure your attack simulation undergoes the mobility amplification
> described in the modeling. If you don't simulate that, you will be caught
> in the mobility experiment with flat graphs. Mobility amplification is a
> core novelty point which we have even mentioned in the paper titles. We
> can't bypass that."

This is not a hypothetical risk. Three independent pieces of evidence from
the current source tree confirm it is already happening:

1. **`lstm_pipeline/calibration_report.txt`** — the OLS fit of the
   mobility-adjusted delay baseline (`eq:mobility_baseline`, main.tex
   ~L2217: `δ̄_r(t) = δ0 + α_ρ·ρ(t) + α_v·v̄(t)^-1`) against 27,795 benign
   rows gives **R² = 0.0004**, with `α_ρ = 5.2e-07` and `α_v = 1.237e-05`.
   Both are statistically indistinguishable from zero. The comment in
   `scratch/s1_detection.h` (~L60) states this outright: *"delay in NS-3
   DSRC is dominated by crypto/routing overhead rather than vehicle
   density/speed; baseline effectively collapses to δ0."*
2. **`scratch/selective_time_delay.h`** (`calculate_unified_selective_delay`,
   ~L10–20) — the attacker's injected delay (`attack_delay_ms`, CLI flag,
   default 80 ms) is a **single fixed constant**, applied identically
   regardless of the configured mobility regime. A comment at
   `scratch/routing.cc:141777–141784` documents that the *original* design
   drew this from `Uniform(60, 300)` ms — "upper bound matched the handoff
   jitter window" — but the shipped code uses a fixed value instead, which
   cannot reproduce mobility-dependent overlap with legitimate jitter.
3. **`lstm_pipeline/mobility_stratified_results.json`** — for A1
   (CP-SelectiveDelay), MCC goes **0.69 → 0.77 → 0.78 → 0.88** as `ρ`/`v̄`
   increase. Detection gets *better* at higher mobility, not worse — the
   opposite of what Mechanism 1 (`eq:bhattacharyya`, main.tex ~L1536)
   claims should happen. (Sample sizes shrink at the high end — 198 rows vs
   1086 — so some of this is noise, but it is not evidence *for* the
   claimed effect either.)
4. **Missing SUMO trace inputs for Experiment 2's own speed sweep.**
   `eq:speed_x` (main.tex ~L5253–5265) requires `v̄ ∈ {10, 60, 100, 140}`
   km/h. The live simulation selects its trace file from `--maxspeed` via
   the `switch` in `scratch/routing.cc` (~L142235 onward,
   `mobility/mobility_urban_<maxspeed>.tcl`), and the only urban trace
   files that actually exist on disk are for
   `{0, 10, 20, 30, 40, 50, 60, 150}` km/h. **There is no
   `mobility_urban_100.tcl` or `mobility_urban_140.tcl`** — two of the
   four points Experiment 2 is specified to sweep cannot be run today,
   independent of whether RC1–RC3 below are fixed. See RC4 (§3) and §4.6.

There is also no code anywhere in `scratch/` that tracks an explicit
"vehicle handed off to a new RSU" event — `handoff`/`zone-cross` only
appear in comments, never in executable logic (confirmed by grep across
`scratch/*.h`, `scratch/routing.cc`). The paper's Mechanism 1 argument
depends on handoff-induced jitter; nothing currently generates it.

## 1. Goal

After this work, the Experiment 2 mobility sweep (`v̄ ∈ {10, 60, 100, 140}`
km/h, main.tex ~L5199 `eq:speed_x`) must show attack-detection quality
(M1 MCC, and ideally FPR) for the Selective Time Delay signatures (S1/S2)
**degrading monotonically-in-trend as `v̄` increases** — not flat, and not
inverted — with the underlying mechanism traceable to a real, code-visible
source of mobility-dependent jitter rather than a curve-fit to produce the
desired shape (see §7, Risks).

## 2. Scope

**In scope (this plan, Phase 1):** Mechanism 1 only — handoff-latency
masking of the Selective Time Delay signatures (Eq 1 `eq:bhattacharyya`,
Eq 14 `eq:delay_updated`, Eq 15 `eq:mobility_baseline`, Eq 16
`eq:ewma_variance`, attacks A1/A2, signature S1).

**Out of scope (flag for a follow-up plan, not fixed here):** Mechanisms
2–4 — evasion probability under stale topology (Eq 2, TCAM churn camouflage
Eq 3, hidden-forwarding observation window Eq 4, attacks A3–A8). These need
the same kind of audit (does the code actually thread mobility into the
attack/detection timing, or is the mobility parameter cosmetic) before
Experiment 2 is trusted for those variants too. Tracked as a follow-up
item, not blocking this phase.

**Also in scope (infrastructure, not a Mechanism-1 fix):** generating the
missing `mobility_urban_100.tcl`/`mobility_urban_140.tcl` trace files
(RC4, §4.6). This is a data-availability gap, not part of the
jitter/attack-delay mechanism itself, but it blocks Experiment 2 from
running at all four specified speed points regardless of whether §4.1–§4.5
land, so it is tracked here rather than deferred.

## 3. Root causes (recap)

- **RC1**: No handoff/zone-crossing event exists in the simulator. Vehicle
  position relative to RSU coverage is never diffed timestep-to-timestep to
  detect "just changed serving RSU."
- **RC2**: Legitimate delay jitter is modeled only as a flat linear
  regressor against instantaneous `ρ(t)`/`v̄(t)` averaged into 1 Hz cycles
  — a regression that gets swamped by DSRC MAC/crypto overhead in the
  aggregate and washes out any transient, event-driven jitter a real
  handoff would cause.
- **RC3**: The attacker's injected delay is a fixed scalar, disconnected
  from RC1/RC2 entirely, so even if legitimate jitter became
  mobility-dependent, the attack signal wouldn't move with it.
- **RC4 (data gap, not a modeling gap)**: Two of the four `v̄` points
  Experiment 2 is specified to sweep — 100 km/h and 140 km/h — have no
  corresponding `mobility_urban_*.tcl` trace file at all, so the
  simulation cannot even be launched at those speeds today. This is
  orthogonal to RC1–RC3 (it blocks *running* the sweep; RC1–RC3 are about
  whether the sweep's *result* would be meaningful) but must be closed
  before Experiment 2 can be executed as literally specified.

## 4. Design

### 4.1 Handoff detection primitive (new)

Add a per-vehicle "serving RSU" tracker: each simulation cycle, compute the
nearest RSU to each vehicle from its current position (position is already
available via the ns-3 mobility model / SUMO trace already driving
`rho(t)`/`v_bar(t)` — see `scratch/routing.cc` density/speed emission near
L118019). Compare to the previous cycle's serving RSU per vehicle; a change
= a handoff event for that vehicle at that timestep.

- File: new `scratch/handoff_tracker.h` (small, self-contained, included
  the same way `s1_detection.h`/`s2_detection.h` are).
- State: `std::vector<uint32_t> veh_serving_rsu` (current), diffed against
  previous each cycle.
- Output: a `bool just_handed_off(vehicle_id)` query and a per-vehicle
  "cycles since last handoff" counter (used in 4.2).

### 4.2 Mobility-driven legitimate jitter (replaces/extends RC2)

At a handoff event, inject a transient extra delay component into the
packet(s) associated with that vehicle for a short window following the
handoff (representing real flow-rule recomputation/reinstallation latency,
main.tex ~L1524: "legitimate handoff latencies of 50–300 ms during
flow-rule recomputation and reinstallation"). Because zone residence time
`t_zone` shrinks with speed (`eq:observation_window`, Eq 4:
`N_obs = r · t_zone`), handoffs become *more frequent* at higher `v̄` —
this is what should drive the aggregate jitter distribution to widen with
speed, without needing to hand-tune a linear regressor.

- File: `scratch/s1_detection.h` — the existing `δ_r(t)` accumulation point
  (`s1_rsu_obs_sum`/`s1_rsu_obs_count`, ~L75) is where this extra jitter
  term gets added in for a handoff-affected packet.
- Keep the existing linear baseline (`s1_delta0`,`s1_alpha_rho`,
  `s1_alpha_v`) as-is structurally (it's what `eq:mobility_baseline`
  specifies) — RC2's fix is giving it a real signal to fit *to* by
  recalibrating after 4.1/4.2/4.3 land (§4.4), not replacing the formula.

### 4.3 Mobility-conditioned attack delay (replaces RC3's fixed constant) — RESOLVED

**Supervisor guidance (2026-07-25):** *"You can make it pseudo-random (you
can control the randomness with defined bounds and behavior). Not totally
random. You can calibrate or use a citation."* This settles the
randomized-vs-independent-variable question raised in the clarification
message: not full randomization, not a single fixed point either —
bounded pseudo-randomness anchored to the existing intensity levels.

**Locked design:**
- Each of Eq 82's three intensity levels ($1.1\times\Delta_{max}\approx55$
  ms, $2\times\Delta_{max}=100$ ms, $4\times\Delta_{max}=200$ ms) becomes
  the **anchor of a bounded band** instead of a single deterministic
  value: draw per-packet delay from a narrow range around each anchor
  (default **±10% of the anchor**: ~50–60 ms / 90–110 ms / 180–220 ms).
  Bands are non-overlapping by construction, so Experiment 1's three
  lines stay distinguishable.
- Sampling uses a **seeded PRNG** (pseudo-random = deterministic given a
  seed, not system-entropy random), one documented seed per
  (attack, intensity level, penetration %) condition, so runs stay
  reproducible for the thesis writeup.
- **Experiment 1** (Attack Penetration): attacker's band stays fixed at
  whichever intensity level is under test — mobility does not enter here,
  consistent with `eq:intensity_td`'s existing design.
- **Experiment 2** (mobility/speed sweep): the attacker's band does
  *not* widen with speed. The amplification comes from the **legitimate**
  side instead — handoff-triggered jitter (§4.1/§4.2) widening the
  benign delay distribution as `v̄` increases, while the attacker's fixed
  band increasingly falls inside it. This is what makes Eq 1's $D_B$
  meaningful as a function of speed without touching the attacker's own
  parameters per speed point (avoids the overfitting risk in §7).

- File: `scratch/selective_time_delay.h`
  (`calculate_unified_selective_delay`) — replace the deterministic
  `attack_delay_ms` return with a seeded draw from the band for the
  active intensity level; `scratch/attack_variables.h` — add the three
  anchor/band constants alongside the existing 50–300 ms legitimate-range
  documentation (~L51–52).
- Keep `--attack_delay_ms` as a CLI override for standalone/deterministic
  testing (existing use case, e.g. the S2-threshold sweep noted at
  `routing.cc:141781`) — the banded pseudo-random mode becomes the
  default for the attack-percentage sweep path used by Experiments 1/2.
- Open sub-decision, not yet supervisor-confirmed: exact band width
  (±10% is our proposed default — narrow enough the three levels never
  collide, wide enough to give Eq 1 a non-degenerate distribution).
  Flag this specific number if he wants it justified/citation-backed too.

### 4.4 Recalibration

After 4.1–4.3 land, re-run `lstm_pipeline/src/rule_calibrator.py` against
freshly generated benign SUMO traces to refit `s1_delta0`, `s1_alpha_rho`,
`s1_alpha_v`, `s1_beta`, `s1_k`. Expect `R²` to move meaningfully above
0.0004 — if it doesn't, 4.1/4.2 haven't actually introduced a
mobility-correlated signal and the design needs revisiting before touching
anything downstream.

- Regenerate: `lstm_pipeline/calibration_report.txt`,
  `lstm_pipeline/calibrated_params.json`.

### 4.5 (Phase 3, optional — separate follow-up, not blocking)

Once 4.1–4.4 give delay data that is genuinely mobility-dependent, the
online histogram-based Bhattacharyya diagnostic discussed earlier (running
histograms of `δ_p` split by benign/attack label, updated in
`s1_detection.h`, emitted once per cycle into the existing per-cycle CSV
next to `obs_delay`) becomes a meaningful empirical readout of Mechanism 1
— `D_B` should shrink as `v̄` increases. Doing this before 4.1–4.4 would
just measure and report the flat/inverted signal that exists today, so it
is sequenced after, not before.

### 4.6 Generate the missing 100/140 km/h urban traces (RC4, prerequisite)

Before Experiment 2 can run at all four specified speed points, generate
`mobility_urban_100.tcl` and `mobility_urban_140.tcl` using the same
forced-uniform-speed SUMO procedure main.tex already specifies for the
existing points (`speedFactor=1.0`, `speedDev=0.0`, so the whole fleet
holds the target `v̄` rather than sampling around it — main.tex ~L5265
onward, Experiment 2 rationale). Concretely: reuse whatever SUMO
network/route config produced `mobility_urban_{0,...,60,150}.tcl`
(same road topology, same vehicle count), just re-run it with the SUMO
`--max-speed`/vType `maxSpeed` (and `speedFactor`/`speedDev`) set for
100 km/h and 140 km/h respectively, export the resulting `.tcl` via the
same `traceExporter`/`ns2mobility` step, and add the two new cases to the
`switch` in `scratch/routing.cc` (~L142235) alongside the existing eight.

- This is purely a missing-input-data fix — it does not touch RC1–RC3 or
  any C++ detection/attack logic, and can be done independently of (and
  before) §4.1–§4.5.
- Sanity-check the generated trace before using it for real runs: confirm
  mean vehicle speed in the `.tcl` file is actually ≈100/140 km/h (SUMO can
  silently cap effective speed below a vType's `maxSpeed` if road/junction
  speed limits or car-following constraints in the existing network are
  lower — worth a quick check given 140 km/h is a fast urban speed).
- Also add the equivalent `mobility_rural_100.tcl`/`mobility_autobahn_*`
  entries only if those road types are separately used by Experiment 2 for
  A1/A2 — confirm scope against `routing.cc`'s road-type selection logic
  before assuming urban-only is sufficient.

## 5. Implementation checklist

- [x] `scratch/handoff_tracker.h` — new file: per-vehicle nearest-RSU
      tracking + handoff-event detection (§4.1).
- [x] `scratch/s1_detection.h` — hook handoff events into the `δ_r(t)`
      accumulation as a transient jitter term (§4.2).
- [ ] `scratch/attack_variables.h` — add the three ±10% bands anchored on
      $1.1/2/4\times\Delta_{max}$ (55/100/200 ms), replacing the unused
      80 ms default (§4.3, resolved).
- [ ] `scratch/selective_time_delay.h` — replace deterministic
      `attack_delay_ms` with a seeded pseudo-random draw from the active
      intensity level's band; keep CLI override for deterministic testing
      (§4.3, resolved).
- [ ] Confirm ±10% band width with supervisor, or gather a citation/
      calibration basis for it if he wants one (§4.3 open sub-decision).
- [ ] Check `Timing_Attack` and `KALUPAHANALIYANAGE2018226` (already
      cited for the <100 ms end-to-end safety budget, main.tex L411/1469)
      for an explicit per-hop/processing-stage breakdown before deciding
      whether $\Delta_{max}=50$ ms gets a citation or a fresh calibration
      pass (§8, resolved — his call, either path acceptable).
- [ ] Generate `mobility_urban_100.tcl` and `mobility_urban_140.tcl`
      (and add the corresponding `--maxspeed` cases to
      `scratch/routing.cc`'s trace-file switch) — **blocking prerequisite
      for Experiment 2**, independent of §4.1–§4.5 (§3 RC4, §4.6).
- [ ] Re-run benign SUMO sweep to regenerate `lstm_training/*.csv` inputs
      for calibration.
- [ ] `lstm_pipeline/src/rule_calibrator.py` — re-run; regenerate
      `calibration_report.txt` / `calibrated_params.json` (§4.4).
- [ ] Re-run Experiment 2 (`scripts/run_std_attacks.py` or equivalent,
      A1/A2, `v̄ ∈ {10,60,100,140}` km/h).
- [ ] `lstm_pipeline/src/mobility_stratified_eval.py` — regenerate
      `mobility_stratified_results.json`.
- [ ] `scripts/plot_lstm_results.py` — regenerate
      `Figure_LSTM_MobilityStratifiedMCC.png`; visually confirm trend
      direction.
- [ ] `python3 scripts/audit_equations.py --strict` — confirm no
      regression (must still be 87/87 PASS+INFO, 0 FAIL).
- [ ] (Phase 3, optional) Online Bhattacharyya diagnostic (§4.5).

## 6. Acceptance criteria

- All four Experiment 2 speed points (`v̄ ∈ {10,60,100,140}` km/h) are
  actually runnable — `mobility_urban_100.tcl`/`mobility_urban_140.tcl`
  exist and produce a fleet whose realized mean speed matches the target
  (§3 RC4, §4.6). This is a precondition for the rest of this section,
  not a substitute for it.
- `rule_calibrator.py`'s refit `R²` is materially above 0.0004 (exact bar
  TBD with supervisor — even R² ≈ 0.05–0.1 would be a defensible order-of-
  magnitude improvement given DSRC overhead will still dominate somewhat).
- A1/A2 MCC (or FPR, whichever direction is more diagnostic) trends
  *worse* — not flat, not better — as `v̄` increases across all 4 speed
  points in `mobility_stratified_results.json`, at fixed `ρ` bin.
- `audit_equations.py --strict` still exits 0 (no equation regression).
- The direction and magnitude of the effect is explainable from 4.1–4.3's
  mechanism (handoff frequency × jitter window), not merely a parameter
  swept until the graph looked right (see §7).

## 7. Risks & mitigations

- **Risk: overfitting the result.** It would be easy to just widen the
  attack-delay range at high `v̄` by hand until the MCC-vs-speed graph
  slopes the "right" way, without the effect being mechanistically real.
  Mitigation: the jitter magnitude in §4.2 must be derived from handoff
  *frequency* (itself a function of `v̄` via zone residence time, already
  formalized in `eq:observation_window`), not hand-tuned per speed point;
  per §4.3 (supervisor-resolved), the attacker's band stays fixed at
  whichever intensity level is under test across all speed points, and
  only its *effective overlap* with the now-widening legitimate
  distribution should change.
- **Risk: R² still near-zero after the fix.** If DSRC MAC/crypto overhead
  genuinely dominates delay variance even with handoff jitter added, the
  linear baseline (`eq:mobility_baseline`) may need a nonlinear or
  event-indicator term instead of `α_v · v̄(t)^-1`. Flag to supervisor
  before spending calibration effort if 4.4 doesn't move R² at all.
- **Risk: touching `routing.cc`/`s1_detection.h` regresses existing
  calibrated thresholds** (`s1_k=3.0`, `s1_beta=0.7`, S3/S4 thresholds
  etc., which are independently calibrated and referenced by
  `audit_equations.py`'s structural-constants section). Mitigation:
  `audit_equations.py --strict` in the checklist (§5) is the regression
  gate; re-run it after every step, not just at the end.
- **Risk: this doesn't cover Mechanisms 2–4.** Explicitly out of scope
  here (§2) — needs its own audit + plan before Experiment 2's other
  attack variants (A3–A8) are trusted.
- **Risk: SUMO silently caps realized speed below the requested 100/140
  km/h target.** Urban road/junction speed limits or car-following
  constraints in the existing network config may prevent the fleet from
  actually reaching a 140 km/h mean, even with `speedFactor=1.0`/
  `speedDev=0.0` set. Mitigation: verify realized mean speed in the
  generated `.tcl` file before using it for real runs (§4.6); if capped,
  either widen the relevant road/junction speed limits in the SUMO
  network or flag to supervisor that 140 km/h may not be achievable
  under the current road topology.

## 8. Open questions for supervisor sign-off

Status legend: `[x]` resolved · `[ ]` still open.

- [x] **Randomized vs. independent-variable attack delay** — resolved
      2026-07-25. Supervisor: *"You can make it pseudo-random (you can
      control the randomness with defined bounds and behavior). Not
      totally random."* → locked design in §4.3: bounded pseudo-random
      bands anchored on the three existing $\Delta_{max}$ intensity
      levels, seeded for reproducibility. Band *width* (±10% default) is
      still our proposal, not yet explicitly confirmed — see §5.
- [x] **Whether $\Delta_{max}=50$ ms needs a citation or a calibration
      pass** — resolved 2026-07-25. Supervisor: *"You can calibrate or use
      a citation."* Either is acceptable; our call which to pursue. Next
      step: check whether the two papers already cited for the <100 ms
      end-to-end budget give a per-hop breakdown before doing a fresh
      calibration run (§5 checklist).
- [ ] Is a handoff-triggered transient jitter model (§4.2) an acceptable
      operationalization of Mechanism 1, or does the committee expect
      something closer to the literal `D_B` integral computed from
      measured distributions? — not yet raised with supervisor.
- [ ] What `R²` / effect-size bar counts as "amplification demonstrated"
      for examination purposes (§6)? — not yet raised.
- [ ] Should Mechanisms 2–4 be audited and fixed before or after the viva
      defense, given time constraints? — not yet raised.
- [ ] If the SUMO network's road/junction speed limits cap realized mean
      speed below 140 km/h under the current urban topology (§4.6, §7),
      is widening those limits acceptable, or should the 140 km/h point
      be substituted/dropped and flagged as a limitation? — not yet
      raised; depends on what §4.6's sanity check finds.
