# AB4 / AB8 / AB11 / AB13 investigation — 2026-10-08 (all runs 180 s, seed 1, Gurobi path, new endorsement)

Nothing below was tuned to widen a gap: attacks and substitutes are as planned; I only corrected substitutes that did not
match the plan. Each batch was preceded by a 10 s debug run of the exact configuration.

## AB4 — STARK timing proof (substitute implemented wrongly before; now fixed)
- **Problem found.** The old substitute (`enable_stark_delay=0`) made the timing check *vacuously pass*. The plan says
  "direct wall clock comparison", i.e. the same accept/reject decision without a proof. The old result (S2 "collapses") was
  an artefact of removing the check, not of removing the proof.
- **Fix.** `--ab4_direct_compare=1`: plain comparison of the raw timestamps against the bound (identical decision, no
  commitment hash), and every check exposes one raw (t_recv, t_fwd) pair to the verifier (counter `m10_raw_ts_exposed`).
- **Result (A2, p=20..100).** M1 identical in every run (0.876–0.992 vs the same) as expected. M10 privacy cost: ZK proof
  exposes **0** raw timestamps, direct comparison **20,150–24,307**. M7 verification overhead: ZK **6.6–7.0e-5 ms/proof** vs
  direct **2.5–2.7e-5 ms** (the proof costs about 2.7x the plain comparison). So the proof buys privacy at a small compute cost.
  Caveat: the simulator's pi_delay is a modelled proof (SHA3-512 commitment + bound check), so M7 is that modelled cost.

## AB8 — f+1 endorsement quorum (rerun after the independent-endorsement fix)
- Substitute changed to match the plan ("single roadside unit, immediate commitment"): `--ab8_single_rsu=1` = commit quorum
  of 1 (the old flag skipped the quorum entirely).
- Each RSU checks the FlowMod against the authorised policy; f=21 Byzantine RSUs endorse everything.
- **M11 (unauthorized commit rate), A1 and A3, p=20..100: 0% with the f+1=22 quorum, 100% with quorum 1** (20/20 points).
  With 0 Byzantine RSUs even quorum 1 blocks everything (debug run), so the quorum's value is tolerance of Byzantine endorsers.
- M1 reference is NOT flat for A3 (0.61 vs 0.94 at p=40): the unblocked FlowMods mean the compromised controller is never
  penalised or revoked (same mechanism as AB9/AB12), so the attack persists. M1 here is confounded by mitigation.

## AB11 — key rotation on revocation (not null: the earlier "neutral" came from not measuring the property)
- **Problem found.** The earlier analysis measured detection MCC and DR on revoked RSUs, which cannot show a key-reuse effect.
- **Fix/probe.** `--ab11_reuse_probe=1`: each cycle every revoked RSU replays a proof under its pre-revocation key; accepted
  iff rotation did not retire the key. Recorded by whole cycles since revocation.
- **Result (A1–A4, p=40 and 100, all 8 runs per arm).** With rotation **0%** of replayed proofs are accepted at every step
  (0 of 228 at each of steps 0–4; 0 of 34,109 at 5+). Without rotation **100%** are accepted at every step (228/228 ... 33,677/33,677).
  M11 is 0% in both arms (within the BFT bound the quorum still holds), M1 differs by <= 0.01.

## AB13 — mobility-adjusted threshold (checked 55 ms and speed extremes)
- The static-threshold flag works (a 1.0 s threshold silences S1 entirely, MCC 0), so identical results are not a bug.
- Static threshold = 22.9 ms (median adaptive threshold of a benign 60 km/h run). Benign adaptive-threshold distribution
  (median / p5 / p95): 10 km/h 16.7 / 11.2 / 24.8 ms; 60 km/h 22.9 / 12.3 / 36.2; 140 km/h 23.9 / 12.3 / 36.9. It does move with speed.
- 12 conditions (speed 10/60/100/140 x delay 55/100/200 ms, A1, p=40), enforcement off and on: M1 equal to within 0.007 in
  all 24 pairs (e.g. 10 km/h, 55 ms: 0.695 vs 0.695); TVR identical to 3 decimals; static FPR 0.1–0.4 points lower.
- **Why.** Every planned attack delay (>= 55 ms = 1.1 x Delta_max) is 1.5–3x above even the 95th-percentile adaptive threshold,
  and benign jitter rarely crosses either threshold, so the decisions do not change. TVR (share of critical packets above
  Delta_max) is detector-independent unless mitigation changes the delay, which it does not here.
- **Not done (needs your decision):** a sub-Delta_max sensitivity point (e.g. 25–40 ms at 10 km/h) would sit where the two
  thresholds differ, but that is a new attack intensity, not the planned one, so I did not run it.

## AB1 (for reference; reran at 180 s)
M6 and M4 are unchanged without the OBU pre-filter (26 ms and 30–52 s either way); M1 falls (0.634 -> 0.407 at p=20,
0.864 -> 0.333 at p=100). In this simulator the pre-filter serves detection, not latency.

## Other 180 s reruns
AB7: M6 26–27 ms (quarantine) vs 42–93 ms (detection only), M4 unbounded without quarantine. AB9: failover 12 ms vs undefined;
M1 0.621 vs 0.784 at p=40 (higher without isolation). AB10: forged proofs accepted 31–47% at p=40, 100% at p=100; S1/S2 M1 not
lower. AB12: M11 0% vs 100%.
