# Item 11 / P1 — A8 rise-and-fall recheck (2026-08-31)

Task: `docs/HPC_TASKS_2026-08-31.md` §3 P1.

**Config.** A8 @60%, 300 s, seeds 1–5, two arms
(`--enable_quarantine_enforcement` 0 and 1), 200 veh / 64 RSU / 4 ctrl,
architecture 3, SUMO mobility. Driver: `scripts/item11_a8_rise_fall.py`
(arms separated by `--run_tag=i11off<S>` / `i11on<S>`).
All 10 runs rc=0; §6 error gate (`Solution not found|Unexpected error in
link lifetime`) = **0 on every log**; 298 cycles each.

Binary was **rebuilt first** — the on-disk binary predated `6cb1189`, the commit
that added the enforcement flag, so both arms would otherwise have been
identical and silently meaningless.

## Result 1 — the published shape reproduces, and quarantine is not the cause

Mean `cur_UCR` across 5 seeds, enforcement **OFF** (no enforcement path exists
in this arm at all):

| t (s) | 9 | 10 | 11 | 13 | 15 | 17 | 19 | ≥25 |
|---|---|---|---|---|---|---|---|---|
| UCR % | 0.0 | **96.0** | 46.2 | 24.3 | 14.7 | 8.8 | 3.3 | ~0 |

The rise-and-fall is real and reproduces exactly. Since this arm has no
enforcement, **quarantine cannot be what drives the decline.** The stated
mechanism in the paper is wrong, as suspected.

The ON arm is statistically indistinguishable (96.0 / 46.2 / 22.9 / 18.7 …),
confirming enforcement contributes nothing to the *shape*.

## Result 2 — the actual mechanism is dedup-counter saturation

`calculate_ucr_metric()` (routing.cc:117766) sets the numerator to
`fade_eavesdrop_counter - g_ucr_prev_eavesdrop` — *newly distinct*
`(flow, packet_ID)` pairs. The dedup set `fade_eavesdropped_packets`
(efade_detection.h:120) is cleared **once per run** (routing.cc:115630), not
per cycle. The denominator `total_sent` is flat (~10–16) all run.

Only ~30 distinct `(flow, packet_ID)` pairs exist in an entire 300 s run.
Seed 1, OFF arm — hidden-duplicate sends vs. newly distinct pairs:

| t (s) | 0–20 | 20–40 | 40–60 | 60–80 | … | 280–300 |
|---|---|---|---|---|---|---|
| sends | 391 | 723 | 747 | 813 | … | 564 |
| NEW pairs | 27 | 2 | 1 | **0** | … | **0** |

The attack never declines — it is *stronger* after UCR reads 0% than during the
peak. The pair space is exhausted by t≈40, after which the counter delta is
permanently 0. **The decline is a measurement artifact, not a security
outcome.** Across 5 seeds, OFF arm: mean **8,695 hidden-duplicate sends occur
after t=50 s**, i.e. entirely inside the region where UCR reads 0%.

## Result 3 — enforcement blocks *scheduling*, not interception

Two different events must be separated, and conflating them overstates the fix.

**(a) Intentional hidden-duplicate sends** (`send_hidden_duplicate`), per run:

| seed | OFF | ON | reduction |
|---|---|---|---|
| 1 | 9,818 | 122 | 98.8% |
| 2 | 9,963 | 56 | 99.4% |
| 3 | 11,973 | 56 | 99.5% |
| 4 | 9,630 | 104 | 98.9% |
| 5 | 8,365 | 107 | 98.7% |
| **mean** | **9,950** | **89** | **99.1%** |

Enforcement does what it claims on the scheduling path. Intentional sends after
t=50 s fall from 8,695 to 6.

**(b) Packets actually received at an eavesdropper**, which is what increments
`fade_eavesdrop_counter` (routing.cc:122087), per run:

| | OFF | ON | reduction |
|---|---|---|---|
| eavesdropper receives | 168,097 | 127,203 | **24.3%** |
| receives after t=50 s | 149,799 | 112,271 | 25.1% |
| distinct (flow,pkt) pairs | 31.8 | 31.6 | — |

The receive-side guard (routing.cc:122085) counts **any** packet arriving at an
eavesdropper whose `previous_senderId` is a malicious RSU — it does not require
the packet to be an intentionally scheduled duplicate. So ordinary relay traffic
through a malicious RSU is counted as successful eavesdropping.

The ratio makes this unambiguous: receives-per-intentional-send is **17:1** in
the OFF arm but **1,011:1** in the ON arm. With intentional duplication almost
entirely suppressed, 127k interceptions still occur. **Enforcement stops the
duplication, but the eavesdropper keeps receiving, because quarantined RSUs are
still permitted to forward legitimate traffic.**

This is exactly open question §2.3 ("should legitimate forwarding by a
quarantined RSU also be blocked?"), and these numbers answer its cost side:
blocking scheduling alone removes only ~24% of interception.

**Cost of enforcement** (final-cycle run averages, 5 seeds):

| metric | OFF | ON | delta |
|---|---|---|---|
| avg_PDR | 29.55 ± 2.36 | 26.10 ± 2.03 | **−3.46** |
| avg_lat_ms | 24.77 ± 1.75 | 20.91 ± 1.68 | −3.86 |
| avg_UCR | 0.865 ± 0.007 | 0.857 ± 0.013 | −0.009 |
| avg_TVR | 0.000 | 0.000 | 0.000 |

Enforcement costs ~3.5 points of PDR and returns ~3.9 ms of latency.
`avg_TVR` is **identically zero in all 10 runs** — the other half of the
paper's impact pair never fires for A8 at all, and should not be presented as
an A8 result.

## Implications for the paper

1. The A8 UCR curve caption must stop attributing the decline to quarantine.
   The decline is counter saturation over a ~30-pair ID space.
2. Real mitigation evidence should use **hidden-duplicate send volume**
   (99.1% reduction, 5 seeds), not UCR.
3. Either redefine UCR against a per-cycle denominator/window, or retire it as
   a temporal curve and report it only as a peak-onset figure.

## Not done / open

- Not investigated: whether the ~30-pair ID space is itself intended
  (`packet_ID` recycling) or a separate defect. This changes whether UCR is
  fixable by redefinition or needs the ID space widened first.
- Per §2, no latched-label or per-variant-θ work touched here.
