# Parameters still uncalibrated — full inventory (2026-09-01)

Compiled by cross-checking main.tex's `[tbd]` markers against the built
binary's `--PrintHelp` and the source defaults. **Every one is CLI-settable** —
none needs a code edit or rebuild to sweep.

## A. Marked `[tbd]` in main.tex

main.tex carries four `[tbd]` markers covering eight parameters. All are given
candidate sets or selection criteria by the paper itself, so calibrating them is
executing the paper's own stated plan, not inventing methodology.

| parameter | main.tex says | CLI flag | current default |
|---|---|---|---|
| $T_{min}$ vehicle/RSU quarantine threshold | `[tbd: {0.3, 0.5, 0.7}]` | `--trust_t_min` | 0.50 |
| $\Delta_r$ trust reward | `[tbd]`, $\Delta_p > \Delta_r$ enforced | `--trust_delta_r` | 0.05 |
| $\Delta_p$ trust penalty | `[tbd]`, same constraint | `--trust_delta_p` | 0.10 |
| $T_{min}^{ctrl}$ controller trust threshold | `[tbd: {0.3, 0.5, 0.7}]`, swept independently of $T_{min}$ | `--trust_t_min_ctrl` | 0.50 |
| $\Delta_r^{ctrl}$ controller reward | `[tbd]` | `--trust_delta_r_ctrl` | 0.05 |
| $\Delta_p^{ctrl}$ controller penalty | `[tbd]`, $\Delta_p^{ctrl} > \Delta_r^{ctrl}$ | `--trust_delta_p_ctrl` | 0.10 |
| $f$ Byzantine witness fault parameter | `[tbd: {1, 2, 3}]`; $f{=}1$ expected at mean density | `--witness_f` | 1 |
| $W$ witness observation window | `[tbd: {5, 10, 15}}` s; "$\leq 9$ s zone residence bound" | `--witness_window` | 10.0 |
| $T_{sync}$ time-reference commit interval | `[tbd: {0.5, 1.0, 2.0}}` s; co-swept with block interval | `--t_sync` | 1.0 |

**Selection criteria the paper already specifies** (so these are not open
questions, just unrun sweeps):

- $\Delta_r$/$\Delta_p$: "selected for minimum false quarantine rate and maximum
  attack detection speed on the validation split"
- $\Delta_r^{ctrl}$/$\Delta_p^{ctrl}$: "minimum time-to-revocation of a
  compromised controller while minimising false [revocation]"
- $T_{min}^{ctrl}$: "lowest false controller revocation rate"
- $T_{sync}$: "co-swept with block interval to assess joint impact on $L_{e2e}$"

### ⚠ A possible inconsistency in the paper's own $W$ row

The candidate set is $\{5, 10, 15\}$ s but the same row states a
"$\leq 9$ s zone residence bound". Two of the three candidates (10, 15) exceed
that bound, and **the current default of 10.0 is one of them**. Either the bound
constrains $W$ — in which case only $W=5$ is admissible and the default is
invalid — or it is context for interpreting longer windows. Worth resolving with
the supervisor before the witness sweep, since it may collapse the grid to a
single point.

## B. Uncalibrated but not marked `[tbd]`

| parameter | status | CLI flag | current default |
|---|---|---|---|
| $T_{hold}$ (eq:local_quarantine) | **not in the [tbd] table at all** — symbol table (main.tex:1274) defines it only in prose; no number anywhere | `--T_hold` | 0.1 s |
| $\beta$ S1 EWMA forgetting factor | main.tex:6049 gives an $N_{eff}$ band ($9 \leq N_{eff} \leq 22$); 0.95 chosen analytically ($N_{eff}=20$, supervisor 2026-08-13) | `--s1_beta` | 0.95 |
| `Z_ALPHA` LSTM threshold multiplier | Python-side (`fed_aggregator.py`); not a main.tex symbol | — (Python) | 3.5 |

$T_{hold}$ is being calibrated now — see `scripts/sweep_t_hold.py` and the
criterion in `crypto_layer.h`'s `T_HOLD` declaration. $\beta$ is arguably already
justified analytically rather than uncalibrated.

## C. Two defects found while compiling this inventory

**1. Duplicate `AddValue` registrations.** `trust_t_min`, `trust_delta_p` and
`trust_delta_r` are each registered **twice**:

| flag | site 1 | site 2 |
|---|---|---|
| `trust_t_min` | `crypto_layer.h:2116` | `routing.cc:142492` |
| `trust_delta_p` | `crypto_layer.h:2115` | `routing.cc:142493` |
| `trust_delta_r` | `crypto_layer.h:2114` | `routing.cc:142494` |

Commit `c42fe3e` added the `routing.cc` set without noticing `crypto_layer.h`
already had them. **Impact is low but non-zero**: both registrations bind the
*same* underlying variables (`TRUST_T_MIN` etc.), so the parsed value lands
correctly either way and no run is wrong because of this. But each appears twice
in `--PrintHelp` with different descriptions, which is confusing when reading off
defaults, and relying on ns-3 tolerating duplicate option names is fragile.
Recommend deleting the `crypto_layer.h` trio, keeping the `routing.cc` ones,
which carry the better `[tbd]`-citing help text.

**2. Stale `--s1_beta` help text.** The help string says "default 0.9" but the
actual default is **0.95** (`s1_detection.h:126`). The *value* is correct and
deliberate — 0.95 gives the analytic $N_{eff}=20$ the supervisor endorsed on
2026-08-13 — so this is a documentation bug, not a behavioural one. Anyone
reading defaults off `--PrintHelp` gets the wrong number.

## D. Suggested order

1. **$T_{hold}$** — in progress; criterion is unambiguous and it gates the
   vehicle-side quarantine validation
2. **$T_{min}$, $\Delta_r$, $\Delta_p$** — these directly drive quarantine
   timing, so they must be settled before M4 (eq:l_mit) is reported at all
3. **$f$, $W$** — resolve the $\leq 9$ s ambiguity first; the grid may collapse
4. **$T_{sync}$** — co-swept with block interval per the paper, lowest priority
   since it affects $L_{e2e}$ rather than detection
5. **Controller trio** ($T_{min}^{ctrl}$, $\Delta_r^{ctrl}$, $\Delta_p^{ctrl}$) —
   independent of the above by the paper's own instruction
