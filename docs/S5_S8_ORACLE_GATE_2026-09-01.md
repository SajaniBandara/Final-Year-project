# S5–S8 are oracle-gated — found while confirming the FPR root-cause analysis

## The finding

All four Hidden-Forwarding signatures early-return unless the accused node is
already flagged in the attacker-assignment array:

| detector | line | gate |
|---|---|---|
| S5 | `s5_detection.h:127` | `if (!active_hf_malicious_nodes[prev_sender]) return false;` |
| S6 | `s6_detection.h:151` | `if (!active_hf_malicious_nodes[prev_sender]) return false;` |
| S7 | `s7_detection.h:126` | `if (!passive_hf_malicious_nodes[prev_sender]) return false;` |
| S8 | `s8_detection.h:96`  | `if (!passive_hf_malicious_nodes[prev_sender]) return false;` |

Those arrays are **ground truth**: `active_hf_malicious_nodes[mal_node] = true`
is written by the attack injector (`hf_attack_helper.h:642`).

## main.tex does not specify this conjunction

`eq:sig_s5` has five conjunctions, all observable:

```
S5:  d' ∉ P(s,d)
   ∧ FlowMod(r) installed (s → d')
   ∧ ML-DSA-87.Verify(σ_copy, pk_s, m_copy) = 0
   ∧ BatchVerify(σ, {pk_i}, {m_i}, r) = 0
   ∧ b_hop(u) = 0
```

**"prev_sender is a known malicious RSU" is not among them.** The paper's S5 is
built entirely from signature failures, hop-proof failures and FlowMod
endorsement state. The implementation adds a sixth, non-observable conjunction.

`s5_detection.h` shows the authors were alert to this class of problem — line
146 defends conjunction 3 as "a cryptographic failure, **not a restated
ground-truth boolean**". Conjunction 2 *is* a restated ground-truth boolean and
was left in place.

## Why it matters

**S5–S8 cannot produce a false accusation, by construction.** Their precision is
not a measurement; it is an identity. Concretely:

- the observation that "S5–S8 never accuse an innocent RSU — structurally
  impossible" is **correct, but not evidence of detector quality**. They are
  told who the attackers are.
- every FPR / precision figure for S5–S8 is **vacuous**. Measured on arm A,
  100% of A5/A6/A8 `score_primary` false positives are dormant *declared*
  attackers and 0 are non-attackers (A7: 95.1% / 4.9%) — that is the gate
  showing through, not precision.
- **DR remains meaningful**: given the attacker set, does the signature fire?
  That is a real question and the DR numbers answer it.
- `score_primary` is therefore worse than "variant-aware": it is
  **attacker-identity-aware**. It is not a deployable configuration and not an
  achievable ceiling. Any headroom quoted from it (e.g. the M1 0.687 at M=3)
  is an upper bound on a system that cannot be built as-is.

## What this does *not* invalidate

- The **d_div / a_tp broadcast defect** is independent and stands (global
  accumulators, 100% cross-RSU agreement, AUC 0.500 within stratum).
- The **persistence-M result** stands: it operates on firing *density*, and the
  dormant-vs-active separation (median `score_primary_cycles` 2–3 vs 4–6) is
  real regardless of how the candidate set was gated.
- The **observer-vs-suspect attribution defect** (`lrad.h:465` marks `rsu`,
  `lrad.h:550` marks `prev_sender`) is independent and stands.
- **A1–A4** do not use these arrays; S1/S2/S3/S4 are unaffected.

## Recommended action

1. Decide whether the gate is a deliberate modelling assumption ("the RSU has
   already been identified as compromised by an out-of-band mechanism") or an
   implementation shortcut. If the former it must be stated in the paper,
   because it changes what S5–S8 claim to do.
2. Until then, **do not report S5–S8 FPR or precision** as detector properties,
   and do not present `score_primary` as an achievable ceiling.
3. The honest experiment is to remove conjunction 2 and re-measure. That gives
   the first real FPR for the HF signatures — and, given the paper's five
   observable conjunctions are all crypto/endorsement failures, it may hold up
   well.

## Provenance

Found 2026-09-01 while verifying the `d_div`/`a_tp` root-cause analysis. That
analysis's claims were independently reproduced and all confirmed:
`truth_declared` FP composition (A5 420/420, A6 312/312, A7 392/412, A8
298/298), the 39–49% non-attacker share of `score` FPs (measured 39.3–48.9%),
`score_primary_cycles` medians (dormant 2–3, active 4–6), and the M caution
(mean A5–A8 MCC peaks 0.6971 at M=3, falls to 0.6220 at M=5, below M=1's
0.6252).
