# Supervisor questions — verified status, 2026-08-12

Answers below were obtained by reading the currently compiled code and the
CSVs already on disk (`S15_SIR`, up to date with its remote) — no new
simulation runs. Where a claim in the supervisor's message couldn't be
traced to anything in this repo, that's stated explicitly rather than
guessed at.

## 1. β — NOT updated to 0.95, and it's a real conflict, not neglect

`scratch/s1_detection.h:92` compiles `s1_beta = 0.8`.

`lstm_pipeline/src/rule_calibrator.py:105-116` has an explicit, dated
rationale attributed to "supervisor + project owner, 2026-08-08" for using
`N_eff ≤ 9` (the **minimum** RSU zone-residence bound only), which selects
β=0.8 (N_eff=5) and explicitly rejects β=0.95 as "more than double the
bound." This directly contradicts the derivation the supervisor sent
afterward, which used the full range `9 ≤ N_eff ≤ 22` and selected β=0.95
(N_eff=20).

Same criterion name (`N_eff = 1/(1-β)`), same date, opposite number. This
needs to be resolved as a genuine conflict between two dated decisions, not
reported as "still pending."

**Why 0.8 was picked** (from `rule_calibrator.py`'s `sweep_beta()`,
introduced in this same commit, `3a14fb7`): the 9s figure was treated as a
**worst-case SLA**, not the lower end of a range. Reasoning in the code —
"largest β within budget... maximises smoothing while still guaranteeing
full adaptation within the *shortest* zone crossing (the conservative
choice)." Vehicles' zone residence ranges 9-22s; if β is picked so
N_eff=20 (β=0.95), a *fast-crossing* vehicle that only stays 9s leaves
before the EWMA ever stabilizes for it. Requiring N_eff≤9 guarantees
stabilization for every vehicle, even the fastest-crossing one — a
defensible worst-case reading of "must form a stable estimate within one
RSU zone crossing."

This is a genuinely different (not careless) interpretation from the
supervisor's later message, which treats 9-22s as a band to select
anywhere within and picks β=0.95 to use "the full available zone window."
Both readings are reasonable in isolation; they just land on opposite ends
of the candidate set. Worth relaying this reasoning verbatim when
escalating, since it shows the 0.8 choice was deliberate engineering
judgment, not an oversight.

**Empirical check (2026-08-13)**: ran A1 and A2 head-to-head, β=0.8 vs
β=0.95, identical config otherwise (40s, 60% attack, seed1, current build).
β=0.95 wins on every metric that moved, both attacks:

| Attack | β | cur_MCC | avg_MCC | cur_FPR | avg_FPR | FP | TN | DR |
|---|---|---|---|---|---|---|---|---|
| A1 | 0.8 | 0.6088 | 0.6163 | 11.741% | 5.987% | 29 | 218 | 100% |
| A1 | **0.95** | **0.6164** | **0.6174** | **11.336%** | **5.934%** | **28** | **219** | 100% |
| A2 | 0.8 | 0.7980 | 0.8777 | 21.277% | 10.839% | 30 | 111 | 100% |
| A2 | **0.95** | **0.8166** | **0.8847** | **19.149%** | **10.110%** | **27** | **114** | 100% |

Higher MCC and lower FPR under β=0.95 for both attacks; detection rate
unchanged at 100% either way, so no recall tradeoff. Caveat: single seed,
single 40s run, not a validated sweep — but the direction is consistent
across both attacks and every metric that differs, which is a real signal
worth attaching to the escalation, not just the two competing derivations.

## 2. zkp_delay_fail fraction — fix confirmed live on current data

Measured across all files currently on disk (64/64 RSUs each, 1152 files /
135,936 rows per attack):

| Attack | RSUs with zkp_delay_fail=1 (of 64) | Fraction of rows =1 |
|---|---|---|
| A1 | 0 | 0.0% |
| A2 | 49 | 10.72% |

A1=0% is expected (control-plane delay isn't zkp-gated). A2 being nonzero
and varying across 49 RSUs confirms the fix is feeding real, non-constant
feature data — not a stale pre-fix CSV. (Supervisor's earlier diagnostic
cited 37/64 for A2; 49/64 now is consistent with more data collected since
then, not a discrepancy.)

## 3. k value — k=3.0, but as a fallback, not a pass

Swept via `rule_calibrator.py:337-410` on a genuine held-out validation
split (last 30% of cycles, held out from EWMA warm-up). **None of
{1, 2, 3} achieved FPR ≤ 1%** on the real benign data — k=3.0 measured
FPR=0.0287. k=3 was selected as the fallback ("most conservative option
when all candidates fail"), not because it cleared the target. Report this
distinction explicitly — "swept and selected" implies it passed, which it
didn't.

## 4. A3/A4 in the LSTM-only table (MCC=0.893 overall, A3=0.872) — FOUND (2026-08-12 update)

Located: `lstm_pipeline/evaluation_results.json`, committed in `2f82589`
("fix: updated LSTM weights and diagrams", 2026-08-09). Produced by
`evaluator.py`'s `predict_test()` on the real held-out **seed5 TEST split**
(`test_X/y/meta.npy`, 65,856 windows, 51.2% positive), deduplicated per
`eq:eval_dedup` — `deduplicate_windows()` groups by
`(rsu, attack_v, pct, seed, non-overlapping 10s block)`, matching spec.

Numbers are close but not exact to what the supervisor cited:
`Overall (LSTM: attacks 1,2,5-8)` M1_MCC=**0.881** vs their 0.893; A3's
`lstm_clf_reference_only` M1_MCC=**0.8733** vs their 0.872. Same structure,
same methodology, likely a slightly different re-run or rounding — treat as
the same table until told otherwise.

**Answers the A3/A4 gating clarification directly**: A3's headline
M1_MCC=0.9051 in this file is tagged `"source": "rule_based_S3_S4"` — the
gated production number (LSTM suppressed per `eq:lstm_gate`, as designed).
The 0.8733 figure is a separate, explicitly-labeled `"lstm_clf_reference_only"`
key — an ungated diagnostic, already labeled exactly as the supervisor asked
("fine as a diagnostic number, just label it clearly"). It was never relayed
back to them, that's the only gap.

**Still open**: this table has never been written into `main.tex` (zero
hits, checked). It's also the LSTM component alone, not the full-system Q6
table (rule + LSTM + witness + crypto combined) — matches the supervisor's
own phrasing ("MCC=0.893 on the **LSTM-only component**"), so it does not
by itself satisfy blocker 4 below (Q6 with the retrained model + corrected
eval unit), only clarifies what this specific number is.

## Four outstanding blockers — verified state

- **Q1 with TP+FN for A1/A2**: Q1 was run (`bf8e0fa`, 2026-08-08) but
  **before** the `t_claimed_packet` stale-claim fix (`ad1438d`,
  2026-08-09 12:47) landed. No Q1 output on disk postdates that fix.
  Needs a fresh run to actually answer the supervisor's question.
- **`eq:dup_alert_cond` content-hash fix**: **Not done.**
  `scratch/crypto_layer.h:1560` and `:1649` still build
  `event_key = (flow_id << 32) | pkt_id` — the same packet-id-recycling
  construction as the `t_claimed_packet` bug that was just fixed elsewhere
  in S1/S2 (`ad1438d`). Same bug class, different call site. A7's
  routing-churn FPR is still live because of it.
- **Q6 block count + macro-MCC under the corrected eval unit**: not
  reported anywhere on disk.
- **Cumulative Q1–Q6 MCC table**: not produced.

## What's next

1. Escalate the β conflict to the supervisor — need one authoritative
   answer (β=0.8 via N_eff≤9, or β=0.95 via 9≤N_eff≤22) before touching
   S1 code or re-running anything that depends on it.
2. Locate the Q3/LSTM-only table (MCC=0.893, A3=0.872) — can't validate or
   build on numbers that don't exist in this repo.
3. Fix `eq:dup_alert_cond`'s `event_key` the same way `t_claimed_packet`
   was fixed (content-based hash over stable identity fields, not a
   recycling packet-id/flow pair).
4. Re-run Q1 (30s, 60%) with the current build; report TP+FN for A1/A2.
5. Confirm/produce the Q6 per-10s-block confusion matrix (`eq:eval_dedup`),
   report block count (expected 1728/variant) and macro-MCC.
6. Once 1-5 are closed, produce the cumulative Q1–Q6 MCC table and send it
   as the go/no-go gate.
