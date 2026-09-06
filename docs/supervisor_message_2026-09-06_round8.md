# Supervisor message — round 8 (received 2026-09-06)

> Verbatim. Responses and status tracked in
> `docs/ROUND8_TRIAGE_2026-09-06.md`.
>
> **Note on crossover:** this message replies to
> `DRAFT_SUPERVISOR_REPLY_2026-09-05.md`. It crossed with
> `SUPERVISOR_UPDATE_2026-09-05.md`, which already reports measured results for
> several items requested here (notably item 1's A/B runs and item 4's outcome).

---

Hi team, long one, this covers every open item from your last report. Going through it in the same order you raised things.

**Item 1, enforcement.** Confirm A2, A6, A8 don't share A4's specific defect, a guard that exists but never gets triggered because nothing decrements trust, before assuming the fix generalizes cleanly. A1 is approved into scope, same construction as A3 since its attacker is always the RSU holding the poisoned FlowMod. Run the validation A/B for A4 and for A1/A2 once guarded, same protocol you used for A3.

**Item 2, UCR.** Approved as done. The withdrawal on the LRAD check was the right call, that's a genuine modeling choice, not a bug, since the paper's own algorithm annotation already says threshold only, no ZKP for exactly this reason. Add one sentence to the paper stating flag_S2p reduces to its threshold term in practice, so S2 partial is never described as doing integrity verification it doesn't do. Write up A5 through A7 against the corrected metric the same way you already did for A8.

**Item 3, the feature fix, and the D_div question specifically.** Approved, and I'm approving the richer version, not the simple one, for the reason above: retraining cost is fixed either way, so there's no reason to settle for a feature that collapses into being fully derived from another one you already have.

Concrete definition. Generalize destination set tracking from the current hardcoded single flow global to a per RSU, per source vehicle accumulator, populated at the same three MacRx sites, attributed through hf_gt_attribution_node() exactly as now. The new per RSU feature becomes a count, not a set size: how many distinct source vehicles currently routing through this RSU have a destination set cardinality exceeding their authorized policy count. In plain terms, how many separate attacking flows are showing an unauthorized destination signature at this RSU right now, rather than whether a single flow is. One thing I need confirmed before you build against it, does the simulation already model multiple concurrent attacking source vehicles routing through a shared RSU at the percentages you're testing. I'd expect yes given the attacker allocation counts already in the simulation settings, but I don't have visibility into the flow model myself and don't want you building on an assumption I haven't verified.

Before the full 60 run regeneration, run one short validation pass, same style as the r_anom equals zero benign check you already did. Confirm three things on a thirty to sixty second sample. The feature is genuinely non-constant across the 64 RSUs during an active attack, not another silent collapse. It sits at exactly zero under benign traffic. Its correlation with r_anom is meaningfully below one, so it's carrying independent information rather than being derivable from r_anom the way the simple version was. If all three hold, go straight into the regeneration and retrain already planned. If it degenerates in a way you didn't expect, don't spend another round iterating on the definition, fall back immediately to the straightforward per RSU fix I approved earlier, characterize D_div honestly in the paper as a corroborating indicator, and move on. We are not doing a third pass on this one feature given where we are on time.

For A_tp, Q4 is approved as option two. Promote the existing forwarded and received count trackers to RSU keyed quantities using the same attribution pattern, this matches the paper's own wording directly and reuses machinery you've already proven correct.

Either way this becomes a real correction to the paper's D_div equation, written out properly with the new formula and its relationship to the original spec explained, not a footnote.

**Q5, the oracle gate.** This has to come out, bundle it into the same regeneration pass as item 3.

I want to be direct about why this matters more than anything else in the report. The gate makes four of your rule based detectors structurally incapable of ever firing on an innocent node, because they refuse to evaluate at all unless the simulation's own answer key already confirms the sender is a true attacker. Every precision number reported for these four detectors this entire session has been guaranteed by construction, not measured. This is the exact same category of problem as using r_anom as its own training label, or banning delta_t_exceeded as an input feature because a trivial rule could reconstruct the label from it, we just found it this late because it was hiding in C++ control flow instead of a training script. The paper's own conjuncts for this detector make no reference to an oracle, they're supposed to be independently verifiable cryptographic and behavioral evidence, which is the entire premise of a zero trust design.

Remove it. Rerun all four affected variants live, in the same pass as the item 3 regeneration since both need fresh runs anyway. Two honest possibilities once it's out, the four conjuncts might be strong enough on their own that the numbers barely move, or something else was hiding behind the gate and they drop hard. Either answer is real information we need. A number that's known to be an artifact of a bypass shortcut isn't publishable regardless of how good it looks, there's no version of this where leaving it in is the right call even under time pressure.

**Item 4, the latch.** Approved as built, including the fix for the shared covering RSU over release case you caught before it shipped, good instinct.

**Q1, the covering RSU proxy for the two data plane hidden forwarding variants.** Approved as is, don't build individual vehicle trust paths to match A4's construction. The over block denies service to innocent vehicles sharing a flagged RSU, but it doesn't corrupt the detection measurement itself, since the attacker's own containment is what's being scored. This is a defensible conservative posture for a safety critical network, not just a shortcut, add one sentence to the limitations section stating it plainly with individual vehicle trust paths as future work.

**Item 5, M4.** Approved as designed, unblocks once item 1 closes.

**Q6, the metric numbering conflict.** The paper is canonical. Conform every script to it, and if a mismatch turns out to be a genuine error in the paper text rather than a naming difference, flag that back to me specifically instead of silently picking a side.

**Q7, the missing canonical scoring script.** Bless the reimplementation formally, commit it to version control today so this exact situation can't recur. Retire the old historical figure explicitly as a number from an unrecoverable script, not comparable to anything computed since.

**Q8, UCR's predicate and window.** Accept the current implementation, document rather than change the code. One quick check first, confirm that in this simulation a duplicate always arrives within a short bounded time of the original, well under any window value under discussion. If that holds, the whole run versus windowed distinction is moot in practice and a documentation note closes it.

**Q9, the window parameter contradicting the stated residence bound.** Reword the paper rather than run a new sweep. Change the framing from a hard bound the default then violates to a value informed by that range, chosen near the lower end to maximize evidence collection while staying responsive within a typical crossing. Tell me if you'd rather see the actual sweep run instead, I can reverse this.

**Q10, the M4 default.** Flip it to the corrected behavior by default immediately, there's no scenario where the inverted version is the right silent default.

**Q11, OBU rows.** Don't blend OBU and RSU rows into one pooled number. Report the OBU stage detector as its own explicit table, separate from the RSU level headline metric, and say so plainly in the paper. This gives that detector credit for real, already validated work without inventing a new aggregation scheme that would raise its own questions.

**Two items from your missing list that need action.**

The confidence multiplier is broken for a structural reason, a bounded probability can't be meaningfully compared against twice a threshold that's already near its ceiling. Don't patch it with an offset either, that still ties its behavior to the other threshold's scale. Recalibrate it the same way the main threshold is now built, a percentile cut on the validation split, just targeting a stricter operating point.

The recall decay on the two timing delay variants needs a specific breakdown before anyone touches code. Break true positives into time buckets across the run and for each bucket report both how many genuine events existed as ground truth and how many were caught. If genuine events themselves taper off later in the run, that's the same dormant window pattern already documented elsewhere and gets the same limitation treatment. If genuine events stay steady but are increasingly missed, that's real degradation and needs its own trace. Send the breakdown before proposing anything.

**Reporting convention.** Approved as you proposed it, with everything above folded in. Macro of per variant scores as the headline, pooled shown alongside for transparency. The correctly attributed score column, latched truth, persistence remeasured after the latch rather than assumed to still stack. Runs at three hundred seconds or longer, length always stated. The attacker identity aware column shown separately, clearly labeled as a diagnostic ceiling, never presented as an achievable deployment number.

**Sequencing.** Run the D_div validation smoke test first, it's cheap and gates everything downstream. Once it passes, bundle the full item 3 regeneration with the oracle gate removal, one set of fresh runs and one retrain covers both. Item 1's remaining validation runs, the recall decay breakdown, and the confidence multiplier recalibration can all proceed in parallel since none of them depend on the regeneration. Do not run the full ablation grid again until the oracle gate is out and the feature fix has landed, every number from every prior round is provisional until then.
