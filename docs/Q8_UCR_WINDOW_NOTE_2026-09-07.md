# Q8 — UCR predicate and window: the bounded-arrival check, and why the
# whole-run vs windowed distinction is moot

**Instruction (round 8):** *"Accept the current implementation, document rather
than change the code. One quick check first, confirm that in this simulation a
duplicate always arrives within a short bounded time of the original, well under
any window value under discussion. If that holds, the whole run versus windowed
distinction is moot in practice and a documentation note closes it."*

## The check

**It holds, and it holds by construction rather than by measurement.** The hidden
duplicate is not emitted at an arbitrary later time — it is scheduled at a fixed
1 ms offset from the original on both code paths:

| path | variants | site | offset |
|---|---|---|---|
| Active HF | A5, A6 | `routing.cc:121770` | `Simulator::Schedule(Seconds(0.001), send_hidden_duplicate_trampoline)` |
| Passive HF | A7, A8 | `routing.cc:121839` | `Simulator::Schedule(Seconds(0.001), send_hidden_duplicate_trampoline)` |

Both copies then traverse the same DSRC channel, so the separation at the
receiver is the 1 ms scheduling offset plus a sub-millisecond channel delta.
`s6_detection.h:77` documents the same fact from the detector's side: *"Both the
legitimate delivery and the eavesdrop copy arrive within 0.001 s of each other
(the trampoline offset in `hf_send_active_duplicate`)."*

## Why this closes the question

The observation window is `S6_WINDOW_S = 30.0` s (`s6_detection.h:82`). The
original-to-duplicate separation is **1 ms — four orders of magnitude smaller**,
a ratio of roughly 30,000:1.

For a windowed predicate to differ from a whole-run predicate, a duplicate would
have to fall outside the window containing its original. At a 1 ms separation
that can only happen when the original lands within 1 ms of a window boundary —
about 1 in 30,000 pairs — and even then the pair is split across two adjacent
windows rather than lost. No candidate value of `W` under discussion is anywhere
near 1 ms, so **no plausible `W` changes the outcome.**

This is a stronger result than an empirical bound would have been: the offset is
a compile-time constant on both paths, not a distribution with a tail that might
occasionally exceed `W`.

## Scope limit, stated plainly

This bounds the *attack model as simulated*. A real adversary is under no
obligation to duplicate within 1 ms, and one that deliberately delayed its copy
beyond `W` would defeat a windowed predicate while remaining visible to a
whole-run one. That is a property of the threat model, not of the implementation,
and it belongs in the limitations section rather than being treated as a defect
in the UCR predicate.

**Action:** documentation only. No code change, per instruction.
