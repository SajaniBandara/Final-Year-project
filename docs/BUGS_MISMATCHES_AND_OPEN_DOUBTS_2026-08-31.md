# Bugs, spec mismatches, and open doubts — consolidated

Working inventory from the 2026-08-31 session on this machine, plus the A8
rise-and-fall findings returned from the HPC machine the same day. Covers the
`packet_id` identity family, the UCR metric, LRAD's HMAC path, and the LSTM
feature-count drift.

**`docs/main.tex` is the authority throughout.** Where a repo `.md` and
`main.tex` disagree, `main.tex` wins; several entries below exist only because
the code was checked against `main.tex` rather than against the older notes.

---

## 0. Status at a glance

| # | Item | Kind | Status |
|---|---|---|---|
| B1 | UCR dedup set is run-scoped, key is cycle-scoped | bug | **open** |
| B2 | LRAD `g_hmac_tags` key omits `flow_id` | bug | **fixed this session** |
| B3 | LRAD HMAC verification is a tautology | bug | open → Path A (declare) |
| M1 | UCR packet identity: `H(p)` specified, never implemented | mismatch | **fixed this session** |
| M2 | UCR window `W` specified, absent in code | mismatch | open (= B1) |
| M3 | UCR off-path predicate: policy vs attack's eavesdropper set | mismatch | open |
| M4 | "UCR returns to 0 post-quarantine" | mismatch | **disproved by data** |
| M8 | `\|P_total\|` counted demanding-flow packets only; numerator was 1.59x it | mismatch | **fixed this session (Option A)** |
| M5 | TVR reported for A8 | mismatch | drop from A8 reporting |
| M6 | `eq:lstm_input` lists 10 features; pipeline uses 11 | mismatch | open |
| M7 | `lstm_weights_cpp.bin` is a 10-feature checkpoint | mismatch | retrain owed |
| C1–C3 | Three claims of mine the evidence refuted | correction | recorded below |
| E1–E3 | Environment / process hazards | process | recorded below |

---

## 1. The root pattern — `packet_id` is a slot index, not an identity

`packet_id = total_packet_counter + 1` (`routing.cc:124890`), and
`total_packet_counter` is **function-local** (`routing.cc:122523`, `125091`), so
it restarts at 1 **every cycle**. It is bounded (~1..16) because it indexes
fixed per-cycle arrays:

```
bool     pending[185][Flow_size+2];    // routing.cc:121248
uint32_t attempts[185][Flow_size+2];   // routing.cc:121250
```

`(flow_id, packet_id)` therefore identifies a packet **only within one cycle**.
Any container holding it must be cycle- or window-scoped. It cannot be "widened"
without re-dimensioning those arrays and the transmission bookkeeping that
depends on the per-cycle reset.

Three consumers already solve this, three different valid ways. Two did not:

| Consumer | Handling | Verdict |
|---|---|---|
| S1 (`s1_detection.h:462-463`) | doesn't use it — `"(for logging)"` only | correct by design |
| S2 / TAP (`claimed_forward_timestamp()`, `routing.cc:114949`) | voids the pair; identity from the tag's claimant + ownership check | fixed previously |
| S6 (`s6_detection.h:82,87`) | keeps the pair, expires entries older than `S6_WINDOW_S = 30.0` | correct |
| crypto (`crypto_layer.h:418`) | composes `flow_id` via `crypto_msg_key()` — the FV688 fix | fixed previously |
| LRAD (`lrad_hmac.h`) | neither — no flow, no expiry | **B2, fixed this session** |
| UCR (`efade_detection.h:120`) | run-scoped set | **B1, open** |

`claimed_forward_timestamp()` carries the diagnosis in its own comment —
*"rather than whatever happens to occupy a recycled array slot"* — so this hazard
was already recognised in this codebase. UCR is the site that never got the fix.

---

## 2. B1 / M1–M4 — UCR

`eq:ucr` (`main.tex:4288`):

```
UCR = |{ p in P_total : exists d' not in P(s_p,d_p), p in R(d', W) }| / |P_total|
```

| axis | `main.tex` | code | consequence |
|---|---|---|---|
| **M1** identity | `H(p)`, SHA3-512, *"the universal packet identity across UCR, witness cache, and S6"* (`main.tex:1306`) | `(flow_id, packet_id)` | recycles → saturates |
| **M2** window | `R(d', W)` — explicit window | set cleared once per run (`routing.cc:115630`, in the run-reset block beside `attack_percentage = 0`) | `W` = whole run |
| **M3** off-path test | `d' not in P(s_p,d_p)`, the blockchain-committed policy (`eq:policy_commit`, `main.tex:3779`) | `is_eavesdropper_node`, the attack's own designated eavesdropper set (`routing.cc:122051-122054`) | metric defined by attack config, not policy |
| **M4** behaviour | *"UCR returns to 0 post-quarantine"* (`main.tex:4302`) | decline reproduces with enforcement **OFF**, 5 seeds | claim disproved |

`sha3_512_hash()` exists (`dkg_setup.h:23`) but **no packet hash is computed
anywhere** — M1 is unimplemented, not mis-implemented.

### M1 FIXED 2026-08-31 — and it exposed M8

`H(p)` is now implemented: `ucr_packet_identity()` (`crypto_layer.h`) returns the
leading 64 bits of `SHA3-512(flow_id ‖ packet_id ‖ original_ts_ns)`, and
`fade_eavesdropped_packets` is a `std::set<uint64_t>` keyed by it.

Payload contents are *not* hashed — ns-3 payloads here are synthetic and
zero-filled, so a content hash would give every packet the same digest. The three
fields used all travel in the packet tag, so every receiver of a packet derives the
same `H(p)`; `original_timestamp` is preserved across hops (read at
`routing.cc:122042`, propagated at 121402/122648) and stamped fresh only at packet
creation (124442), so it identifies the packet, not the hop. A hidden duplicate
inherits the original's `original_timestamp`, so a copy and its original share one
`H(p)` — which is the `eq:ucr` semantics (distinct packets, not copy events).

**The saturation is gone.** Measured A8 @60%, 60 s, seed 1: the numerator reads 0
before attack onset, then 10–45 distinct packets per cycle, sustained to end of run
— instead of dying to ~32 pairs for the whole run.

**But the metric now clamps at the other rail**, and this is a second, independent
defect that the saturation was hiding:

| | value |
|---|---|
| cumulative distinct packets eavesdropped | **1,238** |
| cumulative `total_sent` (the denominator) | **778** |
| cycles where numerator > denominator | **37 / 58** |

`eq:ucr` is a subset ratio — the numerator is `{p ∈ P_total : …}` — so it cannot
exceed `|P_total|`. It does here because the two count different populations:

- **numerator**: every distinct packet reaching an off-path receiver, from any
  source and any cycle
- **denominator**: `sum of f_size` over `2*flows` — packets injected by the
  demanding flows in this cycle only (`routing.cc:117767-117773`)

The excess is 1.59x cumulatively, so it is not a windowing/lag effect. Packets exist
in the network that `f_size` never counted (there is at least one separate packet
creation path at `routing.cc:124442`).

### M8 — `|P_total|` is implemented as the demanding-flow packet count

Open. Fixing it means deciding what `P_total` is, which is a reporting decision, not
a code decision:

- **Option A** — denominator = distinct packets *observed traversing the network* in
  the window (a second `H(p)` set populated on every receive). Guarantees
  numerator ⊆ denominator by construction, so no clamp. Faithful to `eq:ucr`'s
  `p ∈ P_total`. Costs a hash per receive.
- **Option B** — restrict the numerator to demanding-flow data packets so it matches
  the existing denominator. Cheaper, but narrows what UCR measures.

**Option A implemented 2026-08-31.** `fade_all_packets_seen`
(`efade_detection.h`), keyed by the same `H(p)`, is populated at the single
per-received-packet point in MacRx (`routing.cc`, immediately after
`originail_timestamp` is read) - upstream of both eavesdrop sites, so
numerator-subset-of-denominator is guaranteed *structurally*, not by argument. The
hash is computed once there and reused by both sites, so a received packet costs
exactly one `H(p)`.

Choice of A over B is settled by the paper itself: `eq:tvr` (`main.tex:4248`) has
identical structure and defines its set as `P_crit = {p : Priority(p) = High}` - a
predicate over packets, not a flow-size parameter - and its prose explicitly keeps
packets that were *never forwarded* in the set. `P_total` is the same shape with the
predicate dropped: all packets observed. Option B would have narrowed the
numerator's predicate, which `eq:ucr` fixes as `exists d' not-in P(s_p,d_p),
p in R(d',W)` with no mention of demanding flows.

**Result - the clamp is gone and the metric discriminates by attack intensity**
(A8, 60 s, seed 1; per-cycle numerator <= denominator in every cycle):

| config | cumulative UCR | eavesdropped / observed |
|---|---|---|
| A8 @20% | **76.49%** | 576 / 753 |
| A8 @60% | **89.19%** | 1,238 / 1,388 |

This is the behaviour M3 was specified for and that neither previous version could
produce: the broken identity read ~0% at every intensity, and the H(p)-only version
clamped to 100% at every intensity.

The absolute values are high because they are true - under hidden forwarding most
observed packets do reach an off-path receiver. A peak of 100% in individual cycles
is legitimate, not a clamp: those cycles genuinely have every observed packet
eavesdropped.

**CPU cost not cleanly isolated.** The A8@60% 60 s run took 350 s wall (5.8 s per
simulated second), against 7.2-12.3 s/sim-s for the earlier 300 s P1 runs - so no
sign of material slowdown, but that is not a matched control and should not be
quoted as one.

### HPC evidence (A8 @60%, 300 s, seeds 1–5, enforcement OFF/ON)

- Peak UCR 96.0% ± 4.90 in **both** arms; decline identical. Quarantine excluded.
- Only ~32 distinct `(flow, packet_ID)` pairs exist in a 300 s run; the pair space
  is exhausted by t≈100 s and the per-cycle delta is 0 thereafter.
- 167,171 interceptions in seed 1 alone, peaking at 14,396 in the 140–160 s bucket
  — long after the metric reads zero.

**The decline is counter saturation, not containment.**

### What follows for the caption

Counting relay traffic that reaches an off-path receiver is **spec-correct** under
`eq:ucr` — it counts packets received at any `d'` outside the policy, deliberate
copy or not. So the split the HPC run measured is:

| | OFF | ON | reduction |
|---|---|---|---|
| intentional hidden-duplicate sends | 9,950 | 89 | **99.1%** |
| eavesdropper receives | 168,097 | 127,203 | **24.3%** |

**~24% is the honest containment number.** The 99.1% figure measures *scheduling
suppression*, which is not containment in the `eq:ucr` sense. The ~76% residual is
a real gap (supervisor open question §2.3), not a measurement artifact.

Independent corroboration: wall-clock fell 24.2% (3,183 s → 2,411 s), matching the
receive-side reduction, not the send-side one.

### M5 — TVR for A8

`avg_TVR` is identically 0.000 in all ten HPC runs. This is **spec-conformant**:
`main.tex:1280` assigns TVR and UCR to *"selective time delay and hidden forwarding
respectively"*. TVR was never an A8 metric and should not be presented as one.

---

## 3. B2 — LRAD `g_hmac_tags` key (fixed this session)

`g_hmac_tags` was keyed `{node, pkt_id}` — **no flow component**
(`lrad_hmac.h:32`) — and cleared only in `lrad_reset_state()` (per-run,
`lrad.h:141`). Concurrent flows through one node collided on a single slot.

**Fix applied**, following the `crypto_msg_key()` pattern already proven for FV688:

- `lrad_hmac.h` — key is `{node, crypto_msg_key(pkt_id, flow_id)}`; message buffer
  now `msg_id || ts || eta` per `eq:hmac_light`, with `eta_i <- RAND()` via
  `OQS_randombytes()` matching the full-mode signer. The old `nonce` field had been
  set to `pkt_id` by every caller, duplicating `msg_id` and carrying no entropy.
  Verified behaviour-neutral (all counters bit-identical)
- `lrad.h` — `lrad_s2_partial_check()` takes `flow_id`; it was already in
  `lrad_obu()`'s signature as `fid`, just never passed through
- `routing.cc` — three write sites pass the flow; the write-if-absent at 124465
  made unconditional

**Measured** (A2 @40%, 40 s, seed 1, 40,000 `lrad_s2_partial_check()` calls):

| | pre-fix | post-fix |
|---|---|---|
| `fires` | 2,197 | **2,272** (+3.4%) |
| `miss` | 6,625 | 6,625 (bit-identical) |
| entries older than one transmission period | **0** | **0** |

`miss` being bit-identical at both the 20k and 40k checkpoints, with `fires`
shifting proportionally, indicates a systematic effect rather than noise.

**Direction matters:** the collision was *masking* detections — a colliding slot
served another flow's fresher timestamp, making the gap look smaller than it was.
The fix recovers them. It does not remove false positives.

Build clean; validation run `rc=0`, error gate 0, `avg_PDR` unchanged at 64.0111.
**Not committed.**

---

## 4. B3 — LRAD HMAC verification is a tautology

`lrad_s2_partial_check()` (`lrad.h`) rebuilds the HMAC message from the entry's
**own stored fields**:

```cpp
it    = g_hmac_tags.find({vehicle, crypto_msg_key(pkt_id, flow_id)});
msg_r = pkt_id || it->second.ts || it->second.flow_id
if (memcmp(HMAC(k, msg_r), it->second.tag, 64) != 0) return false;
```

`pkt_id` and `flow_id` are the map key (the lookup only matched because they
agree), `ts` is read out of the struct that holds the tag, and the key is the same
node's. So the comparison is `HMAC(k,m) == HMAC(k,m)` — **true for every entry that
exists**. The `memcmp` branch is unreachable; the function is a pure threshold test.

Per `alg:lrad_obu` (`main.tex:2340`), `tau` is a **procedure parameter** — it should
arrive with the packet, and `HMAC.Verify(tau,p)` should recover an authenticated
`ts_recv`.

### Why implementing it would not help

**HMAC authenticates origin, not truthfulness.** In S2 the malicious node is the
*forwarder*; it holds its own key and can sign a false timestamp perfectly. A
correct `Verify` returns **true**. That is precisely why full S2 pairs the check
with a ZKP (`eq:sig_s2`: `... AND pi_delay(u) = bottom`) and why `alg:lrad_obu`
marks S2-partial *"threshold only, no ZKP"*. None of the eight attacks is an
impersonation attack, so the forgery vector HMAC defends against is never exercised.

**Resolution: Path A — declare it modeled.** Precedent exists: STARK/ZKP timing
proofs are already recorded in `REPORT_IMPLEMENTATION_AUDIT.md` as supervisor-
approved simulation. The computational cost is real and measured
(`crypto_timing_log`), so the *overhead* claim stands; only the *verification*
claim is downgraded.

---

## 5. M6 / M7 — LSTM feature drift

| | value | source |
|---|---|---|
| `eq:lstm_input` in `main.tex` | **10** features | `main.tex:3183` |
| Pipeline | **11** features | `lstm_model.py:28`, `N_FEATURES = 11` |
| `lstm_weights_cpp.bin` | **10**-feature checkpoint | `lstm_model.py:13-18` |

History (`lstm_model.py:9-18`): 7 → 10 on 2026-07-26 (`d_div`, `a_tp`, `r_anom`);
10 → 11 on 2026-08-14 (supervisor Fix 3) appending `delta_t_exceeded` =
`1[exists p in window : delta_p > Delta_max]`. `delta_t` itself also changed from
mean to per-cycle **max** in the same fix.

> *"Any checkpoint trained before this change has N_FEATURES=10 and is
> INCOMPATIBLE — must be retrained, not loaded as-is"*

`lstm_normalize_features()` aborts loudly on a size mismatch, so this is not latent.
**A retrain is already owed**, independent of anything in this document.

Regeneration scale: `results_routing/lstm_training/` holds 64 RSU directories ×
67 files (14 configs × 5 seeds), 77 MB, each run 299 cycles.

`main.tex`'s `eq:lstm_input` also needs the 11th feature added — it is a feature
behind the pipeline.

---

## 6. Corrections — claims of mine the evidence refuted

Recorded so they are not repeated.

**C1 — LRAD staleness false positives: predicted, refuted.**
I claimed entries would age and fire `flag_S2p` spuriously, growing over a run.
Measured: **0 stale entries in 40,000 calls, in both builds.** The unconditional
write paths (`routing.cc:121554`, `124996`) restamp on every forward, so `ts_recv`
is always fresh. The freshness gate I added is therefore dead code in the default
config (it only rejects gaps > `data_transmission_period` = 1.0 s, versus
`S2_DELTA_MAX` = 50 ms, so it cannot suppress a real detection). My
"CONFIRMED BROKEN" verdict was too strong.

**C2 — "changing the tag forces a full re-run": wrong.**
The tag is attached with `AddPacketTag()` — an ns-3 **packet tag**, i.e. simulation
metadata. It does not contribute to `Packet::GetSize()` and is never serialized to
the channel; payload is set explicitly (`Create<Packet>(p_size - 28)`,
`flow_packet_size = 750`). Adding fields changes no packet size, airtime, PDR,
latency, or LSTM feature. `TagData` uses a `size` field with `uint8_t data[1]`
(flexible array), so there is no fixed size ceiling either.

**C3 — proposed `is_hidden_duplicate` tag bit for UCR: wrong against spec.**
`eq:ucr` counts packets received at any off-policy `d'`, deliberate copy or not.
Gating the numerator on intentional duplicates would make the code diverge from the
spec, not converge. See §2.

---

## 7. Open doubts

1. **UCR fix scope.** The spec-faithful fix needs `H(p)` computed per packet, a real
   window `W`, and the policy-based off-path test. Is that in scope for the thesis
   timeline, or is UCR retired as a temporal curve and reported only as a
   peak-onset figure?
2. **The ~76% interception residual.** Scheduling-only enforcement leaves it intact.
   Design change, or documented limitation?
3. **LRAD freshness gate.** Never fires at `data_transmission_frequency = 1.0`.
   Unknown whether it matters at other frequencies. Currently harmless.
4. **Fix 23 retrain sequencing.** Owed regardless; no dependency on this document's
   items now that C2 is corrected.
5. **`main.tex` `eq:lstm_input`** needs the 11th feature — who owns that edit.

---

## 8. Environment and process hazards

**E1 — disk exhaustion.** Root filled to 100% (141 MB free) mid-run; `/tmp` shares
the partition, so the shell itself began failing. Cause: `bc_detection_log_*.csv` at
~1.8 GB per 300 s A8 run. **P1 seeds 3 and 4 were contaminated** (`path_err` 17 and
6, logs containing `No space left`) and discarded; seeds 1–2 completed clean.
`detector_windows_*` + `MOBIGUARD_*` — the files analysis actually reads — total
only ~9 MB. Delete the bulk diagnostic CSVs per run, not per sweep.

**E2 — launcher path.** `scripts/run_std_attacks.py` hardcodes
`NS3_DIR = ~/ns3_g13/...` (HPC). On this machine `--build` syncs correctly and then
fails at the build step; run `./waf build` directly afterwards. **Do not commit a
path fix** — the repo intentionally keeps the HPC path.

**E3 — `routing.cc` local-only diff.** The working tree carries a
`sdvn_hidden_attacks` → `nipuni` path swap (~1,096 lines). **Never commit it.** Any
commit of `scratch/routing.cc` must stage only the intended hunks.

---

## 9. Provenance

- §2 HPC results: A8 @60%, 300 s, seeds 1–5, two arms, 10-way parallel, 61.7 min
  wall; all runs `rc=0`, error gate 0, 298 cycles.
- §3 measurements: this machine, A2 @40%, 40 s, seed 1, instrumented builds
  (instrumentation removed afterwards).
- A4/A3 enforcement A/B (`A4_QUARANTINE_LEAK_2026-08-31.md`) was re-checked against
  the stale-binary concern raised by the HPC session: binary built 02:34:35 vs
  commit `6cb1189` at 02:19:40, flag present. The **A3 control** (25,234 → 25,176)
  is the decisive evidence — a stale binary would have made A3 identical too.
