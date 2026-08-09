# Stale Forwarding Claims — Root Cause Analysis and Epoch-Tag Fix

**Status:** root cause established from run data; fix specified, **not yet applied**.
**Date:** 2026-08-09
**Affects:** S1, S2, TAP (every consumer of `t_claimed_packet`)
**Does not affect:** S3–S8, LSTM, witness (they never read this array)

---

## 1. Executive summary

S1, S2 and TAP compute hop delay as `t_recv − t_claimed`, where `t_claimed` is
read from `t_claimed_packet[node][flow][packet]`. That array is indexed by a
**recycling** packet id, so a read cannot tell whether the stored timestamp
belongs to the packet in hand or to an earlier occupant of the same slot.

Measured on the live Q5 run (`A2_Q5.log`), **62 % of S2's triggers are
physically impossible delays** — up to 15.7 seconds — produced by reading
another packet's timestamp. They are counted as false positives against benign
nodes.

This single defect accounts for the poor delay-signature results seen
throughout the Q1/Q4/Q5 ablation work, and explains why S3–S8 show zero false
positives under identical conditions.

---

## 2. Evidence

### 2.1 The delay distribution is bimodal

Extracted from 1 173 S2 triggers in `A2_Q5.log`:

| Percentile | hop_delay |
|---|---|
| p0  | 82.076 ms |
| p25 | 82.088 ms |
| p50 | **1 153 ms** |
| p75 | 3 251 ms |
| p95 | 9 894 ms |
| p100 | **15 741 ms** |

| Band | Count | Share |
|---|---|---|
| 82.076–82.088 ms (attack band) | 430 | 36.7 % |
| 90–200 ms | 15 | 1.3 % |
| 200 ms – 1 s | 66 | 5.6 % |
| **> 1 s** | **662** | **56.4 %** |

The genuine detections form a razor-tight cluster at ~82.08 ms — exactly the
80 ms injected delay plus ~2 ms propagation. Everything above 200 ms is an
artefact: a VANET hop does not take seconds.

### 2.2 The stale stamps are not an uninitialised array

Implied stamp time (`t_recv − hop_delay`) for the anomalous triggers spans
**1.189 s to 17.475 s**, median 6.466 s. They are real timestamps from earlier
in the run, not zeros.

### 2.3 The same stamp is re-read repeatedly

Sender 34, flow 0 — implied stamp in parentheses:

```
(t=1.38,  delay=82 ms,    stamp=1.30)   <- genuine
(t=7.46,  delay=3997 ms,  stamp=3.46)
(t=8.29,  delay=6992 ms,  stamp=1.30)   <- same stamp as t=1.38
(t=10.28, delay=8984 ms,  stamp=1.30)   <- again
```

Sender 38, flow 0 reads stamp `17.47 s` **five times**. Across the run,
**31.5 % of triggers (414 / 1 316) read a stamp value already seen for that
same (sender, flow)**.

This is the decisive observation. The stamping call at `routing.cc:121316` is
**unconditional** — no first-write-wins guard — so had the presumed sender
actually forwarded a fresh packet, it would have overwritten the slot. The
stamp staying identical proves the sender never re-stamped it: **the reader is
looking up a (sender, flow, packet) triple that does not correspond to the
packet actually in flight.**

---

## 3. Root cause

### 3.1 The key is not unique over time

```c
const int Flow_size = 55;              // routing.cc:88
const int flows     = 4;               // routing.cc:131
double t_claimed_packet[total_size][2*flows][Flow_size+2];   // [268][8][57]
```

Only **57 packet slots per (node, flow)**. Over a 90 s run each flow carries
far more than 57 packets, so slots are recycled. Nothing stored alongside the
timestamp identifies which packet wrote it.

### 3.2 The existing guard cannot detect staleness

```c
if (t_fwd_by_sender <= 0.0) return false;   // rejects NEVER-written slots
```

A stale value is a perfectly valid non-zero timestamp, so it passes.

### 3.3 Tagged-but-unstamped packets make it worse

There are **five tag-set sites but only three stamp sites**:

| Tag-set | Purpose | Stamped? |
|---|---|---|
| 121180 | normal relay | pairs with 121316 (verify) |
| 121614 | `hidden_tag` — Hidden Forwarding | **no** |
| 122317 | re-tag with `updated_packet_ID` | **no** |
| 124003 | `dup_tag` — Hidden Forwarding | **no** |
| 124110 | source transmit | yes — 124134 |

A receiver processing a packet from an unstamped path still performs the
lookup, finds a leftover value, and treats it as that sender's claim.

### 3.4 This is a deviation from main.tex, not merely a bug

main.tex:1351 defines the packet identity explicitly:

> `H(p)` — **SHA3-512 packet hash used as the universal packet identity**
> across UCR (Eq. ucr), witness cache, and Signature S6 (Eq. sig_s6);
> **replaces `msg_id` for notational consistency**.

The implementation substitutes a recycling index. Its `msg_id` is:

```c
inline uint32_t crypto_msg_key(uint32_t pkt_id, uint32_t flow_id) {
    return ((flow_id & 0xFFFu) << 12) | (pkt_id & 0xFFFu);   // crypto_layer.h:358
}
```

That is `(flow_id, packet_id)` packed into 24 bits — the same information and
the same non-uniqueness, merely disguised as an identity. `crypto_layer.h:353`
justifies it with *"main.tex never defines msg_id's exact contents"*, which
main.tex:1351 contradicts.

**So the root cause is a specification deviation:** the paper mandates a
globally unique packet identity; the implementation uses a slot index that
recycles every 57 packets per (node, flow).

### 3.5 Why the earlier flow-key fix did not close it

Commit `fdee626` added the flow dimension, eliminating cross-*flow* collisions,
and measured a real improvement (42 % of S2 triggers were that artefact;
52 of 53 false-positive nodes had no other trigger). But collisions **within**
a (node, flow) pair across time were left untouched — that is what remains.

---

## 4. Why this explains the ablation results

| Observation | Explanation |
|---|---|
| A2 FPR ~40 %, MCC 0.62 | 62 % of its triggers are fabricated |
| A1 false positives exceed true positives | same read path |
| S3–S8 at **zero** false positives | they never read `t_claimed_packet` |
| A3 MCC 1.000 | pure occupancy signal, no claim lookup |

It also **retires an earlier hypothesis**: S2's uncalibrated 50 ms `Δ_max` is
not the main cause. The artefacts are 1–15 s, so no threshold in a sane range
excludes them.

---

## 5. The fix

### 5.0 RECOMMENDED — carry the claim in the packet, delete the array

**The array should not exist.** Every other option keeps
`t_claimed_packet` and adds machinery to police its key. This one removes what
needs policing.

Lines 121176 (`Create<Packet>`), 121180 (`SetpacketId`), 121184
(`AddPacketTag`) and 121316 (the stamp) are **all at indentation 24 — the same
block, the same execution, the same simulator instant**. The claim and the tag
are produced together, so the claim can simply travel with the packet:

```c
// writer, at ~121183 -- BEFORE AddPacketTag
tag.SetClaimedForwardTime( node_local_time(current_hop) );
packet_i->AddPacketTag(tag);
```

```c
// reader (MacRx / s1 / s2 / TAP)
double t_fwd = tagmodified_routing.GetClaimedForwardTime();
if (t_fwd <= 0.0) return false;          // unchanged sentinel path
```

`t_claimed_packet` (and any epoch array) are then **deleted outright**.

**Why this is the best option**

* **Removes the bug class, not an instance.** Staleness requires shared mutable
  state keyed by something. With the claim inside the packet there is no slot,
  no key, no recycling, and no way for one packet to read another's value.
* **It is what main.tex describes.** `t_fwd_u` is *"the forwarding node's
  claimed timestamp"* — data the sender asserts and transmits. A global array
  indexed by `(node, flow, packet)` is a simulation shortcut with no protocol
  counterpart. This closes the §3.4 deviation without needing `H(p)`: identity
  stops being necessary once the datum rides with the packet it describes.
* **Byzantine semantics preserved.** A malicious node still writes whatever it
  likes into the field — that is what a *claimed* timestamp is — so
  `node_clock_offset()` anchoring downstream is unchanged.
* **Smallest change.** One tag field, one write, one read, minus ~955 KB of
  arrays and three accessor functions.

| | Age guard | Epoch counter | `H(p)` | **Claim in tag** |
|---|---|---|---|---|
| Fixes root cause | partial | yes | yes | **yes** |
| Shared mutable state | kept | kept | kept | **eliminated** |
| main.tex alignment | — | new deviation | removes one | **removes one** |
| Stamp↔tag pairing | n/a | must trace | must trace | **n/a — same block** |
| Serialization change | no | yes | no | yes |

Sections 5.1–5.3 record the alternatives considered and why they are inferior.

## 5.x Alternatives considered

Store an explicit owner identity with each claim and require the reader to
prove the slot is his. A mismatch returns `0.0`, i.e. the existing
"no claim recorded" path, so no downstream logic changes.

Correct **by construction** rather than by threshold: a wrong-owner slot is
rejected regardless of how recent it is.

### 5.1 Why not an age guard

`now − claim > 2·Δ_max → reject` is two lines and would remove the 1–15 s
artefacts. But it is a heuristic: a stale claim younger than the threshold
still passes, which is reachable with 57 slots recycling under load. Useful as
an interim measure; not a correctness guarantee.

### 5.2 Why not the ns-3 packet UID

`Packet::GetUid()` is unavailable at the write site.
`check_delivery_and_retransmit(flow_id, packet_id, hop, current_hop, …)`
takes no `Ptr<Packet>` — it is a scheduling-layer function operating on
indices.

### 5.3 PREFERRED: use the paper's `H(p)` instead of an invented epoch

An epoch counter fixes the symptom but **invents** an identity, adding a new
deviation from main.tex. Since §3.4 shows the defect *is* a deviation from
`H(p)`, the better fix removes the deviation rather than layering another.

**Caveat — `H(p)` cannot be used literally here.** Packets are created as
`Create<Packet>(arguments.p_size-28)` (routing.cc:121176) — zero-filled dummy
payloads. Two different packets of the same size are byte-identical, so a
content hash yields the same value for different packets. The paper's `H(p)`
presumes real payload content; in simulation the hash must cover identifying
fields instead:

```
H(p) = SHA3-512( flow_id || packet_id || sender_id || send_timestamp )
```

truncated to 64 bits for storage. This is `H(p)` in the paper's sense — a
universal, unique packet identity — and it is unique in simulation because the
timestamp distinguishes successive occupants of the same slot.

**Why this is materially better than the epoch counter:**

| | Epoch counter | `H(p)` over identifying fields |
|---|---|---|
| main.tex alignment | new deviation to document | **removes** an existing deviation |
| Tag field required | yes (`m_epoch`) | **no** |
| Serialization change | yes — silent-corruption risk | **none** |
| Stamp↔tag pairing (EDIT 7) | must be traced | **not needed** |
| Reader derives identity | from tag | recomputes from fields it already has |

The tag already carries `previous_senderId` and `previous_timestamp`
(routing.cc:121181-121182), and `sha3_512_hash()` already exists
(crypto_layer.h:86), so the receiver can recompute the identity independently.

**Open item for the `H(p)` variant:** the claim value is written at *decision*
time while the tag's `previous_timestamp` is set at *send* time (deferred by
`total_tx_delay`). Whichever timestamp is chosen must be used consistently on
both sides, so the owner hash may need to be written in a second phase at the
tag-set site rather than at the stamp site. Trace this before implementing.

**Recommendation:** implement the `H(p)` variant. Retain EDITS 3–6 below as the
storage/validation skeleton, substituting the 64-bit `H(p)` for the epoch
counter, and drop EDITS 1, 2 and 7 entirely.

---

## 6. Implementation

### EDIT 1 — tag gains an epoch field (`routing.cc` ~6399–6423)

```c
public:  uint32_t GetEpoch();
         void     SetEpoch(uint32_t epoch);
private: uint32_t m_epoch;
```

Initialise `m_epoch = 0` in the constructor (~6430). Accessors next to
`SetpacketId`/`GetpacketId` (~6512).

### EDIT 2 — serialization (6458 / 6470 / 6482)

```c
GetSerializedSize:  + sizeof(uint32_t)      // +4 bytes
Serialize:          i.WriteU32(m_epoch);    // APPEND last
Deserialize:        m_epoch = i.ReadU32();  // APPEND last, same order
```

> **A `Serialize`/`Deserialize` order mismatch does not error.** It silently
> corrupts flow and packet ids. Smoke-test before any sweep.

### EDIT 3 — counter and parallel array (~114905)

```c
uint32_t g_claim_epoch_counter = 0;   // monotonic, assigned at stamp time
uint32_t g_rx_claim_epoch      = 0;   // epoch of the packet being processed
uint32_t t_claimed_epoch[total_size][2*flows][Flow_size+2] = {};
```

### EDIT 4 — stamp records and returns its epoch (114933)

```c
inline uint32_t record_claimed_forward_timestamp(uint32_t node, uint32_t flow_id,
                                                 uint32_t packet_id)
{
    if (node >= (uint32_t)total_size)        return 0;
    if (flow_id >= (uint32_t)(2*flows))      return 0;
    if (packet_id >= (uint32_t)(Flow_size+2))return 0;
    const uint32_t ep = ++g_claim_epoch_counter;
    t_claimed_packet[node][flow_id][packet_id] = node_local_time(node);
    t_claimed_epoch [node][flow_id][packet_id] = ep;
    return ep;                      // caller must place this on the tag
}
```

### EDIT 5 — read validates ownership (114943)

```c
inline double claimed_forward_timestamp(uint32_t node, uint32_t flow_id,
                                        uint32_t packet_id)
{
    if (node >= (uint32_t)total_size)         return 0.0;
    if (flow_id >= (uint32_t)(2*flows))       return 0.0;
    if (packet_id >= (uint32_t)(Flow_size+2)) return 0.0;
    if (g_rx_claim_epoch == 0) return 0.0;    // tagged-but-unstamped path
    if (t_claimed_epoch[node][flow_id][packet_id] != g_rx_claim_epoch) return 0.0;
    return t_claimed_packet[node][flow_id][packet_id];
}
```

### EDIT 6 — `MacRx` publishes the receive-side epoch (~121727)

Immediately after `uint32_t packet_ID = tagmodified_routing.GetpacketId();`:

```c
g_rx_claim_epoch = tagmodified_routing.GetEpoch();
```

Passing context by file-scope global mirrors the existing
`g_current_trust_source` idiom (`routing.cc:114697`) and avoids threading a
parameter through `MacRx → lrad_obu/lrad_rsu → s1/s2/tap`. Safe because ns-3
is single-threaded and every detection call runs synchronously inside this
callback.

### EDIT 7 — thread the epoch from stamp to tag — **MUST BE TRACED**

The stamp and the tag-set are neither adjacent nor simultaneous. The stamp
site comment (`routing.cc:121310`) records the claim at **decision** time
"before any attack-injected delay is applied", while the send timestamp is
"deferred to `total_tx_delay`". The epoch must therefore be held in a local
and applied to the tag of the packet that transmission produces:

```c
uint32_t ep = record_claimed_forward_timestamp(node, flow, pkt);
...
tag.SetEpoch(ep);
```

| Stamp | Pairing | Status |
|---|---|---|
| 124134 | 124110 | **confirmed** — 20 lines apart, same `packet_ID` |
| 121316 | 121180? | different branch/indent — **verify** |
| 124665 | ? | no obvious partner — **trace** |

`hidden_tag` (121614) and `dup_tag` (124003) intentionally receive **no**
epoch. They keep epoch 0 and are rejected by EDIT 5 — correct, since they
never had a legitimate claim to read.

---

---

## 6.5 Side effects — checked

**Verified safe**

* **The re-tag site (122317) is dead code** — it sits inside a `/* … */`
  block. Only four live tag-set sites exist: 121180, 121614 (`hidden_tag`),
  124003 (`dup_tag`), 124110.
* **Tagged-but-unstamped paths behave correctly.** `hidden_tag` and `dup_tag`
  never set a claim, so they carry 0.0 and hit the existing
  `if (t_fwd <= 0.0) return false` sentinel. Today they read whatever the slot
  happens to hold, so this *removes* a false-positive source.
* **Byzantine clock handling unchanged.** `node_clock_offset()` anchoring and
  the M9 TIME_REF attacks operate on the claim's *value*, not its storage.

**Requires attention when implementing**

* **Three stamp sites, not one.** 121316 (relay), 124134 (source — pairs with
  tag-set 124110), 124665 (pairing not yet traced). All three must convert, or
  the converted paths return 0.0 and silently stop detecting.
* **All readers must convert together.** `s1_detection.h`, `s2_detection.h`,
  `tap_detection.h` and routing.cc:121965. `s2_detect_packet()` is invoked from
  `lrad.h:275` without the tag, so the value must be threaded or published in a
  file-scope global set in `MacRx` (the `g_current_trust_source` idiom,
  routing.cc:114697).

**Material consequence — the ground truth also changes**

`s2_detection.h:98` latches ground truth from the *same* measurement:

```c
if (delay_exceeds && sender_sim_index < total_size)
    g_s2_gt_delay_exceeded[sender_sim_index] = true;
```

A2's ground-truth positive set is `is_malicious_node[1][n] &&
g_s2_gt_delay_exceeded[n]`. Stale claims currently inflate `delay_exceeds`, so
**removing them may shrink the ground-truth positive set**: a malicious node
whose only threshold crossing came from a stale read stops counting as a
positive.

Consequences:

* **False positives fall sharply** — the main, intended effect. Benign nodes
  tripping the latch never became positives anyway (it is ANDed with
  `is_malicious_node`), so their detections were pure FP and disappear.
* **TP and FN both shift**, because the positive population itself changes.
  `DR = TP/(TP+FN)` may move in either direction.
* **Post-fix numbers are therefore not directly comparable** to the pre-fix
  Q1/Q5 rows. Both must be regenerated, not patched by ratio.

This is a *correctness* improvement — the ground truth stops counting
fabricated delays as evidence that an attack manifested — but it means "results
improve" applies to precision, FPR and MCC, not necessarily to DR.

## 7. Verification protocol

1. `./waf build`
2. Single short run:
   ```bash
   ./waf --run-no-build "scratch/routing/routing ... --simTime=20 \
     --attack_number=2 --attack_percentage=60 --sim_seed=1 \
     --attack_delay_ms=80 --attack_delay_pseudo_random=0"
   ```
3. Delay distribution must collapse to the attack band:
   ```bash
   grep -oE "hop_delay=[0-9.]+ms" <log> | sed 's/hop_delay=//;s/ms//' | sort -n | tail -5
   ```
   **PASS:** max stays near ~82 ms.  **FAIL:** values > 200 ms remain.
4. Detection must not regress: `cur_DR` stays 100 % on A2.

---

## 8. Expected impact

**Detection rate: unchanged.** A1/A2 already sit at 100 % current DR; genuine
triggers have fresh, correctly-owned stamps and pass untouched.

**False positives: should largely disappear.** 62 % of triggers are
wrong-owner reads, and the earlier flow-fix measured that 52 of 53
false-positive nodes had no other trigger — FP nodes are created by this
defect, not merely inflated by it.

Projected: A2 MCC ~0.62 → 0.9+, FPR ~40 % → low single digits; A1 similarly.
A3–A8 unaffected.

---

## 9. Impact on main.tex

### 9.1 The model needs NO change

`eq:delay_updated` (main.tex:2173) defines only the quantity:

```
δ_p(v,r,t) = t_recv − t_send,   both anchored to T_ref(t)
```

It says nothing about how `t_send` reaches the receiver — no array, no lookup.
In any real protocol the receiver can obtain it only from the packet, so
carrying the claim in the tag is the natural realisation of this equation.
Likewise `H(p)` (main.tex:1351) is already specified as the universal packet
identity. **The fix removes a deviation from main.tex; it does not create one,
and no equation, definition or claim requires editing.**

This also means no new entry is needed in the deviations documentation — the
opposite: if the substitution of a recycling index for `H(p)` was ever recorded
as a known deviation, that entry can be closed.

### 9.2 The results DO need regenerating

| main.tex element | Action |
|---|---|
| Q1 table (`tab:q1_confusion`) A1/A2 rows | **regenerate** — currently flagged as upper bounds |
| Q1 verification status, caveat four | **remove** once regenerated |
| Q1 table A3–A8 rows | unchanged — those signatures never read the claim |
| Q4 (`tab:q4_witness`) | unchanged — witness-native counters do not read the claim |
| Q5 section (not yet written) | write from post-fix data |

The caveat added in commit `86ce631` — *"the A1 and A2 rows predate two
subsequent corrections … should be regarded as upper bounds pending
regeneration"* — is discharged by re-running Q1 after this fix, at which point
that sentence should be deleted rather than amended.

### 9.3 What must be stated when the numbers are regenerated

Per §6.5, the ground-truth positive set changes as well as the detections.
Post-fix A1/A2 figures are therefore **not comparable** to the pre-fix ones by
ratio or adjustment; both must come from a clean re-run, and any narrative
comparing "before and after the fix" must say that the denominator moved.

---

## 10. Consequences for already-published results

The A1/A2 rows of the Q1 table in `main.tex` (and the equivalent Q5 rows) were
produced with this defect present and **overstate false positives**. They are
already flagged there as upper bounds pending regeneration. Q1 and Q5 must be
re-run after this fix before those rows are final. A3–A8 rows are unaffected
and need no regeneration.
