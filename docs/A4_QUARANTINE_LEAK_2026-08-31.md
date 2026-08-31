# A4 quarantine enforcement leak — confirmed

Closes `SESSION_2026-08-31_ENFORCEMENT_AND_CALIBRATION.md` §10 item 8, which
flagged this as *"untested — A3/A4 were not in this validation set."* Tested on
the machine holding A3/A4. **The suspicion was correct**, and the mechanism is
different from the A6/A8 case in a way that matters for the fix.

---

## 1. Result

A/B on the same binary, seed 1, 300 s attack config at `simTime=90`,
`--attack_percentage=60`, only `--enable_quarantine_enforcement` varied.
A3 is the control: its attacker **is** an RSU, so enforcement should bite there.

| run | malicious installs | Δ vs off | quarantined nodes |
|---|---|---|---|
| `q_a4_off` | 49,689 | — | 28 RSUs, **0 vehicles** |
| `q_a4_on`  | 49,689 | **0** | 28 RSUs, **0 vehicles** |
| `q_a3_off` | 25,234 | — | 2 RSUs |
| `q_a3_on`  | 25,176 | **−58** | 2 RSUs |

**A4 is byte-identical with enforcement on. A3 is not.** Enforcement works;
it is simply inert for A4.

All four runs: `path_err = 0` (no degraded link-lifetime cycles).

---

## 2. Mechanism — confirmed end to end

1. **A4 (DP) passes a vehicle as the guarded node.**
   `tcam_attack_helper.h:936` — `tcam_install_malicious(attacker_node, target_rsu_node_id, fake_fid)`
   where `attacker_node` is a **vehicle**.
   A3 (CP) passes `tcam_install_malicious(rsu_idx, rsu_idx, …)` — attacker *is*
   the RSU, which is why the control behaves.

2. **The guard checks that vehicle.**
   `tcam_attack_helper.h:784` — `if (quarantine_blocks(node_id)) return;`

3. **No vehicle is ever quarantined.** Measured: 0 of 28 quarantined nodes in
   A4, 0 of 2 in A3. `quarantine_blocks()` does span the full node space
   including vehicles, so this is not an indexing bound — vehicles simply never
   reach the quarantine condition.

4. **Nothing decrements the attacking vehicle's trust.** S3/S4 record their
   detections against the **victim RSU** (`tcam_detection.h:336,349`), and
   `tcam_detection.h` contains **no `trust_update_negative` call at all**.
   Quarantine fires from `g_trust_score[node] < TRUST_T_MIN`
   (`crypto_layer.h:1372-1373`), so with nothing decrementing the attacker,
   `quarantine_blocks(attacker_node)` is permanently false.

---

## 3. Why this is NOT the A6/A8 fix again

The A6/A8 leak was a **guard placement** problem: the attacker was reachable,
and guarding both `current_hop` and `hf_gt_attribution_node(current_hop)`
closed it.

Here the attacker **never enters quarantine at all**, so *no placement of the
guard can help*. The gap is upstream of enforcement, in attribution.

**Do not "fix" this by also guarding `target_rsu_node_id`.** It would compile,
and it would change the numbers, but it is wrong twice over:

- It blocks the attack whenever the **victim** is quarantined, punishing the
  wrong node — quarantining a victim should not stop its attacker.
- It hands a compromised RSU a **shield**: getting itself quarantined would
  stop incoming TCAM attacks against it.

The honest framing is that A4's attacker is currently unattributable by the
S3/S4 path, so quarantine has nothing to act on. Whether that should be fixed
by attributing S3/S4 detections to the installing node, or by accepting that
TCAM-DP attribution is out of scope, is a design decision rather than a bug fix.

---

## 4. Caveats

- **A3's effect is small in absolute terms** — 58 of 25,234 installs (0.23%),
  because only 2 RSUs quarantine within the window. That is sufficient to prove
  the guard fires, and **not** sufficient to characterise enforcement's impact
  on A3. A longer run or higher attack percentage would be needed for that.
- **Single seed, `simTime=90`, 60% only.** This establishes the mechanism, not
  a distribution. `simTime=90` was chosen deliberately: quarantine fires from
  ~t=10, so ~80 s of post-quarantine observation is ample for a mechanism test,
  at ~6× less wall time than 300 s.
- The A4 vs A3 install counts are not comparable to each other (different attack
  models); only the **within-variant** off/on comparison is meaningful.

---

## 5. Reproduce

```
--simTime=90 --sim_seed=1 --attack_number={3,4} --attack_percentage=60 \
  --enable_detector_windows=1 --enable_quarantine_enforcement={0,1}
```

Compare `grep -c "TCAM INSTALL MAL"` between the off/on arms of the same attack.
Check quarantined node ids with
`grep -oE "TRUST-QUARANTINE\] node=[0-9]+"` — vehicle ids are `< N_Vehicles`.

Logs: `logs/a4_quarantine/`.
