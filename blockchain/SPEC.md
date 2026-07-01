# Chaincode Schema — `mobiguard-cc`

Six asset types, one chaincode, mapped to the report's blockchain
architecture (Security & Consensus Layer, §3.4.10) and signature
equations (§3.4.4–3.4.9).

## Asset types

| # | Asset | Key prefix | Schema | Report eq. | Functions |
|---|-------|-----------|--------|-------------|-----------|
| 1 | FlowMod log/endorsement | `flowmod:{hash}` | `{rsuId, flowModHash, recvTimestamp, endorsements[], status}` | Eq 3.41/3.43/3.44 | `LogFlowMod()`, `EndorseFlowMod()`, `QueryUnauthorizedFlowMod()`, `GetFlowMod()`, `MarkFlowModUnauthorized()` |
| 2 | Detection events | `detect:{nodeId}:{ts}` | `{suspectNode, signatureIndex (S1-S8), timestamp, rsuId, rsuSig}` | Eq 3.42 | `LogDetection()`, `GetDetection()`, `GetAllDetections()` |
| 3 | Trust scores | `trust:{nodeId}` | `{score (bp 0-10000), lastUpdate}` | Eq 3.46 | `UpdateTrust()`, `QueryTrust()`, `GetAllTrustScores()` |
| 4 | Quarantine / peer lifecycle | `quarantine:{nodeId}` | `{status, demotedAt, removedAt, liftedAt, timestamp}` | Eq 3.47 | `LiftQuarantine()`, `GetQuarantineRecord()`, `QueryQuarantineList()`, `QueryRemovedList()` |
| 5 | Model hash commits | `model:{rsuId}:{round}` | `{hash, committedAt, verified}` | Eq 3.39 | `CommitModelHash()`, `VerifyModelHash()`, `GetModelHash()` |
| 6 | Witness alerts | `alert:{packetHash}` | `{type (dup/non-fwd), suspectNode, alerts[], verifiedCount, penalized}` | Eq 3.20-3.24 | `SubmitAlert()`, `GetAlert()`, `GetAllAlerts()` |

**Peer selection (supervisor instruction):**
`QueryPeerSelection()`, `IsActivePeer()` — in `peer_selection.go`

**Utility:**
`GetMyIdentity()` — returns caller's `cid.GetID()` string; used by
bridge at startup to discover RSU identity for model hash functions.

**Controller read-only access:** `QueryTrust()`, `QueryQuarantineList()`,
`QueryRemovedList()`, `QueryPeerSelection()`, `GetFlowMod()`,
`QueryUnauthorizedFlowMod()`, `GetAllDetections()`, `GetAlert()`,
`GetAllAlerts()`, `GetModelHash()`, `GetMyIdentity()`.

## Trust score constants (basis points, 0–10000 = [0,1])

| Constant | Value (bp) | Value (float) | Meaning |
|---|---|---|---|
| `initialTrustScore` | 10000 | 1.0 | Starting score for all nodes |
| `defaultTrustDemote` | 3000 | 0.30 | Peer → client demotion threshold (T_demote, replaces T_min from Eq 3.47) |
| `defaultTrustRemove` | 1000 | 0.10 | Client → ejected threshold (T_remove, supervisor instruction) |
| `defaultTrustReward` | 100 | +0.01 | Δr per successful verification (Eq 3.46) |
| `defaultTrustPenalty` | 500 | −0.05 | Δp per failed verification (Eq 3.46) |

All values are **placeholders** pending SUMO/ns-3 calibration.

## Three-state peer lifecycle (supervisor instruction)

```
Score >= 3000: active peer   (no quarantine record)
               |
               | score drops below 3000
               ▼
Score 1000-2999: demoted     (QuarantineDemoted)
  - excluded from peer selection
  - still monitored, trust updates continue
  - LiftQuarantine() can reinstate
               |
               | score drops below 1000 while already demoted
               ▼
Score < 1000: removed        (QuarantineRemoved)
  - all writes permanently blocked
  - cannot be lifted
```

## Byzantine fault tolerance parameters

| Constant | Value | Meaning |
|---|---|---|
| `byzantineF` | 1 | f (Byzantine fault tolerance parameter) |
| `flowModEndorsementQuorum` | 2 (f+1) | Distinct RSU endorsements to commit a FlowMod (Eq 3.41/3.48) |
| `witnessAlertQuorum` | 3 (2f+1) | Distinct witness alerts to trigger SC.PenalizeTrust (Eq 3.24) |

## Access control

| Entity | MSP | BC Read | BC Write |
|--------|-----|---------|----------|
| RSU | Org1MSP | ✓ | ✓ (all six asset types) |
| Controller | Org2MSP | ✓ | ✗ |

Enforced via `requireRSU()` / `requireKnownOrg()` in `access_control.go`.
Write-block for removed nodes enforced via `requireNotRemoved()`.

**Note:** Org1MSP/Org2MSP are the current test-network MSP IDs. When
the network is redesigned for multi-RSU SUMO deployment (single RSUOrg
with per-RSU client identities via `fabric-ca-client register`), update
`rsuOrgMSP` / `controllerOrgMSP` constants in `types.go`.

## Schema deviations from original SPEC.md

| Deviation | Reason |
|---|---|
| `WitnessAlert.SuspectNode` field added | Required for `SC.PenalizeTrust(v_i)` (Eq 3.24) to know which node to penalize at 2f+1 quorum |
| `WitnessAlert.Penalized` field added | Guards the auto-penalize path so it fires exactly once per packet regardless of further alert submissions |
| `QuarantineRecord` extended with `DemotedAt`, `RemovedAt`, `LiftedAt` | Audit trail for three-state lifecycle (supervisor instruction) |
| `"active"` status renamed to `"demoted"` | Supervisor's language: "demoting them into a client state" |
| `"removed"` status added | Supervisor's instruction: "remove it from the system" |
| `QuarantineStatusActivePeer = "active_peer"` | Virtual label used only in `NodeStatus.QuarantineState` (peer selection output); never stored in `QuarantineRecord.Status` |

## CSV → chaincode mapping (Phase 3/4, bridge)

| CSV file | → chaincode function | Status |
|----------|----------------------|--------|
| `bc_flowmod_log.csv` | `LogFlowMod()` | **Buildable now (Phase 3a)** |
| `bc_detection_events.csv` | `LogDetection()` | Blocked on S1-S8 |
| `bc_trust_updates.csv` | `UpdateTrust()` | Blocked on S1-S8 |
| `bc_model_hashes.csv` | `CommitModelHash()` | Blocked on federated LSTM |
| `bc_witness_alerts.csv` | `SubmitAlert()` | Blocked on S1-S8 |

Validation baseline: `--routing_test=1 --active_attack_variant=-1`
(clean run, PDR=100%) — verifies FlowMod log entries land on-chain
correctly before testing attack variants.

## TODO items

- `TODO(witness-direct-write)` in `alert.go`: witnesses currently submit
  via RSU relay, not directly. Revisit when witness logic lands in ns-3
  (Phase 3b+). Options: (a) VehicleOrgMSP with per-vehicle identities,
  or (b) multi-RSU broadcast relay.
- All `sim_params.go` constants are placeholders — calibrate from SUMO
  traces and ns-3 baseline runs (Phases 3-5).
- `byzantineF=1` appropriate for 2-RSU test-network; update to
  `floor((N_RSU - 1) / 3)` when real RSU topology is deployed.
