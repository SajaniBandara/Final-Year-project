# Phase Status

## Phase 1 — Fabric test network (COMPLETE)

- Fabric 2.5.15 / CA 1.5.17 installed
- `test-network` up: orderer + Org1/Org2 (1 peer each) + CouchDB
- Channel `mychannel` created, both peers joined
- Sample chaincode `basic` deployed, committed (2-of-2 endorsement),
  verified end-to-end (`CreateAsset`/`ReadAsset`/`InitLedger`/`GetAllAssets`)

## Phase 2 — `mobiguard-cc` chaincode (COMPLETE)

Deployed to `test-network` on `mychannel`, sequence 1,
endorsement policy `OR('Org1MSP.peer','Org2MSP.peer')`.
All six asset types verified end-to-end with synthetic invocations
(`test_synthetic.sh`, all 8 sections passed, June 18 2026).

### Org-to-role mapping (current test-network)
- Org1MSP → RSUOrg (write access to all six asset types)
- Org2MSP → ControllerOrg (read-only: queries only)
- Second Org1 identity `rsu02` enrolled under ca-org1 (required for
  FlowMod f+1=2 endorsement quorum testing)

### Six asset types implemented
| # | Asset | Key prefix | Report eq. |
|---|-------|-----------|------------|
| 1 | FlowMod log/endorsement | `flowmod:{hash}` | Eq 3.41/3.43/3.44 |
| 2 | Detection events | `detect:{nodeId}:{ts}` | Eq 3.42 |
| 3 | Trust scores | `trust:{nodeId}` | Eq 3.46 |
| 4 | Quarantine / peer lifecycle | `quarantine:{nodeId}` | Eq 3.47 |
| 5 | Model hash commits | `model:{rsuId}:{round}` | Eq 3.39 |
| 6 | Witness alerts | `alert:{packetHash}` | Eq 3.20-3.24 |

### Supervisor instructions implemented
- Three-state peer lifecycle (active → demoted → removed) per supervisor:
  - T_demote = 0.30 (3000 bp): peer demoted to client state
  - T_remove = 0.10 (1000 bp): client ejected from system, writes blocked
  - `QuarantineLifted`: manual reinstatement via `LiftQuarantine` (demoted only)
- Runtime peer selection via `QueryPeerSelection` / `IsActivePeer`
- Initially all nodes are active peers (score initialises at 10000)
- Placeholder simulation parameters in `sim_params.go` (all S1-S8
  thresholds, LSTM hyperparameters, crypto/PBFT settings per Table 4.1)

### Known gotchas hit during Phase 2
- `CORE_PEER_TLS_ENABLED=true` must be set explicitly in the shell
  (not inherited from core.yaml alone); add to `~/.bashrc`
- CA containers (`ca_org1`, `ca_org2`) are not started by
  `network.sh up` — start manually with `docker start ca_org1 ca_org2`
  before enrolling new identities
- Cold-start latency on first chaincode invocation (~5s); test script
  includes `sleep 8` warm-up at top

### Open items / known deviations
- `byzantineF=1` and trust Δr/Δp/Tmin values are placeholders —
  recalibrate from SUMO/ns-3 data (see `sim_params.go`)
- Witness-alert RSU-relay vs. direct-write tension documented in
  `alert.go` TODO(witness-direct-write) — revisit when S1-S8 land
- `WitnessAlert.SuspectNode` / `Penalized` fields are additions beyond
  original SPEC.md schema (required for Eq 3.24 auto-penalize logic)

## Phase 3 — ns-3 output extension (PARTIALLY BLOCKED)

- 3a: FlowMod CSV writer from `g_tcam_table` (`tcam_attack_helper.h`) —
  **NEXT, buildable now**
- 3b: detection/trust/model/alert CSVs — blocked on S1-S8 signature
  modeling (not yet started in `routing.cc`)

## Phase 4 — Bridge (Node.js, fabric-gateway)

- Tails CSVs from Phase 3, maps rows to chaincode calls
- Can be built/tested against Phase 3a (FlowMod) now; other tailers
  wired but inert until Phase 3b lands

## Phase 5 — End-to-end validation

- Baseline: `--routing_test=1 --active_attack_variant=-1` (PDR=100%)
- Then individual attack variants once S1-S8 + Phase 3b exist
