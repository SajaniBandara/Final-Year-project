# mobiguard-cc — Deployment Notes (Phase 2)

## MSP relabeling (no test-network redeploy required)

The chaincode's access control checks `cid.GetMSPID()` against two
constants:

- `RSUOrgMSP`  — write access (all six asset types)
- `ControllerOrgMSP` — read-only (queries)

The existing `test-network` from Phase 1 was brought up with the default
sample orgs, whose MSP IDs are `Org1MSP` and `Org2MSP`. **Two options**:

### Option A (recommended for Phase 2): rename in code only

Set the constants in `types.go` to match the existing test-network MSP
IDs directly:

```go
const (
    rsuOrgMSP        = "Org1MSP"
    controllerOrgMSP = "Org2MSP"
)
```

This requires zero changes to `test-network`'s crypto material or
`configtx`. Org1 = RSUOrg (write), Org2 = ControllerOrg (read-only) by
convention from here on. All `peer chaincode invoke` write calls
(`LogFlowMod`, `EndorseFlowMod`, `LogDetection`, `UpdateTrust`,
`CommitModelHash`, `VerifyModelHash`, `SubmitAlert`, `LiftQuarantine`,
`MarkFlowModUnauthorized`) must be run with Org1's identity/peer
addresses. Query calls (`peer chaincode query`) can use either org.

### Option B: actually rename the orgs in test-network config

More correct-looking long-term but requires regenerating crypto material
/ `configtx.yaml` / `core.yaml` references — not worth it for Phase 2.
Defer until a real multi-RSU network topology is built (see PHASES.md
Phase 3+ and the SUMO/N-RSU migration noted in chat history), at which
point the org structure will be redesigned anyway (single RSUOrg with
many per-RSU client identities via `fabric-ca-client register`).

**This codebase ships with Option A as the default** (`Org1MSP` /
`Org2MSP` in `types.go`) so it runs against your existing test-network
unmodified. Update the constants only when you actually redo the network
topology.

## Endorsement policy

Chaincode-level Fabric endorsement policy (set at `approveformyorg` /
`commit` time, same as the `basic` sample):

```
OR('Org1MSP.peer','Org2MSP.peer')
```

This is intentionally loose — it governs "is this transaction valid to
commit", not the report's application-level f+1 / 2f+1 quorums (Eq
3.41/3.48, Eq 3.24), which are tracked inside asset state
(`Endorsements[]`, `Alerts[]`) and enforced by chaincode Go logic
regardless of how many Fabric peers endorsed the underlying transaction.

Note: with this loose policy, an Org2 (ControllerOrg) peer could
technically endorse a write transaction at the Fabric level — but
`requireRSU()` rejects the call chaincode-side (`cid.GetMSPID() !=
"Org1MSP"`) before any state mutation, so the transaction will fail
regardless.

## Build & deploy commands (run from `fabric-samples/test-network`)

```bash
# Package
peer lifecycle chaincode package mobiguard-cc.tar.gz \
  --path ../../mobiguard-cc --lang golang --label mobiguard-cc_1.0

# Install on both peers (set CORE_PEER_* env vars for Org1, then Org2,
# as in the basic-sample workflow)
peer lifecycle chaincode install mobiguard-cc.tar.gz

# Get package ID
peer lifecycle chaincode queryinstalled

# Approve for each org
peer lifecycle chaincode approveformyorg -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com --tls \
  --cafile "$ORDERER_CA" --channelID mychannel --name mobiguard-cc \
  --version 1.0 --package-id <PACKAGE_ID> --sequence 1 \
  --signature-policy "OR('Org1MSP.peer','Org2MSP.peer')"

# Commit (after both orgs approve)
peer lifecycle chaincode commit -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com --tls \
  --cafile "$ORDERER_CA" --channelID mychannel --name mobiguard-cc \
  --version 1.0 --sequence 1 \
  --signature-policy "OR('Org1MSP.peer','Org2MSP.peer')" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA"
```

Remember the Phase 1 gotcha: every `invoke` (not `query`) needs
`--peerAddresses`/`--tlsRootCertFiles` for BOTH peers per the 2-of-2
... well, the chaincode endorsement policy here is `OR`, not `AND`, so
**this particular gotcha from Phase 1 (the `basic` sample's 2-of-2
policy) does NOT apply to mobiguard-cc** — a single peer's endorsement
satisfies `OR('Org1MSP.peer','Org2MSP.peer')`. You can invoke with just
one `--peerAddresses`/`--tlsRootCertFiles` pair (matching the calling
org, since `requireRSU`/`requireKnownOrg` check identity, not which peer
endorsed).

## Running as Org1 vs Org2

Use the same `CORE_PEER_*` env-var switching pattern as in the `basic`
sample walkthrough:

```bash
# Org1 (RSUOrg) — for write calls
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Org2 (ControllerOrg) — for query calls
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051
```

## Second Org1 identity (required for FlowMod endorsement quorum testing)

`EndorseFlowMod` derives the endorsing RSU's identity from
`cid.GetID()` (an X.509-DN-based string unique per enrolled identity).
To test the `flowModEndorsementQuorum` (f+1=2) path — i.e. two distinct
RSU endorsements on the same FlowMod — you need a **second enrolled
identity under Org1's CA**, since `EndorseFlowMod` rejects a repeat
endorsement from the same identity.

Using Org1's CA (already running per Phase 1):

```bash
# From fabric-samples/test-network, with Org1 CA env vars set
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com

fabric-ca-client register --caname ca-org1 \
  --id.name rsu02 --id.secret rsu02pw --id.type client \
  --tls.certfiles "${PWD}/organizations/fabric-ca/org1/ca-cert.pem"

fabric-ca-client enroll -u https://rsu02:rsu02pw@localhost:7054 \
  --caname ca-org1 \
  -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/rsu02@org1.example.com/msp" \
  --tls.certfiles "${PWD}/organizations/fabric-ca/org1/ca-cert.pem"

# Copy the NodeOUs config so the new identity is recognized as a client
cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" \
   "${PWD}/organizations/peerOrganizations/org1.example.com/users/rsu02@org1.example.com/msp/config.yaml"
```

Then for the second endorsement, set:

```bash
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/rsu02@org1.example.com/msp
```

(other Org1 env vars — `CORE_PEER_LOCALMSPID`, `CORE_PEER_TLS_ROOTCERT_FILE`,
`CORE_PEER_ADDRESS` — stay the same) and re-invoke `EndorseFlowMod`.

This mirrors the real Phase 3+ migration (one RSUOrg, many per-RSU
client identities) — `rsu02` here is effectively "RSU #2" for testing
purposes.

## Discovering your own identity string (`GetMyIdentity`)

`EndorseFlowMod`, `CommitModelHash`, and `VerifyModelHash` key off the
caller's `cid.GetID()` string, which is a long X.509-DN-based value
(e.g. `x509::CN=admin,OU=client...::CN=ca.org1.example.com,...`). Rather
than parsing or hardcoding this, call the read-only `GetMyIdentity`
function as the relevant identity to retrieve it:

```bash
peer chaincode query -C mychannel -n mobiguard-cc -c '{"function":"GetMyIdentity","Args":[]}'
# => {"id":"x509::CN=admin,OU=client+OU=...::CN=ca.org1.example.com,...","mspId":"Org1MSP"}
```

Use the returned `id` value as the `rsuId` argument to
`VerifyModelHash` / `GetModelHash` after that same identity has called
`CommitModelHash`. The Node.js bridge (Phase 4) should call
`GetMyIdentity` once at startup per RSU process and cache the result.
