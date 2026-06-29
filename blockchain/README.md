# MOBIGUARD — Hyperledger Fabric Integration

Blockchain audit-trail layer for the MOBIGUARD SDVN security framework
(ns-3 simulation in `routing.cc`, ~143k lines, `architecture=3`).

See `SPEC.md` for the chaincode schema and equation mappings from the
project report. See `PHASES.md` for status / next steps.

## Prerequisites (versions verified working)

- Ubuntu 22.04
- Docker 29.x + Compose plugin v5.x
- Go 1.23.4 (Fabric requires 1.21+)
- Node.js 22.x / npm 10.x
- Hyperledger Fabric 2.5.15, Fabric CA 1.5.17
- jq, git, curl

## Setting up the Fabric test network (Phase 1)

This regenerates everything under `fabric-samples/` — not committed to git.

```bash
mkdir -p ~/mobiguard-blockchain && cd ~/mobiguard-blockchain
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh -o install-fabric.sh
chmod +x install-fabric.sh
./install-fabric.sh docker binary 2.5.15 1.5.15   # samples already cloned if repo exists

cd fabric-samples/test-network
./network.sh up createChannel -c mychannel -ca -s couchdb
```

### Known issue: peer exits with CouchDB 401 on cold start

Occasionally `peer0.org1` or `peer0.org2` exits with:
```
panic: Error in instantiating ledger provider: error handling CouchDB
request. Error:unauthorized, Status Code:401
```
This is a startup race between the peer and CouchDB's auth init — not a
credential mismatch. Fix:
```bash
docker start peer0.orgN.example.com
sleep 10
# then manually join the channel for that org (see scripts/join-peer.sh)
```

### Endorsement policy reminder

The default channel policy requires **2-of-2 org endorsements**. Every
`peer chaincode invoke` (and every chaincode call from the bridge) must
collect endorsements from both peers:
```
--peerAddresses localhost:7051 --tlsRootCertFiles <org1 tls ca>
--peerAddresses localhost:9051 --tlsRootCertFiles <org2 tls ca>
```
Without this, `invoke` returns status 200 but the transaction is committed
as **INVALID** — reads will silently show no data.

## Project layout

```
mobiguard-cc/      Go chaincode — six asset types (see SPEC.md)
bridge/            Node.js bridge (fabric-gateway) — tails ns-3 CSV output,
                   submits chaincode transactions
ns3-routing/       Relevant ns-3 source files (routing.cc excerpts,
                   tcam_attack_helper.h) — NOT the full ns-3 tree
scripts/           Helper scripts (deploy chaincode, join peers, etc.)
```

## ns-3 environment

- ns-3 3.35 at `~/ns-allinone-3.35/ns-3.35` (separate tree, not in this repo)
- `routing_test=1 --active_attack_variant=-1` is the clean baseline
  (PDR=100%) used for end-to-end bridge validation
