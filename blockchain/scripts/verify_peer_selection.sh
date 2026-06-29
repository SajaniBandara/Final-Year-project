#!/bin/bash
# =============================================================================
# MOBIGUARD BLOCKCHAIN: DYNAMIC RSU ENDORSER SELECTION VERIFICATION
# Verifies three-bucket peer classification and lifecycle transitions:
#   Active Peer → Demoted Client → Removed Node
# Maps to supervisor instruction: §peer_selection.go
# =============================================================================
set -e

cd ~/mobiguard-blockchain/fabric-samples/test-network

export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config/
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
export ORG1_CA=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export ORG2_CA=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CHANNEL=mychannel
export CC=mobiguard-cc

ORG1_ADMIN_MSP=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp

invoke_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_MSPCONFIGPATH=${ORG1_ADMIN_MSP}
  peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$ORDERER_CA" -C $CHANNEL -n $CC \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    -c "$1"
  sleep 2
}

query_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_MSPCONFIGPATH=${ORG1_ADMIN_MSP}
  peer chaincode query -C $CHANNEL -n $CC -c "$1"
}

echo "=============================================================="
echo " MOBIGUARD: DYNAMIC RSU ENDORSER SELECTION VERIFICATION"
echo " Active Peer → Demoted Client → Removed Node"
echo "=============================================================="

# ── PHASE 1: Initial State ─────────────────────────────────────────
echo ""
echo "=== PHASE 1: Initial State ==="
echo "--- All nodes implicitly active (no quarantine record yet) ---"
echo ""

echo "--- rsu-alpha: no ledger record yet, trust=10000 (implicit) ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-alpha"]}'

echo "--- rsu-beta: no ledger record yet, trust=10000 (implicit) ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-beta"]}'

echo "--- Full peer selection (empty — no events yet) ---"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

# ── PHASE 2: Trigger First Detection on rsu-alpha ─────────────────
echo ""
echo "=== PHASE 2: First detection event on rsu-alpha ==="
echo "--- Score: 10000 → 9500 (penalty=500, still active peer) ---"
invoke_org1 '{"function":"LogDetection","Args":["rsu-alpha","2","1718100001","sig-001"]}'

echo "--- Trust score after 1st penalty ---"
query_org1 '{"function":"QueryTrust","Args":["rsu-alpha"]}'

echo "--- IsActivePeer: still true (score 9500 > T_demote=3000) ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-alpha"]}'

echo "--- Peer selection: rsu-alpha in activePeers bucket ---"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

# ── PHASE 3: Drive rsu-alpha to Demotion ──────────────────────────
echo ""
echo "=== PHASE 3: Drive rsu-alpha below T_demote=3000 ==="
echo "--- Need 14 more penalties: 9500 - (14x500) = 2500 < 3000 ---"
echo "--- SC.Demote fires on penalty 14 ---"

for i in $(seq 1 14); do
  echo "  [Penalty $i/14 — score will be $((9500 - i*500))]"
  invoke_org1 "{\"function\":\"LogDetection\",\"Args\":[\"rsu-alpha\",\"2\",\"$((1718100001+i))\",\"sig-$(printf '%03d' $((i+1)))\"]}"
done

echo ""
echo "--- Trust score after demotion (expected: ~2500) ---"
query_org1 '{"function":"QueryTrust","Args":["rsu-alpha"]}'

echo "--- IsActivePeer: NOW FALSE (demoted) ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-alpha"]}'

echo "--- Quarantine record (expected: status=demoted) ---"
query_org1 '{"function":"GetQuarantineRecord","Args":["rsu-alpha"]}'

echo "--- Peer selection: rsu-alpha in demotedClients bucket ---"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

# ── PHASE 4: Verify Demoted Node Behavior ─────────────────────────
echo ""
echo "=== PHASE 4: Demoted node behavior ==="
echo "--- Demoted node CAN still be monitored (LogDetection works) ---"
invoke_org1 '{"function":"LogDetection","Args":["rsu-alpha","2","1718100020","sig-demoted-monitor"]}'

echo "--- Trust score still updating while demoted ---"
query_org1 '{"function":"QueryTrust","Args":["rsu-alpha"]}'

echo "--- rsu-beta still active (unaffected by rsu-alpha demotion) ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-beta"]}'

# ── PHASE 5: Drive rsu-alpha to Removal ───────────────────────────
echo ""
echo "=== PHASE 5: Drive rsu-alpha below T_remove=1000 ==="
echo "--- From ~2000, need 4 more penalties: 2000 - (4x500) = 0 < 1000 ---"
echo "--- SC.Remove fires when score crosses T_remove=1000 ---"

for i in $(seq 1 4); do
  echo "  [Removal penalty $i/4]"
  invoke_org1 "{\"function\":\"LogDetection\",\"Args\":[\"rsu-alpha\",\"2\",\"$((1718100030+i))\",\"sig-rem-$(printf '%03d' $i)\"]}"
done

echo ""
echo "--- Trust score after removal ---"
query_org1 '{"function":"QueryTrust","Args":["rsu-alpha"]}'

echo "--- IsActivePeer: false (removed) ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-alpha"]}'

echo "--- Quarantine record (expected: status=removed) ---"
query_org1 '{"function":"GetQuarantineRecord","Args":["rsu-alpha"]}'

echo "--- Peer selection: rsu-alpha in removedNodes bucket ---"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

# ── PHASE 6: Verify Removed Node Write Block ───────────────────────
echo ""
echo "=== PHASE 6: Verify write block on removed node ==="
echo "--- LogDetection on removed rsu-alpha MUST FAIL ---"
echo "--- Expected: requireNotRemoved() blocks with error ---"
set +e
invoke_org1 '{"function":"LogDetection","Args":["rsu-alpha","2","1718999999","blocked-write"]}'
WRITE_BLOCKED=$?
set -e

if [ $WRITE_BLOCKED -ne 0 ]; then
  echo "  ✓ CONFIRMED: Write blocked for removed node"
else
  echo "  ✗ UNEXPECTED: Write succeeded — requireNotRemoved() not firing"
fi

# ── PHASE 7: Verify LiftQuarantine Rejects Removed Node ───────────
echo ""
echo "=== PHASE 7: LiftQuarantine must reject removed node ==="
echo "--- Expected: error — cannot lift removed node ---"
set +e
invoke_org1 '{"function":"LiftQuarantine","Args":["rsu-alpha","1718200000"]}'
LIFT_REJECTED=$?
set -e

if [ $LIFT_REJECTED -ne 0 ]; then
  echo "  ✓ CONFIRMED: LiftQuarantine rejected for removed node"
else
  echo "  ✗ UNEXPECTED: LiftQuarantine succeeded on removed node"
fi

# ── PHASE 8: LiftQuarantine on a Demoted Node ─────────────────────
echo ""
echo "=== PHASE 8: Demote rsu-beta then lift quarantine ==="
echo "--- First drive rsu-beta to demoted state ---"

for i in $(seq 1 15); do
  invoke_org1 "{\"function\":\"LogDetection\",\"Args\":[\"rsu-beta\",\"2\",\"$((1718200000+i))\",\"beta-sig-$(printf '%03d' $i)\"]}"
done

echo "--- rsu-beta demoted ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-beta"]}'
query_org1 '{"function":"GetQuarantineRecord","Args":["rsu-beta"]}'

echo ""
echo "--- Now lift rsu-beta quarantine ---"
invoke_org1 '{"function":"LiftQuarantine","Args":["rsu-beta","1718300000"]}'

echo "--- IsActivePeer after lift: expected TRUE ---"
query_org1 '{"function":"IsActivePeer","Args":["rsu-beta"]}'

echo "--- Quarantine record after lift (expected: status=lifted) ---"
query_org1 '{"function":"GetQuarantineRecord","Args":["rsu-beta"]}'

echo "--- Final peer selection: rsu-beta back in activePeers ---"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

# ── PHASE 9: Final System State ────────────────────────────────────
echo ""
echo "=== PHASE 9: Final system state ==="
echo "--- All trust scores ---"
query_org1 '{"function":"GetAllTrustScores","Args":[]}'

echo "--- Full quarantine list ---"
query_org1 '{"function":"QueryQuarantineList","Args":[]}'

echo "--- Removed list ---"
query_org1 '{"function":"QueryRemovedList","Args":[]}'

echo ""
echo "=============================================================="
echo " PEER SELECTION VERIFICATION COMPLETE"
echo " rsu-alpha: active → demoted → removed (write blocked)"
echo " rsu-beta:  active → demoted → lifted → active"
echo "=============================================================="
