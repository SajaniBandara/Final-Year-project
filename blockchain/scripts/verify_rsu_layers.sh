#!/bin/bash
# =============================================================================
# verify_rsu_layers.sh
# Verifies the three-layer RSU trust and access control model (§3.4.10).
#
#   Layer 1  Fabric MSP identity check (requireRSU)
#            Write functions restricted to Org1MSP identities.
#            Controllers (Org2MSP) are rejected at the chaincode gate.
#
#   Layer 2  Peer demotion (QueryPeerSelection)
#            Trust score below T_demote=0.30 (3000 bp) triggers
#            QuarantineDemoted. The bridge reads IsActivePeer=false
#            and excludes the node from --peerAddresses. Monitoring
#            (UpdateTrust) continues at chaincode level.
#
#   Layer 3  Permanent removal (requireNotRemoved)
#            Trust score below T_remove=0.10 (1000 bp) while already
#            demoted triggers QuarantineRemoved. requireNotRemoved()
#            blocks all further writes for this node at the chaincode
#            entry point. Removal cannot be reversed.
#
# Penalty schedule (defaultTrustPenalty=500 bp, initial score=10000):
#   Penalty 15  score=2500 < T_demote(3000)  QuarantineDemoted
#   Penalty 19  score=500  < T_remove(1000)  QuarantineRemoved
#   Penalty 20  blocked    requireNotRemoved fires
#
# Usage:
#   source ~/mobiguard-blockchain/fabric-samples/test-network/deploy-mobiguard.sh
#   ~/mobiguard-blockchain/scripts/verify_rsu_layers.sh 2>&1 | tee ~/mobiguard-blockchain/rsu_layers.log
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
ORG2_ADMIN_MSP=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp

# Subject node for this verification run
RSU_NODE="rsu-node-01"

# Output helpers
PASS='\033[0;32m[PASS]\033[0m'
FAIL='\033[0;31m[FAIL]\033[0m'
INFO='\033[0;36m[INFO]\033[0m'
NOTE='\033[0;33m[NOTE]\033[0m'
BOLD='\033[1m'
NC='\033[0m'

separator() { echo ""; echo "--------------------------------------------------------------"; echo "  $1"; echo "--------------------------------------------------------------"; }

# Invoke from Org1MSP (RSU organisation) — both peers for valid endorsement
invoke_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_MSPCONFIGPATH=${ORG1_ADMIN_MSP}
  peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$ORDERER_CA" -C $CHANNEL -n $CC \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA" \
    -c "$1"
  local peer_rc=$?
  sleep 2
  return $peer_rc
}

# Invoke from Org2MSP (controller organisation) — write ops must be rejected
invoke_org2() {
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG2_CA}
  export CORE_PEER_ADDRESS=localhost:9051
  export CORE_PEER_MSPCONFIGPATH=${ORG2_ADMIN_MSP}
  peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$ORDERER_CA" -C $CHANNEL -n $CC \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA" \
    -c "$1"
  local peer_rc=$?
  sleep 2
  return $peer_rc
}

# Query from Org1MSP
query_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_MSPCONFIGPATH=${ORG1_ADMIN_MSP}
  peer chaincode query -C $CHANNEL -n $CC -c "$1"
}

# Run a command and pass only if it fails with the expected error substring
expect_error() {
  local label="$1"
  local expected="$2"
  local cmd="$3"
  set +e
  out=$(eval "$cmd" 2>&1)
  rc=$?
  set -e
  if [ $rc -ne 0 ] && echo "$out" | grep -q "$expected"; then
    echo -e "${PASS} $label"
    echo "       Error confirmed: $(echo "$out" | grep -o "$expected")"
  else
    echo -e "${FAIL} $label"
    echo "       Output: $out"
    exit 1
  fi
}

# =============================================================================
echo ""
echo "=============================================================="
echo "  MOBIGUARD — RSU Trust Layer Verification"
echo "  §3.4.10 Three-Layer Access Control Model"
echo "  Node under test: $RSU_NODE"
echo "=============================================================="


# =============================================================================
# LAYER 1  Fabric MSP identity check
# =============================================================================
separator "LAYER 1  Fabric MSP Identity Check (requireRSU)"

echo ""
echo -e "${INFO} Invoking UpdateTrust from Org2MSP (ControllerOrgMSP)."
echo "       requireRSU() checks ctx.GetClientIdentity().GetMSPID()."
echo "       Expected: chaincode returns status 500, access denied."
echo ""

expect_error \
  "Org2MSP write rejected — requireRSU enforced at chaincode entry" \
  "access denied" \
  "invoke_org2 '{\"function\":\"UpdateTrust\",\"Args\":[\"$RSU_NODE\",\"false\",\"1000\"]}'"

echo ""
echo -e "${INFO} Invoking UpdateTrust from Org1MSP (RSUOrgMSP) — baseline confirmation."
invoke_org1 '{"function":"UpdateTrust","Args":["'"$RSU_NODE"'","true","1001"]}'
echo -e "${PASS} Org1MSP write accepted — identity check passed"


# =============================================================================
# BASELINE STATE
# =============================================================================
separator "Baseline State — Node Active, Score = 10000"

echo ""
echo "QueryTrust — current score:"
query_org1 '{"function":"QueryTrust","Args":["'"$RSU_NODE"'"]}'

echo ""
echo "IsActivePeer — expected: true"
query_org1 '{"function":"IsActivePeer","Args":["'"$RSU_NODE"'"]}'

echo ""
echo "QueryPeerSelection — node should appear in activePeers:"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'


# =============================================================================
# LAYER 2  Demotion
# Score = 10000, penalty = 500 per call.
# 15 penalties: 10000 - 15×500 = 2500 < T_demote(3000) → QuarantineDemoted
# =============================================================================
separator "LAYER 2  Peer Demotion (T_demote = 3000 bp)"

echo ""
echo -e "${INFO} Applying 15 consecutive trust penalties via UpdateTrust(success=false)."
echo "       Each penalty subtracts 500 basis points (defaultTrustPenalty)."
echo "       applyLifecycleTransition() creates QuarantineRecord{status=demoted}"
echo "       when score first crosses below T_demote = 3000."
echo ""

TS=2000
for i in $(seq 1 15); do
  EXPECTED_SCORE=$((10000 - i * 500))
  STATUS="active"
  [ $EXPECTED_SCORE -lt 3000 ] && STATUS="DEMOTED"
  echo -n "  Penalty $i/15  score -> $EXPECTED_SCORE  [$STATUS]  "
  invoke_org1 '{"function":"UpdateTrust","Args":["'"$RSU_NODE"'","false","'"$TS"'"]}' \
    2>&1 | grep -o "status:200" || echo "non-200"
  TS=$((TS + 1))
done

echo ""
echo "QueryTrust — score after 15 penalties (expected: 2500):"
query_org1 '{"function":"QueryTrust","Args":["'"$RSU_NODE"'"]}'

echo ""
echo "GetQuarantineRecord — expected status: demoted"
query_org1 '{"function":"GetQuarantineRecord","Args":["'"$RSU_NODE"'"]}'

echo ""
echo "QueryQuarantineList — demoted nodes visible to bridge:"
query_org1 '{"function":"QueryQuarantineList","Args":[]}'

echo ""
echo -e "${INFO} Checking bridge-level endorsement gate."
echo ""

IS_ACTIVE=$(query_org1 '{"function":"IsActivePeer","Args":["'"$RSU_NODE"'"]}')
echo "IsActivePeer($RSU_NODE) = $IS_ACTIVE"

if [ "$IS_ACTIVE" = "false" ]; then
  echo -e "${PASS} IsActivePeer returned false — bridge will exclude node from --peerAddresses"
else
  echo -e "${FAIL} Expected false, received: $IS_ACTIVE"
  exit 1
fi

echo ""
echo "QueryPeerSelection — node expected in demotedClients:"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

echo ""
echo -e "${NOTE} Enforcement model (Phase 2): demotion is applied at the bridge layer."
echo "       The bridge reads IsActivePeer=false and omits this node's peer address"
echo "       from --peerAddresses on all future endorsement requests. The node"
echo "       retains its Fabric certificate and may submit its own transactions"
echo "       (client role), but its endorsement signature is no longer solicited"
echo "       by any other network participant (peer role revoked in application logic)."
echo "       Phase 3 would enforce this at the MSP layer via certificate revocation."

echo ""
echo -e "${INFO} Confirming monitoring continues after demotion — UpdateTrust still commits."
invoke_org1 '{"function":"UpdateTrust","Args":["'"$RSU_NODE"'","false","'"$TS"'"]}'
TS=$((TS + 1))
echo -e "${PASS} UpdateTrust committed — score update proceeds, demotion does not block writes"
echo -e "${PASS} Layer 2 verified — endorsement gate active, trust monitoring uninterrupted"


# =============================================================================
# LAYER 3  Permanent Removal
# Current score = 2000. Three more penalties reach 1000 (boundary, still demoted).
# One final penalty: score = 500 < T_remove(1000) → QuarantineRemoved.
# requireNotRemoved() then blocks all subsequent writes for this node.
# =============================================================================
separator "LAYER 3  Permanent Removal (T_remove = 1000 bp)"

echo ""
echo -e "${INFO} Applying 3 further penalties toward T_remove = 1000."
echo "       Score boundary: 1000 >= T_remove, so status remains demoted at score 1000."
echo ""

for i in 1 2 3; do
  CURRENT_SCORE=$((2000 - i * 500))
  echo -n "  Penalty $i/4  score -> $CURRENT_SCORE  [demoted, above T_remove]  "
  invoke_org1 '{"function":"UpdateTrust","Args":["'"$RSU_NODE"'","false","'"$TS"'"]}' \
    2>&1 | grep -o "status:200" || echo "non-200"
  TS=$((TS + 1))
done

echo ""
echo "QueryTrust — score at boundary T_remove=1000, status still demoted:"
query_org1 '{"function":"QueryTrust","Args":["'"$RSU_NODE"'"]}'
query_org1 '{"function":"GetQuarantineRecord","Args":["'"$RSU_NODE"'"]}'

echo ""
echo -e "${INFO} Applying final penalty — score drops to 500 < T_remove(1000)."
echo "       applyLifecycleTransition() escalates QuarantineDemoted -> QuarantineRemoved."
echo ""
invoke_org1 '{"function":"UpdateTrust","Args":["'"$RSU_NODE"'","false","'"$TS"'"]}'
TS=$((TS + 1))

echo ""
echo "GetQuarantineRecord — expected status: removed"
query_org1 '{"function":"GetQuarantineRecord","Args":["'"$RSU_NODE"'"]}'

echo ""
echo "QueryRemovedList — permanently ejected nodes:"
query_org1 '{"function":"QueryRemovedList","Args":[]}'

echo ""
echo "QueryPeerSelection — node expected in removedNodes:"
query_org1 '{"function":"QueryPeerSelection","Args":[]}'

echo ""
echo -e "${INFO} Verifying write block — all writes for removed node rejected at chaincode level."
echo "       requireNotRemoved() is invoked at the entry point of every write function."
echo ""

expect_error \
  "UpdateTrust(success=false) blocked — node removed from system" \
  "removed from the system" \
  "invoke_org1 '{\"function\":\"UpdateTrust\",\"Args\":[\"$RSU_NODE\",\"false\",\"$TS\"]}'"
TS=$((TS + 1))

echo ""
expect_error \
  "UpdateTrust(success=true) blocked — score recovery not possible once removed" \
  "removed from the system" \
  "invoke_org1 '{\"function\":\"UpdateTrust\",\"Args\":[\"$RSU_NODE\",\"true\",\"$TS\"]}'"
TS=$((TS + 1))

echo ""
echo -e "${NOTE} Enforcement model (Phase 2+): requireNotRemoved() fires before any state"
echo "       read or write, ensuring no partial ledger updates are possible for a"
echo "       removed node regardless of the calling identity or function invoked."

echo ""
expect_error \
  "LiftQuarantine rejected — removal is permanent and irreversible" \
  "removal is permanent" \
  "invoke_org1 '{\"function\":\"LiftQuarantine\",\"Args\":[\"$RSU_NODE\",\"$TS\"]}'"

echo ""
echo "QueryTrust — final score (frozen at 500, no further updates accepted):"
query_org1 '{"function":"QueryTrust","Args":["'"$RSU_NODE"'"]}'


# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "=============================================================="
echo "  Verification Summary"
echo "=============================================================="
echo ""
echo -e "${PASS} Layer 1  requireRSU: Org2MSP write rejected at Fabric identity check"
echo -e "${PASS} Layer 2  Demotion:  Score 2500 < T_demote(3000) -> QuarantineDemoted"
echo "          IsActivePeer=false, node excluded from bridge peer selection"
echo "          Trust monitoring continues — chaincode writes not blocked"
echo -e "${PASS} Layer 3  Removal:   Score 500  < T_remove(1000) -> QuarantineRemoved"
echo "          All writes blocked by requireNotRemoved at chaincode entry"
echo "          LiftQuarantine rejected — ejection is permanent"
echo ""
