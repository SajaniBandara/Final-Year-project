#!/bin/bash
# chmod +x ~/mobiguard-blockchain/scripts/verify_failover.sh
# ~/mobiguard-blockchain/scripts/verify_failover.sh 2>&1 | tee ~/mobiguard-blockchain/failover_verification.log
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

# Org1 Admin MSP path (used throughout as default)
ORG1_ADMIN_MSP=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
ORG1_USER1_MSP=${PWD}/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp

invoke_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_MSPCONFIGPATH=$1
  # Both peers required so the transaction meets the endorsement policy
  # and actually commits to the ledger (a single-peer proposal returns
  # status:200 but never reaches ordering/commit).
  peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$ORDERER_CA" -C $CHANNEL -n $CC \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA" \
    -c "$2"
  local peer_rc=$?
  sleep 2
  return $peer_rc
}

# invoke_org1_idempotent: like invoke_org1 but treats "already registered"
# errors as success — safe to re-run on a live ledger.
invoke_org1_idempotent() {
  local msp=$1
  local payload=$2
  local label=$3
  set +e
  out=$(invoke_org1 "$msp" "$payload" 2>&1)
  rc=$?
  set -e
  if [ $rc -ne 0 ]; then
    if echo "$out" | grep -q "already registered"; then
      echo "  [SKIP] $label already registered — continuing"
    else
      echo "$out" >&2
      return $rc
    fi
  else
    echo "$out"
  fi
}

query_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_ADDRESS=localhost:7051
  export CORE_PEER_MSPCONFIGPATH=${ORG1_ADMIN_MSP}
  peer chaincode query -C $CHANNEL -n $CC -c "$1"
}

echo "=============================================================="
echo " MOBIGUARD BLOCKCHAIN: CONTROLLER FAILOVER VERIFICATION"
echo " §3.4.11 Eq 3.49-3.53"
echo "=============================================================="

# ── PRE-STEP: Ensure controllers are registered ─────────────────────
echo ""
echo "=== PRE-STEP: Register ctrl-A and ctrl-B (skip if exists) ==="
invoke_org1_idempotent $ORG1_ADMIN_MSP \
  '{"function":"RegisterController","Args":["ctrl-A","6.9271","79.8612","1718020000"]}' \
  "ctrl-A"
invoke_org1_idempotent $ORG1_ADMIN_MSP \
  '{"function":"RegisterController","Args":["ctrl-B","7.2906","80.6337","1718020001"]}' \
  "ctrl-B"

# ── STEP 1: Register RSUs ────────────────────────────────────────────
echo ""
echo "=== STEP 1: Register RSU-X and RSU-Y (skip if exists) ==="
invoke_org1_idempotent $ORG1_ADMIN_MSP \
  '{"function":"RegisterRSU","Args":["rsu-X","6.9500","79.8700","1718020002"]}' \
  "rsu-X"
invoke_org1_idempotent $ORG1_ADMIN_MSP \
  '{"function":"RegisterRSU","Args":["rsu-Y","7.2500","80.6000","1718020003"]}' \
  "rsu-Y"

echo ""
echo "=== STEP 2: Auto-assign RSUs to nearest trusted controller ==="
echo "--- rsu-X (Colombo) → should assign to ctrl-A ---"
invoke_org1 $ORG1_ADMIN_MSP \
  '{"function":"AutoAssignController","Args":["rsu-X","1718020004"]}'
echo "--- rsu-Y (Kandy) → should assign to ctrl-B ---"
invoke_org1 $ORG1_ADMIN_MSP \
  '{"function":"AutoAssignController","Args":["rsu-Y","1718020005"]}'

echo ""
echo "=== STEP 3: Verify initial assignments (Eq 3.51) ==="
query_org1 '{"function":"GetAllAssignments","Args":[]}'

echo ""
echo "=== STEP 4: Verify initial trusted set (Eq 3.49) ==="
echo "--- Expected: ctrl-A and ctrl-B both trusted, score=10000 ---"
query_org1 '{"function":"GetTrustedControllers","Args":[]}'

# ── STEP 5: Submit conflict evidence — quorum path ─────────────────
echo ""
echo "=== STEP 5: Submit conflict evidence against ctrl-A ==="
echo "--- Report 1 of 2 (Admin identity) ---"
invoke_org1 $ORG1_ADMIN_MSP \
  '{"function":"SubmitConflictEvidence","Args":["ctrl-A","flowhash-malicious-001","1718020100"]}'

echo "--- Conflict count after report 1 (quorum not reached yet) ---"
query_org1 '{"function":"GetConflictEvidenceCount","Args":["ctrl-A"]}'
query_org1 '{"function":"GetControllerStatus","Args":["ctrl-A"]}'

echo "--- Report 2 of 2 (User1 identity — different RSU, satisfies f+1=2 quorum) ---"
invoke_org1 $ORG1_USER1_MSP \
  '{"function":"SubmitConflictEvidence","Args":["ctrl-A","flowhash-malicious-001","1718020101"]}'

echo "--- Conflict count after report 2 (quorum reached, penalty fired: 10000→9500) ---"
query_org1 '{"function":"GetConflictEvidenceCount","Args":["ctrl-A"]}'
query_org1 '{"function":"GetControllerStatus","Args":["ctrl-A"]}'

# ── STEP 6: Drive trust below T_ctrl_min=3000 ─────────────────────
echo ""
echo "=== STEP 6: Apply 15 trust penalties (9500 → 2500, below T_ctrl_min=3000) ==="
echo "--- SC.Revoke (Eq 3.52) fires on penalty 15 ---"
for i in {1..15}; do
  echo "  [Penalty $i/15 — score will be $((9500 - i*500))]"
  invoke_org1 $ORG1_ADMIN_MSP \
    '{"function":"UpdateControllerTrust","Args":["ctrl-A","false","1718020200"]}'
done

# ── STEP 7: Verify failover ────────────────────────────────────────
echo ""
echo "=== STEP 7: Verify trusted controller set post-failover (Eq 3.49) ==="
echo "--- Expected: only ctrl-B remains ---"
query_org1 '{"function":"GetTrustedControllers","Args":[]}'

echo ""
echo "=== STEP 8: Verify ctrl-A is revoked (Eq 3.52) ==="
query_org1 '{"function":"GetControllerStatus","Args":["ctrl-A"]}'

echo ""
echo "=== STEP 9: Verify RSU reassignment after failover (Eq 3.53) ==="
echo "--- Expected: rsu-X reassigned from ctrl-A → ctrl-B ---"
query_org1 '{"function":"GetAllAssignments","Args":[]}'

echo ""
echo "=== STEP 10: Full controller audit ==="
query_org1 '{"function":"GetAllControllers","Args":[]}'

echo ""
echo "=============================================================="
echo " VERIFICATION COMPLETE"
echo "=============================================================="