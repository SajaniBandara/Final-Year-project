#!/bin/bash
# test_synthetic.sh -- Phase 2 synthetic invocation walkthrough for
# mobiguard-cc, run from fabric-samples/test-network after deployment.
#
# Exercises all six asset types plus cross-asset triggers, including
# the supervisor's three-state peer lifecycle (active->demoted->removed).
#
# Prerequisites: see DEPLOY.md (enroll rsu02 under Org1 CA for FlowMod
# quorum test). Run from the test-network directory.

set -e

echo "Warming up chaincode (cold start ~5s)..."
sleep 8

CHANNEL=mychannel
CC=mobiguard-cc
ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
ORG1_CA=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
ORG2_CA=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt

as_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
  export CORE_PEER_ADDRESS=localhost:7051
}

as_org1_rsu2() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/rsu02@org1.example.com/msp
  export CORE_PEER_ADDRESS=localhost:7051
}

as_org2() {
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG2_CA}
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
  export CORE_PEER_ADDRESS=localhost:9051
}

invoke() {
  peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$ORDERER_CA" -C "$CHANNEL" -n "$CC" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA" \
    -c "{\"function\":\"$1\",\"Args\":$2}"
  sleep 3
}

query() {
  peer chaincode query -C "$CHANNEL" -n "$CC" -c "{\"function\":\"$1\",\"Args\":$2}"
  echo
}

# =========================================================================
echo "=== 1. FlowMod: log -> 2 endorsements -> committed (f+1=2 quorum) ==="
# =========================================================================
as_org1
invoke LogFlowMod '["flowhash-002","1718000000"]'
query GetFlowMod '["flowhash-002"]'            # status: pending, 0 endorsements

invoke EndorseFlowMod '["flowhash-002"]'       # 1st endorsement (Admin identity)
query GetFlowMod '["flowhash-002"]'            # status: pending, 1 endorsement

as_org1_rsu2
invoke EndorseFlowMod '["flowhash-002"]'       # 2nd endorsement (rsu02 identity)
as_org1
query GetFlowMod '["flowhash-002"]'            # status: committed, 2 endorsements

# =========================================================================
echo
echo "=== 2. FlowMod: unauthorized check on never-logged hash ==="
# =========================================================================
as_org2
query QueryUnauthorizedFlowMod '["flowhash-never-logged-002"]'   # expect: true
query QueryUnauthorizedFlowMod '["flowhash-002"]'            # expect: false (committed)

# =========================================================================
echo
echo "=== 3. Detection event (S2) + trust penalty side-effect ==="
# =========================================================================
as_org2
query QueryTrust '["vehicle-43"]'   # expect: 10000 (initial, no record yet)
as_org1
query IsActivePeer '["vehicle-43"]' # expect: true

as_org1
invoke LogDetection '["vehicle-43","2","1718000100","sig-placeholder"]'

as_org2
query QueryTrust '["vehicle-43"]'   # expect: 9500 (10000 - 500 penalty)
query IsActivePeer '["vehicle-43"]' # expect: true (9500 > T_demote=3000)

# =========================================================================
echo
echo "=== 4. Three-state lifecycle: active -> demoted -> removed ==="
# =========================================================================

# --- 4a. Drive vehicle-43 below T_demote (3000) ---
# Current score: 9500. Need < 3000: 14 more penalties of -500 each
# 9500 - 14*500 = 2500 < 3000. Triggers QuarantineDemoted.
as_org1
for i in $(seq 1 14); do
  ts=$((1718000200 + i))
  invoke LogDetection "[\"vehicle-43\",\"2\",\"$ts\",\"sig-$i\"]"
done

as_org2
query QueryTrust '["vehicle-43"]'      # expect: 2500
query IsActivePeer '["vehicle-43"]'    # expect: false (demoted)
query QueryQuarantineList '[]'         # expect: vehicle-43 listed, status=demoted
query QueryPeerSelection '[]'          # vehicle-43 in DemotedClients bucket

# --- 4b. Drive vehicle-43 further below T_remove (1000) ---
# Current score: 2500. Need < 1000: 4 more penalties of -500 each
# 2500 - 4*500 = 500 < 1000. Triggers QuarantineRemoved.
as_org1
for i in $(seq 1 4); do
  ts=$((1718000400 + i))
  invoke LogDetection "[\"vehicle-43\",\"2\",\"$ts\",\"demote-to-remove-$i\"]"
done

as_org2
query QueryTrust '["vehicle-43"]'      # expect: 500
query IsActivePeer '["vehicle-43"]'    # expect: false (removed)
query QueryRemovedList '[]'            # expect: vehicle-43 listed, status=removed
query QueryPeerSelection '[]'          # vehicle-43 in RemovedNodes bucket

# --- 4c. Verify writes are blocked for removed node ---
as_org1
echo "--- Expecting error: write blocked for removed node ---"
invoke LogDetection '["vehicle-43","2","1718000999","should-be-blocked"]' && echo "ERROR: write should have been rejected" || echo "OK: write correctly rejected"

# --- 4d. Verify LiftQuarantine is rejected for removed node ---
echo "--- Expecting error: cannot lift removed node ---"
invoke LiftQuarantine '["vehicle-43","1718001000"]' && echo "ERROR: lift should have been rejected" || echo "OK: lift correctly rejected"

# =========================================================================
echo
echo "=== 5. Lift a DEMOTED (not removed) node and re-check peer selection ==="
# =========================================================================
# Use a fresh node (vehicle-56) to demonstrate the demote -> lift path
as_org1
for i in $(seq 1 15); do
  ts=$((1718001100 + i))
  invoke LogDetection "[\"vehicle-56\",\"1\",\"$ts\",\"sig55-$i\"]"
done
# vehicle-56: 10000 - 15*500 = 2500 -> demoted

as_org2
query IsActivePeer '["vehicle-56"]'  # expect: false

as_org1
invoke LiftQuarantine '["vehicle-56","1718001200"]'

as_org2
query IsActivePeer '["vehicle-56"]'  # expect: true (lifted)
query QueryPeerSelection '[]'        # vehicle-56 back in ActivePeers

# =========================================================================
echo
echo "=== 6. Model hash commit + verify (match and mismatch) ==="
# =========================================================================
as_org1
MY_ID=$(peer chaincode query -C "$CHANNEL" -n "$CC" -c '{"function":"GetMyIdentity","Args":[]}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo "Org1 Admin identity: $MY_ID"

invoke CommitModelHash '["1","0xabc123modelhash","1718002000"]'
query GetModelHash "[\"$MY_ID\",\"1\"]"   # expect: verified=false

invoke VerifyModelHash "[\"$MY_ID\",\"1\",\"0xabc123modelhash\"]"
query GetModelHash "[\"$MY_ID\",\"1\"]"   # expect: verified=true

echo "--- mismatch case ---"
invoke CommitModelHash '["2","0xdef456modelhash","1718002050"]'
invoke VerifyModelHash "[\"$MY_ID\",\"2\",\"0xWRONGHASH\"]"   # returns false, stays unverified
query GetModelHash "[\"$MY_ID\",\"2\"]"   # expect: verified=false

# =========================================================================
echo
echo "=== 7. Witness alert quorum (2f+1=3): penalty on 3rd alert ==="
# =========================================================================
as_org1
invoke SubmitAlert '["pkthash-888","dup","vehicle-100","witness-A","sig-A","1718003000"]'
invoke SubmitAlert '["pkthash-888","dup","vehicle-100","witness-B","sig-B","1718003001"]'

as_org2
query QueryTrust '["vehicle-100"]'  # expect: 10000 (2/3 alerts, no penalty yet)
query GetAlert '["pkthash-888"]'   # expect: verifiedCount=2, penalized=false

as_org1
invoke SubmitAlert '["pkthash-888","dup","vehicle-100","witness-C","sig-C","1718003002"]'

as_org2
query QueryTrust '["vehicle-100"]'  # expect: 9500 (penalty on 3rd alert)
query GetAlert '["pkthash-888"]'   # expect: verifiedCount=3, penalized=true

# =========================================================================
echo
echo "=== 8. QueryPeerSelection final state ==="
# =========================================================================
as_org2
query QueryPeerSelection '[]'
# Expect:
#   ActivePeers:    vehicle-56 (lifted), vehicle-100 (score 9500, no quarantine record)
#   DemotedClients: (none remaining -- vehicle-43 was escalated to removed)
#   RemovedNodes:   vehicle-43

echo
echo "=== Done ==="
