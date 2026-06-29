#!/usr/bin/env bash
# =============================================================================
# deploy-mobiguard.sh
# Full reset-and-deploy for mobiguard-cc on the Fabric test-network.
#
# Usage (source it so env vars stay in your shell):
#   source ./deploy-mobiguard.sh
#
# What it does:
#   1. Tears down any running network + prunes Docker volumes
#   2. Brings the network back up with CouchDB state database
#   3. Creates / joins mychannel with anchor peers
#   4. Exports all peer/orderer env vars
#   5. Packages mobiguard-cc (Go chaincode at ../../mobiguard-cc)
#   6. Installs on peer0.org1 and peer0.org2
#   7. Approves for Org1 and Org2
#   8. Commits to mychannel
#   9. Prints the Package ID and a ready-to-use cheat-sheet
# =============================================================================

set -e  # exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}${BOLD}[deploy]${NC} $*"; }
ok()   { echo -e "${GREEN}${BOLD}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}${BOLD}[ WARN ]${NC} $*"; }
die()  { echo -e "${RED}${BOLD}[ FAIL ]${NC} $*"; exit 1; }

# =============================================================================
# STEP 0 — sanity checks
# =============================================================================
log "Checking prerequisites..."
[[ -f "./network.sh" ]]            || die "Run this from the test-network directory."
[[ -d "../../mobiguard-cc" ]]      || die "../../mobiguard-cc not found."
command -v docker &>/dev/null      || die "docker not found."

# =============================================================================
# STEP 1 — tear down existing network + volumes
# =============================================================================
log "Tearing down existing network..."
./network.sh down 2>&1 | tail -5
docker volume prune -f >/dev/null 2>&1
ok "Network down, volumes pruned."

# =============================================================================
# STEP 2 — bring network up with CouchDB
# =============================================================================
log "Starting network with CouchDB..."
./network.sh up -s couchdb 2>&1 | tail -10
ok "Network is up."

# =============================================================================
# STEP 3 — create channel (includes anchor-peer updates)
# =============================================================================
log "Waiting 15 s for peers to stabilise..."
sleep 15
log "Creating channel mychannel..."
./network.sh createChannel -c mychannel 2>&1 | tail -6
ok "Channel mychannel created."

# =============================================================================
# STEP 4 — export environment variables
# =============================================================================
log "Exporting environment variables..."

export PATH="${SCRIPT_DIR}/../bin:$PATH"
export FABRIC_CFG_PATH="${SCRIPT_DIR}/../config/"
export CORE_PEER_TLS_ENABLED=true

export ORDERER_CA="${SCRIPT_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
export ORG1_CA="${SCRIPT_DIR}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export ORG2_CA="${SCRIPT_DIR}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

export CHANNEL=mychannel
export CC=mobiguard-cc
export CC_VERSION=1.0
export CC_SEQUENCE=1

# ── helpers to switch orgs ───────────────────────────────────────────────────
use_org1() {
    export CORE_PEER_LOCALMSPID="Org1MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE="${ORG1_CA}"
    export CORE_PEER_MSPCONFIGPATH="${SCRIPT_DIR}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
    export CORE_PEER_ADDRESS=localhost:7051
}

use_org2() {
    export CORE_PEER_LOCALMSPID="Org2MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE="${ORG2_CA}"
    export CORE_PEER_MSPCONFIGPATH="${SCRIPT_DIR}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
    export CORE_PEER_ADDRESS=localhost:9051
}

ok "Env vars exported."

# =============================================================================
# STEP 5 — package chaincode
# =============================================================================
log "Packaging chaincode (Go build — may take ~60 s)..."
use_org1
peer lifecycle chaincode package mobiguard-cc.tar.gz \
    --path ../../mobiguard-cc \
    --lang golang \
    --label "mobiguard-cc_${CC_VERSION}"
ok "Package created: mobiguard-cc.tar.gz"

# =============================================================================
# STEP 6 — install on both peers
# =============================================================================
log "Installing on peer0.org1..."
use_org1
peer lifecycle chaincode install mobiguard-cc.tar.gz
ok "Installed on Org1."

log "Installing on peer0.org2..."
use_org2
peer lifecycle chaincode install mobiguard-cc.tar.gz
ok "Installed on Org2."

# =============================================================================
# STEP 7 — capture Package ID
# =============================================================================
use_org1
log "Querying installed chaincodes..."
QUERY_OUT=$(peer lifecycle chaincode queryinstalled 2>&1)
echo "$QUERY_OUT"

PKGID=$(echo "$QUERY_OUT" \
    | grep "mobiguard-cc_${CC_VERSION}" \
    | sed 's/.*Package ID: \([^,]*\),.*/\1/' \
    | head -1)

[[ -n "$PKGID" ]] || die "Could not parse Package ID from queryinstalled output."
export PKGID
ok "Package ID: ${BOLD}${PKGID}${NC}"

# =============================================================================
# STEP 8 — approve for Org1
# =============================================================================
log "Approving for Org1..."
use_org1
peer lifecycle chaincode approveformyorg \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --channelID "$CHANNEL" --name "$CC" \
    --version "$CC_VERSION" --package-id "$PKGID" --sequence "$CC_SEQUENCE" \
    --tls --cafile "$ORDERER_CA"
ok "Org1 approved."

# =============================================================================
# STEP 9 — approve for Org2
# =============================================================================
log "Approving for Org2..."
use_org2
peer lifecycle chaincode approveformyorg \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --channelID "$CHANNEL" --name "$CC" \
    --version "$CC_VERSION" --package-id "$PKGID" --sequence "$CC_SEQUENCE" \
    --tls --cafile "$ORDERER_CA"
ok "Org2 approved."

# =============================================================================
# STEP 10 — check commit readiness (optional, informational)
# =============================================================================
use_org1
log "Checking commit readiness..."
peer lifecycle chaincode checkcommitreadiness \
    --channelID "$CHANNEL" --name "$CC" \
    --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
    --tls --cafile "$ORDERER_CA" --output json

# =============================================================================
# STEP 11 — commit
# =============================================================================
log "Committing chaincode to channel..."
use_org1
peer lifecycle chaincode commit \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --channelID "$CHANNEL" --name "$CC" \
    --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
    --tls --cafile "$ORDERER_CA" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA"
ok "Chaincode committed."

# Verify
log "Verifying committed chaincode..."
peer lifecycle chaincode querycommitted \
    --channelID "$CHANNEL" --name "$CC" \
    --tls --cafile "$ORDERER_CA"

# =============================================================================
# DONE — print cheat-sheet
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║              mobiguard-cc deployed successfully!         ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Package ID:${NC}  $PKGID"
echo ""
echo -e "${BOLD}Shell is set to Org1 Admin. Handy commands:${NC}"
echo ""
echo -e "  ${CYAN}# Register a controller${NC}"
echo '  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \'
echo '    --tls --cafile $ORDERER_CA -C mychannel -n mobiguard-cc \'
echo '    --peerAddresses localhost:7051 --tlsRootCertFiles $ORG1_CA \'
echo '    --peerAddresses localhost:9051 --tlsRootCertFiles $ORG2_CA \'
echo "    -c '{\"function\":\"RegisterController\",\"Args\":[\"ctrl-1\",\"1.234\",\"103.456\",\"1000\"]}'"
echo ""
echo -e "  ${CYAN}# Apply a trust penalty${NC}"
echo '  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \'
echo '    --tls --cafile $ORDERER_CA -C mychannel -n mobiguard-cc \'
echo '    --peerAddresses localhost:7051 --tlsRootCertFiles $ORG1_CA \'
echo '    --peerAddresses localhost:9051 --tlsRootCertFiles $ORG2_CA \'
echo "    -c '{\"function\":\"UpdateControllerTrust\",\"Args\":[\"ctrl-1\",\"false\",\"2000\"]}'"
echo ""
echo -e "  ${CYAN}# Check TrustUpdated event in latest block${NC}"
echo '  peer channel fetch newest ./latest_block.pb \'
echo '    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \'
echo '    -c mychannel --tls --cafile $ORDERER_CA && \'
echo '  configtxlator proto_decode --input ./latest_block.pb --type common.Block \'
echo '    | python3 -c "'
echo '        import sys,json,base64; d=json.load(sys.stdin)'
echo '        for tx in d[\"data\"][\"data\"]:'
echo '          try:'
echo '            for a in tx[\"payload\"][\"data\"][\"actions\"]:'
echo '              ev=a[\"payload\"][\"action\"][\"proposal_response_payload\"][\"extension\"][\"events\"]'
echo '              print(ev[\"event_name\"],\"|\",base64.b64decode(ev[\"payload\"]).decode())'
echo '          except: pass'
echo '    "'
echo ""
echo -e "  ${CYAN}# Switch to Org2 Admin${NC}"
echo '  use_org2   # function is already defined in this shell'
echo ""
echo -e "  ${CYAN}# Switch back to Org1 Admin${NC}"
echo '  use_org1'
echo ""
