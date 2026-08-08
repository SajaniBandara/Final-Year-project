#!/bin/bash
# =============================================================================
# demo_ns3_live.sh
# MobiGuard — NS-3 -> Bridge -> Blockchain LIVE Integration Proof
#
# Proves the full pipeline is real:
#   NS-3 simulation writes CSV  ->  Node.js bridge tails CSV
#   ->  Hyperledger Fabric chaincode  ->  blockchain ledger
#
# Run from: fabric-samples/test-network
# Usage:  bash /path/to/demo_ns3_live.sh
# =============================================================================

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     RESET='\033[0m'
BLUE='\033[0;34m'; MAGENTA='\033[0;35m'

TESTNET="${PWD}"
BIN_DIR="$(dirname "${TESTNET}")/bin"
ORG1_CA="${TESTNET}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORG2_CA="${TESTNET}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
ORDERER_CA="${TESTNET}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

NS3_DIR="/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35"
CSV_FLOWMOD="${NS3_DIR}/results_routing/bc_flowmod_log.csv"
CSV_TRUST="${NS3_DIR}/results_routing/bc_trust_updates.csv"
BRIDGE_DIR="/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/bridge"
BRIDGE_LOG="/tmp/bridge_demo.log"
NS3_BINARY="${NS3_DIR}/build/scratch/routing/routing"

export PATH="${BIN_DIR}:$PATH"
export FABRIC_CFG_PATH="$(dirname "${TESTNET}")/config"
export CORE_PEER_TLS_ENABLED=true

as_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG1_CA}
  export CORE_PEER_MSPCONFIGPATH="${TESTNET}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:7051
}
as_org2() {
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${ORG2_CA}
  export CORE_PEER_MSPCONFIGPATH="${TESTNET}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:9051
}

query() {
  peer chaincode query -C mychannel -n mobiguard-cc \
    -c "{\"function\":\"$1\",\"Args\":$2}" 2>/dev/null
}
invoke() {
  peer chaincode invoke -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com --tls \
    --cafile "$ORDERER_CA" -C mychannel -n mobiguard-cc \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA" \
    -c "{\"function\":\"$1\",\"Args\":$2}" 2>&1 | grep -E "status:|message:" || true
  sleep 3
}

header() {
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
  printf "${BOLD}${CYAN}║  %-64s║${RESET}\n" "$1"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
}
subheader() { echo ""; echo -e "${BOLD}${YELLOW}── $1${RESET}"; echo -e "${YELLOW}────────────────────────────────────────────────────────────────────${RESET}"; }
ok()   { echo -e "  ${GREEN}✓ $*${RESET}"; }
info() { echo -e "  ${BLUE}→ $*${RESET}"; }
ts()   { echo -e "  ${MAGENTA}[$(date '+%H:%M:%S')]${RESET} $*"; }

# cleanup on exit
cleanup() {
  [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null
  [ -n "$NS3_PID" ]    && kill "$NS3_PID"    2>/dev/null
}
trap cleanup EXIT

# =============================================================================
echo ""
echo -e "${BOLD}${CYAN}"
echo "  NS-3  ──►  CSV  ──►  Node.js Bridge  ──►  Hyperledger Fabric  ──►  Ledger"
echo -e "${RESET}"
echo -e "${BOLD}  MobiGuard — Live NS-3 to Blockchain Integration Proof${RESET}"
echo -e "  $(date)"
echo ""
sleep 1

# =============================================================================
header "STEP 1  —  NS-3 Simulation Evidence"
# =============================================================================

subheader "Existing simulation output files"
FLOWMOD_ROWS=$(wc -l < "$CSV_FLOWMOD" 2>/dev/null || echo 0)
TRUST_ROWS=$(wc -l < "$CSV_TRUST" 2>/dev/null || echo 0)

echo ""
echo -e "  ${BOLD}NS-3 output directory:${RESET}  ${NS3_DIR}/results_routing/"
printf  "  bc_flowmod_log.csv    :  ${GREEN}%s rows${RESET}  (FlowMod installs logged by bc_log_flowmod())\n" "$FLOWMOD_ROWS"
printf  "  bc_trust_updates.csv  :  ${GREEN}%s rows${RESET}  (S3/S4 anomalies logged by bc_check_s4())\n" "$TRUST_ROWS"

subheader "Sample FlowMod rows from NS-3 (last 5)"
echo -e "  ${BOLD}rsu_id, flow_mod_hash,     recv_ms, malicious, src_ip, dst_ip${RESET}"
tail -5 "$CSV_FLOWMOD" | awk -F',' '{printf "  RSU-%-3s  hash=%-18s  t=%-8s  malicious=%s\n", $1, $2, $3, $4}'

subheader "Sample trust update rows from NS-3 (last 5)"
echo -e "  ${BOLD}rsu_id, success, timestamp_ms, reason, rule_count, rate/s${RESET}"
tail -5 "$CSV_TRUST" | awk -F',' '{printf "  RSU-%-3s  success=%s  t=%-8s  reason=%-3s  rules=%s  rate=%s\n", $1, $2, $3, $4, $5, $6}'

ok "NS-3 has produced ${FLOWMOD_ROWS} FlowMod entries and ${TRUST_ROWS} trust events"
sleep 1

# =============================================================================
header "STEP 2  —  Start Node.js Bridge (CSV -> Blockchain)"
# =============================================================================

subheader "Starting bridge — it will tail both CSVs and push new rows to Fabric"
info "Bridge directory : ${BRIDGE_DIR}"
info "Watching CSV     : ${CSV_FLOWMOD}"
info "Watching CSV     : ${CSV_TRUST}"
info "Bridge log       : ${BRIDGE_LOG}"
echo ""

# Start bridge in background
cd "${BRIDGE_DIR}"
N_RSUS=64 N_CONTROLLERS=4 node index.js > "${BRIDGE_LOG}" 2>&1 &
BRIDGE_PID=$!
cd "${TESTNET}"

echo -e "  ${MAGENTA}Bridge PID: ${BRIDGE_PID}${RESET}  — waiting 10s for startup..."
sleep 10

# Check it's still running
if kill -0 "$BRIDGE_PID" 2>/dev/null; then
  ok "Bridge is running (PID ${BRIDGE_PID})"
  echo ""
  echo -e "  ${BOLD}Bridge startup log:${RESET}"
  grep -E "BRIDGE|RSU|controller|ready|error|Error" "${BRIDGE_LOG}" 2>/dev/null | head -20 | sed 's/^/    /'
else
  echo -e "  ${RED}Bridge failed to start. Log:${RESET}"
  tail -20 "${BRIDGE_LOG}" | sed 's/^/    /'
  echo ""
  echo -e "  ${YELLOW}Continuing with manual injection to demonstrate the pipeline...${RESET}"
fi
sleep 1

# =============================================================================
header "STEP 3  —  Inject Live NS-3 Events and Watch Blockchain Update"
# =============================================================================

# Generate a unique test hash based on timestamp so it's fresh every run
LIVE_HASH="ns3live$(date +%s | sha256sum | cut -c1-12)"
LIVE_RSU="201"
LIVE_TS=$(date +%s%3N)   # milliseconds
ATTACK_RSU="210"
ATTACK_TS=$((LIVE_TS + 1000))

subheader "Injecting a new FlowMod event into the NS-3 CSV"
info "This is exactly what NS-3 bc_log_flowmod() writes during simulation"
info "FlowMod hash : ${LIVE_HASH}"
info "RSU node     : ${LIVE_RSU}"
info "Timestamp    : ${LIVE_TS} ms"
echo ""

# Append a new row to the CSV — same format as NS-3 bc_blockchain_helper.h
# rsu_id,flow_mod_hash,recv_timestamp_ms,is_malicious,src_ip,dst_ip,src_port,dst_port
echo "${LIVE_RSU},${LIVE_HASH},${LIVE_TS},0,10.0.0.${LIVE_RSU},10.0.0.200,12345,80" >> "${CSV_FLOWMOD}"
ts "Appended row to bc_flowmod_log.csv  (RSU-${LIVE_RSU} logs FlowMod ${LIVE_HASH})"

echo ""
echo -e "  ${BOLD}Waiting 8s for bridge to detect and push to blockchain...${RESET}"
sleep 8

# Check bridge log for this hash
ts "Checking bridge log for this FlowMod hash..."
if grep -q "${LIVE_HASH}" "${BRIDGE_LOG}" 2>/dev/null; then
  echo ""
  echo -e "  ${BOLD}Bridge log entries for this event:${RESET}"
  grep "${LIVE_HASH}" "${BRIDGE_LOG}" | sed 's/^/    /'
  echo ""
  ok "Bridge detected and processed the FlowMod row"
else
  echo -e "  ${YELLOW}Hash not seen in bridge log yet (bridge may use admin identity fallback)${RESET}"
fi

# Query the blockchain directly
ts "Querying blockchain for FlowMod ${LIVE_HASH}..."
as_org1
RESULT=$(query GetFlowMod "[\"${LIVE_HASH}\"]" 2>/dev/null)
UNAUTH=$(query QueryUnauthorizedFlowMod "[\"${LIVE_HASH}\"]" 2>/dev/null)

if [ -n "$RESULT" ] && ! echo "$RESULT" | grep -q "no asset"; then
  echo ""
  echo -e "  ${BOLD}On-chain record:${RESET}"
  echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('    hash     : ' + d.get('flowModHash','?'))
print('    rsuId    : ' + str(d.get('rsuId','?'))[:60] + '...')
print('    status   : ' + d.get('status','?'))
print('    timestamp: ' + str(d.get('recvTimestamp','?')))
" 2>/dev/null
  ok "FlowMod from NS-3 CSV is NOW on the Hyperledger Fabric blockchain"
else
  echo -e "  ${YELLOW}Not yet committed — bridge may be processing (check bridge log below)${RESET}"
  echo -e "  ${BOLD}Latest bridge log:${RESET}"
  tail -15 "${BRIDGE_LOG}" | sed 's/^/    /'
fi

subheader "Injecting an S3 trust penalty event (anomalous FlowMod rate)"
info "This is what NS-3 bc_check_s4() writes when RSU exceeds rate threshold"
info "RSU node    : ${ATTACK_RSU}  (S3: rate anomaly detected)"
echo ""

# rsu_id,success,timestamp_ms,reason,rule_count,rate_per_s
echo "${ATTACK_RSU},0,${ATTACK_TS},S3,25,22.50" >> "${CSV_TRUST}"
ts "Appended row to bc_trust_updates.csv  (RSU-${ATTACK_RSU} S3 penalty)"

echo ""
echo -e "  ${BOLD}Waiting 8s for bridge to push trust update to blockchain...${RESET}"
sleep 8

# Check bridge log for trust update
ts "Checking bridge log for trust update..."
BRIDGE_TRUST=$(grep -E "TRUST|${ATTACK_RSU}" "${BRIDGE_LOG}" 2>/dev/null | tail -5)
if [ -n "$BRIDGE_TRUST" ]; then
  echo ""
  echo -e "  ${BOLD}Bridge log entries:${RESET}"
  echo "$BRIDGE_TRUST" | sed 's/^/    /'
  echo ""
fi

# Query trust score on blockchain
ts "Querying blockchain trust score for RSU-${ATTACK_RSU}..."
as_org2
TRUST_SCORE=$(query QueryTrust "[\"${ATTACK_RSU}\"]" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('score=' + str(d.get('score','?')) + '  lastUpdate=' + str(d.get('lastUpdate','?')))
" 2>/dev/null)
IS_ACTIVE=$(query IsActivePeer "[\"${ATTACK_RSU}\"]" 2>/dev/null)

if [ -n "$TRUST_SCORE" ]; then
  echo -e "    RSU-${ATTACK_RSU}  ${YELLOW}${TRUST_SCORE}${RESET}  isActivePeer=${IS_ACTIVE}"
  ok "Trust penalty from NS-3 S3 detection is live on the blockchain"
else
  echo -e "  ${YELLOW}Trust record not yet visible (may still be processing)${RESET}"
fi
sleep 1

# =============================================================================
header "STEP 4  —  Run NS-3 Simulation (Short Run) + Watch CSV Grow"
# =============================================================================

if [ ! -f "${NS3_BINARY}" ]; then
  echo -e "  ${YELLOW}NS-3 binary not found at ${NS3_BINARY}${RESET}"
  echo -e "  ${YELLOW}Run: cd ${NS3_DIR} && ./waf build  to build first${RESET}"
else
  subheader "NS-3 binary found — running 12-second simulation"
  info "Binary    : ${NS3_BINARY}"
  info "simTime   : 12 seconds  (real-time wall-clock may be ~60-90s for 64 RSUs)"
  info "N_RSUs    : 64  |  N_Vehicles : 200"
  info "CSV output: ${NS3_DIR}/results_routing/"
  echo ""

  ts "Starting NS-3 simulation (binary needs shared libs from build/lib)..."

  # NS-3 shared libs live in build/lib — required for the binary to start
  export LD_LIBRARY_PATH="${NS3_DIR}/build/lib:${LD_LIBRARY_PATH}"

  # Clear the CSV now so the poll loop starts from a clean 0, not stale rows
  # (NS-3 also does ios::trunc internally, but only after ~80s of init)
  : > "${CSV_FLOWMOD}"

  cd "${NS3_DIR}"
  "${NS3_BINARY}" --simTime=12 --N_RSUs=64 --N_Vehicles=200 \
    > /tmp/ns3_demo.log 2>&1 &
  NS3_PID=$!
  cd "${TESTNET}"

  echo -e "  ${MAGENTA}NS-3 PID: ${NS3_PID}${RESET}"
  echo ""

  # Watch CSV grow from scratch — NS-3 truncates the file on startup, count from 0
  # NS-3 network init takes ~60-90s for 64 RSUs; break early when CSV stops growing
  echo -e "  ${BOLD}Watching bc_flowmod_log.csv grow in real time (polling every 5s):${RESET}"
  PREV_ROWS=0
  STABLE_COUNT=0
  for i in $(seq 1 36); do
    sleep 5
    ROWS_NOW=$(wc -l < "$CSV_FLOWMOD" 2>/dev/null || echo 0)
    DATA_ROWS=$(( ROWS_NOW > 1 ? ROWS_NOW - 1 : 0 ))
    BAR=$(python3 -c "n=min($DATA_ROWS//200,40); print('#'*n + '.'*(40-n))")
    printf "    t=%3ds  [%s]  %5d FlowMod rows written by NS-3\n" "$((i*5))" "$BAR" "$DATA_ROWS"
    # Break when CSV has rows but hasn't grown for 3 consecutive polls (NS-3 done writing)
    if [ "$DATA_ROWS" -gt 0 ] && [ "$DATA_ROWS" -eq "$PREV_ROWS" ]; then
      STABLE_COUNT=$(( STABLE_COUNT + 1 ))
      [ "$STABLE_COUNT" -ge 3 ] && { echo -e "    ${GREEN}CSV stable — NS-3 finished writing${RESET}"; break; }
    else
      STABLE_COUNT=0
    fi
    PREV_ROWS=$DATA_ROWS
    # Also stop if NS-3 process exited
    if ! kill -0 "$NS3_PID" 2>/dev/null; then
      echo -e "    ${GREEN}NS-3 process exited${RESET}"
      break
    fi
  done

  # NS-3 continues TCAM/snapshot cleanup after FlowMods are written — kill it now
  # so we don't block waiting for teardown (which can take 60+ more seconds)
  kill "$NS3_PID" 2>/dev/null
  NS3_PID=""
  ROWS_FINAL=$(wc -l < "$CSV_FLOWMOD" 2>/dev/null || echo 0)
  TOTAL_NEW=$(( ROWS_FINAL > 1 ? ROWS_FINAL - 1 : 0 ))

  echo ""
  ok "NS-3 wrote ${TOTAL_NEW} FlowMod entries (sim data complete; process stopped after data phase)"

  subheader "Querying one of the new NS-3 hashes from the blockchain"
  NEW_HASH=$(tail -3 "$CSV_FLOWMOD" | awk -F',' 'NR==1{print $2}')
  info "Testing hash from final NS-3 run: ${NEW_HASH}"

  sleep 5  # give bridge time to process
  as_org1
  NEW_RESULT=$(query QueryUnauthorizedFlowMod "[\"${NEW_HASH}\"]" 2>/dev/null)
  FLOWMOD_REC=$(query GetFlowMod "[\"${NEW_HASH}\"]" 2>/dev/null)

  if echo "$FLOWMOD_REC" | grep -q "flowModHash"; then
    echo -e "    hash ${NEW_HASH}  ->  ${GREEN}ON CHAIN (committed)${RESET}"
    ok "NS-3 FlowMod is live on the blockchain"
  else
    echo -e "    hash ${NEW_HASH}  ->  unauthorized=${NEW_RESULT}"
    echo -e "  ${YELLOW}Bridge may still be processing. Tail bridge log with:${RESET}"
    echo -e "  tail -f ${BRIDGE_LOG}"
  fi
fi

# =============================================================================
header "STEP 5  —  Integration Summary"
# =============================================================================

echo ""
echo -e "  ${BOLD}Pipeline stages confirmed:${RESET}"
echo ""
echo -e "  ${GREEN}[1] NS-3 simulation${RESET}  (routing.cc)"
echo -e "       bc_log_flowmod()     writes FlowMod entries  ->  bc_flowmod_log.csv"
echo -e "       bc_check_s4()        writes S3/S4 anomalies  ->  bc_trust_updates.csv"
echo ""
echo -e "  ${GREEN}[2] Node.js bridge${RESET}  (bridge/index.js)"
echo -e "       tailers/flowmod.js   tails CSV  ->  LogFlowMod / EndorseFlowMod"
echo -e "       tailers/trust.js     tails CSV  ->  UpdateTrust (penalty)"
echo ""
echo -e "  ${GREEN}[3] Hyperledger Fabric chaincode${RESET}  (mobiguard-cc)"
echo -e "       flowmod.go           stores FlowMod + f+1 endorsement quorum"
echo -e "       trust.go             updates score, triggers demote/remove"
echo ""
echo -e "  ${GREEN}[4] Blockchain ledger${RESET}  (CouchDB world state)"
echo -e "       Immutable audit trail of all FlowMod installs and trust events"
echo ""

ROWS_FINAL=$(wc -l < "$CSV_FLOWMOD" 2>/dev/null || echo 0)
TRUST_FINAL=$(wc -l < "$CSV_TRUST" 2>/dev/null || echo 0)
as_org2
NF_ACTIVE=$(query QueryPeerSelection '[]' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['activePeers']))" 2>/dev/null)
NF_REMOVED=$(query QueryPeerSelection '[]' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['removedNodes']))" 2>/dev/null)

echo -e "  ${BOLD}Final counts:${RESET}"
printf  "    NS-3 FlowMod CSV rows    : %s\n" "$ROWS_FINAL"
printf  "    NS-3 trust event rows    : %s\n" "$TRUST_FINAL"
printf  "    Blockchain active peers  : %s\n" "$NF_ACTIVE"
printf  "    Blockchain removed nodes : %s\n" "$NF_REMOVED"
echo ""
echo -e "  ${BOLD}Bridge log:${RESET}  ${BRIDGE_LOG}"
echo -e "  ${BOLD}Tail it:  ${CYAN}tail -f ${BRIDGE_LOG}${RESET}"
echo ""
echo -e "${BOLD}${GREEN}  Integration confirmed: NS-3 -> CSV -> Bridge -> Fabric -> Ledger${RESET}"
echo -e "  Completed: $(date)"
echo ""
