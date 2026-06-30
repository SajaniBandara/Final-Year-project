# MobiGuard — Hyperledger Fabric Integration

Blockchain audit-trail layer for the MobiGuard SDVN security framework.  
NS-3 simulation lives in `scratch/routing/routing.cc`. Blockchain code lives here.

See `SPEC.md` for the chaincode schema and equation mappings.  
See `PHASES.md` for phase status and milestones.

---

## ⚡ Every Time You Restart Your Machine

Run these steps **in order** each session before starting the NS-3 simulation.

### Step 1 — Deploy the Fabric Network

```bash
cd "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/fabric-samples/test-network"
./deploy-mobiguard.sh
```

This brings up Docker containers (peers, orderer, CAs, CouchDB), creates the
`mychannel` channel, and installs + commits the `mobiguard-cc` chaincode.  
Takes about **2–3 minutes**. Wait for the banner:

```
╔══════════════════════════════════════════════════════════╗
║              mobiguard-cc deployed successfully!         ║
╚══════════════════════════════════════════════════════════╝
```

---

### Step 2 — Enroll RSU Identities (first time only, or if wallet is deleted)

```bash
cd "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/bridge"
./enroll_rsu_identities.sh stage1
```

This registers and enrolls `rsu-200` to `rsu-203` with the Fabric CA and saves
their cryptographic wallets to `bridge/wallet/`.  
**Skip this step** if the `wallet/` folder already exists from a previous session.

---

### Step 3 — Start the Bridge (Terminal 1)

```bash
cd "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/bridge"
node index.js
```

Wait until you see:
```
[BRIDGE] ✅ Real-time tailers active. Waiting for NS-3 events...
```

Keep this terminal open. The bridge watches the NS-3 CSV output files and writes
events to the blockchain in real-time.

---

### Step 4 — Run the NS-3 Simulation (Terminal 2)

```bash
cd /home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35

# Benign baseline (no attack)
./waf --run "scratch/routing/routing --simTime=40 --active_attack_variant=-1 --use_sumo_mobility=1"

# Attack 3 — Control Plane TCAM Flood
./waf --run "scratch/routing/routing --simTime=40 --active_attack_variant=2 --use_sumo_mobility=1"

# Attack 4 — Data Plane TCAM Exhaustion
./waf --run "scratch/routing/routing --simTime=40 --active_attack_variant=3 --use_sumo_mobility=1"
```

Watch Terminal 1 — you will see the bridge printing live blockchain writes as
the simulation progresses.

---

### Step 5 — Shut Down (when done)

Press `Ctrl+C` in Terminal 1 to stop the bridge, then:

```bash
cd "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/fabric-samples/test-network"
./network.sh down
```

---

## 🔍 Useful Query Commands

Set up env vars first (copy-paste once per terminal):

```bash
export PATH="/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/fabric-samples/bin:$PATH"
export FABRIC_CFG_PATH="/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/fabric-samples/config/"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_MSPCONFIGPATH="/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_TLS_ROOTCERT_FILE="/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/final yr project updated/Final-Year-project/blockchain/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
```

```bash
# Check RSU controller assignment
peer chaincode query -C mychannel -n mobiguard-cc \
  -c '{"function":"QueryControllerAssignment","Args":["rsu-200"]}'

# Check trust score for an RSU
peer chaincode query -C mychannel -n mobiguard-cc \
  -c '{"function":"QueryTrust","Args":["200"]}'

# Check all RSU assignments
peer chaincode query -C mychannel -n mobiguard-cc \
  -c '{"function":"GetAllAssignments","Args":[]}'

# Check running Docker containers
docker ps
```

---

## Prerequisites (verified working)

| Tool | Version |
|------|---------|
| Ubuntu | 22.04 |
| Docker + Compose plugin | 29.x / v5.x |
| Go | 1.23.4 |
| Node.js / npm | 22.x / 10.x |
| Hyperledger Fabric | 2.5.15 |
| Fabric CA | 1.5.17 |

---

## Project Layout

```
blockchain/
├── README.md                  ← You are here (startup runbook)
├── SPEC.md                    ← Chaincode schema & equation mappings
├── PHASES.md                  ← Phase status & milestones
│
├── mobiguard-cc/              ← Go smart contract (6 asset types)
│   ├── flowmod.go             ← FlowMod log/endorsement (Eq 3.41/3.43)
│   ├── trust.go               ← RSU trust scores (Eq 3.47/3.48)
│   ├── assignment.go          ← Controller assignment (Eq 3.51/3.53)
│   ├── evidence.go            ← Conflict evidence submission
│   ├── access_control.go      ← Identity-based access control
│   └── main.go
│
├── bridge/                    ← Node.js NS-3 ↔ Fabric bridge
│   ├── index.js               ← Entry point (registers RSUs, starts tailers)
│   ├── fabric-client.js       ← Fabric Gateway connection & signing
│   ├── config.json            ← RSU/controller config (stage1/2/3)
│   ├── tailers/
│   │   ├── flowmod.js         ← Tails bc_flowmod_log.csv → LogFlowMod
│   │   └── trust.js           ← Tails bc_trust_updates.csv → UpdateTrust
│   ├── wallet/                ← Enrolled RSU identities (not in git)
│   └── enroll_rsu_identities.sh
│
├── fabric-samples/
│   ├── bin/                   ← Fabric CLI binaries (not in git)
│   ├── config/                ← configtx, orderer, core YAML
│   └── test-network/
│       ├── deploy-mobiguard.sh  ← ⭐ Main deploy script (run this first)
│       ├── network.sh
│       └── ...
│
└── scripts/                   ← Utility scripts
```

---

## Known Issues & Fixes (already applied)

| Issue | Fix Applied |
|-------|-------------|
| CouchDB `401 Unauthorized` on peer startup | `network.sh` starts CouchDB 8s before peers |
| `Invalid S` ECDSA signature rejection | Bridge uses `signers.newPrivateKeySigner` |
| Chaincode install `invalid UTF-8` | Removed precompiled binary from Go source dir |
| `Uint8Array` JSON parse crash | Wrapped SDK response in `Buffer.from()` |
| Scripts fail on path with spaces | Quoted `${TEST_NETWORK_HOME}` in anchor scripts |
