#!/usr/bin/env bash
# enroll_rsu_identities.sh
# MobiGuard — Enroll RSU Fabric identities for the current stage.
#
# Run this ONCE before starting the bridge for each stage.
# Requires: Fabric network running, ca_org1 container up.
#
# Usage:
#   ./enroll_rsu_identities.sh stage1   # enroll rsu-200..rsu-203
#   ./enroll_rsu_identities.sh stage2   # enroll rsu-200..rsu-215
#   ./enroll_rsu_identities.sh stage3   # enroll rsu-200..rsu-263

set -e

STAGE=${1:-stage1}
BRIDGE_DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$BRIDGE_DIR/../fabric-samples/bin:$PATH"
WALLET_DIR="$BRIDGE_DIR/wallet"
FABRIC_DIR="$BRIDGE_DIR/../fabric-samples/test-network"
CA_URL="https://localhost:7054"
CA_CERT="$FABRIC_DIR/organizations/fabric-ca/org1/ca-cert.pem"
MSP_DIR="$FABRIC_DIR/organizations/peerOrganizations/org1.example.com"

# ── RSU node_id range per stage ──────────────────────────────────────────────
# routing.cc: RSU sim node index = N_Vehicles + rsu_index, N_Vehicles=200
N_VEHICLES=200
case "$STAGE" in
  stage1) START=0; END=3   ;;   # 4 RSUs:  node IDs 200-203
  stage2) START=0; END=15  ;;   # 16 RSUs: node IDs 200-215
  stage3) START=0; END=63  ;;   # 64 RSUs: node IDs 200-263
  *)
    echo "Usage: $0 [stage1|stage2|stage3]"
    exit 1
    ;;
esac

echo "=== MobiGuard RSU Identity Enrollment: $STAGE ==="
echo "    Enrolling RSUs rsu-$((N_VEHICLES+START)) to rsu-$((N_VEHICLES+END))"
echo ""

# Ensure CA container is running
if ! docker ps --format '{{.Names}}' | grep -q "^ca_org1$"; then
    echo "[ENROLL] Starting ca_org1 container..."
    docker start ca_org1
    sleep 3
fi

mkdir -p "$WALLET_DIR"

# Admin enroll (needed for registering new identities)
ADMIN_WALLET="$WALLET_DIR/admin"
if [ ! -d "$ADMIN_WALLET" ]; then
    echo "[ENROLL] Enrolling Org1 Admin..."
    mkdir -p "$ADMIN_WALLET"
    export FABRIC_CA_CLIENT_HOME="$ADMIN_WALLET"
    fabric-ca-client enroll \
        -u "https://admin:adminpw@localhost:7054" \
        --caname ca-org1 \
        --tls.certfiles "$CA_CERT" \
        -M "$ADMIN_WALLET/msp"
    echo "[ENROLL] Admin enrolled."
fi

# Enroll each RSU identity
for i in $(seq $START $END); do
    NODE_ID=$((N_VEHICLES + i))
    RSU_NAME="rsu-$NODE_ID"
    RSU_WALLET="$WALLET_DIR/$RSU_NAME"

    if [ -d "$RSU_WALLET/msp/signcerts" ]; then
        echo "[ENROLL] $RSU_NAME already enrolled — skipping"
        continue
    fi

    echo "[ENROLL] Registering + enrolling $RSU_NAME (node_id=$NODE_ID)..."

    # Register
    export FABRIC_CA_CLIENT_HOME="$WALLET_DIR/admin"
    fabric-ca-client register \
        --id.name "$RSU_NAME" \
        --id.secret "${RSU_NAME}pw" \
        --id.type client \
        --id.affiliation org1.department1 \
        --caname ca-org1 \
        --tls.certfiles "$CA_CERT" \
        2>/dev/null || echo "  (may already be registered — proceeding to enroll)"

    # Enroll
    mkdir -p "$RSU_WALLET"
    export FABRIC_CA_CLIENT_HOME="$RSU_WALLET"
    fabric-ca-client enroll \
        -u "https://${RSU_NAME}:${RSU_NAME}pw@localhost:7054" \
        --caname ca-org1 \
        --tls.certfiles "$CA_CERT" \
        -M "$RSU_WALLET/msp"

    echo "[ENROLL] ✅ $RSU_NAME enrolled → $RSU_WALLET/msp"
done

echo ""
echo "=== Enrollment complete for $STAGE ==="
echo "    Wallet directory: $WALLET_DIR"
echo "    Next: cd $BRIDGE_DIR && N_RSUS=$((END-START+1)) node index.js"
