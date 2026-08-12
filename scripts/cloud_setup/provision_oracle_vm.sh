#!/usr/bin/env bash
# provision_oracle_vm.sh
#
# One-time setup for a fresh Ubuntu VM (e.g. an Oracle Cloud Always-Free
# Ampere A1 instance) to build and run the MOBIGUARD NS-3 simulation for
# LSTM training-data collection.
#
# routing.cc and several launcher scripts hardcode absolute paths under
# /home/sdvn_hidden_attacks/... (see scripts/local_path_swap.sh, which
# handles the same problem for a different personal machine). Rather than
# rewriting those paths for yet another machine, this script assumes it is
# being run AS a Linux user named sdvn_hidden_attacks, so nothing in the
# repo needs to change. Create that user first, then run this script as it:
#
#   sudo useradd -m -s /bin/bash sdvn_hidden_attacks
#   sudo passwd sdvn_hidden_attacks          # or: sudo mkdir -p /home/sdvn_hidden_attacks/.ssh && copy in a pubkey
#   sudo su - sdvn_hidden_attacks
#   bash provision_oracle_vm.sh
set -euo pipefail

if [ "$(whoami)" != "sdvn_hidden_attacks" ]; then
    echo "Run this as user 'sdvn_hidden_attacks' (see header comment) --" >&2
    echo "routing.cc hardcodes /home/sdvn_hidden_attacks/... paths." >&2
    exit 1
fi

GITHUB_REPO="https://github.com/SajaniBandara/Final-Year-project.git"
NS3_TARBALL="https://www.nsnam.org/releases/ns-allinone-3.35.tar.bz2"
NS3_DIR="$HOME/ns3_g13/ns-allinone-3.35/ns-3.35"
REPO_DIR="$HOME/ns3_g13/g13_project_repo/Final-Year-project"
MOBILITY_DIR="$HOME/ns3_g13/mobility"

echo "==> [1/6] Installing system packages"
sudo apt-get update
sudo apt-get install -y build-essential cmake git python3 python3-pip python3-dev \
    libssl-dev pkg-config wget bzip2

echo "==> [2/6] Building liboqs (Open Quantum Safe)"
if [ ! -f /usr/local/include/oqs/oqs.h ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git ~/liboqs
    cd ~/liboqs && mkdir -p build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON ..
    make -j"$(nproc)"
    sudo make install
    sudo ldconfig
else
    echo "  liboqs already installed, skipping"
fi

echo "==> [3/6] Downloading + building NS-3.35"
mkdir -p "$HOME/ns3_g13"
if [ ! -d "$NS3_DIR" ]; then
    cd "$HOME/ns3_g13"
    wget -q "$NS3_TARBALL" -O ns-allinone-3.35.tar.bz2
    tar xjf ns-allinone-3.35.tar.bz2
    cd ns-allinone-3.35
    ./build.py
else
    echo "  NS-3.35 already present at $NS3_DIR, skipping"
fi

echo "==> [4/6] Cloning project repo (also pulls the mobility/*.tcl traces -- they're git-tracked)"
mkdir -p "$(dirname "$REPO_DIR")"
if [ ! -d "$REPO_DIR" ]; then
    git clone "$GITHUB_REPO" "$REPO_DIR"
else
    git -C "$REPO_DIR" pull
fi

echo "==> [5/6] Populating the flat mobility/ dir that routing.cc's hardcoded paths expect"
mkdir -p "$MOBILITY_DIR"
cp -n "$REPO_DIR"/mobility/*.tcl "$MOBILITY_DIR"/
echo "  $(ls "$MOBILITY_DIR" | wc -l) trace files in $MOBILITY_DIR"

echo "==> [6/6] Syncing scratch files, writing the crypto-linking wscript, building"
cd "$REPO_DIR"
python3 scripts/run_std_attacks.py --build || true   # first pass creates scratch/routing/; link fails until the wscript below exists

mkdir -p "$NS3_DIR/scratch/routing"
cat > "$NS3_DIR/scratch/routing/wscript" << 'EOF'
import os

def build(bld):
    obj = bld.create_ns3_program('routing', bld.env['NS3_ENABLED_MODULES'])
    obj.source  = ['routing.cc']
    obj.lib     = ['oqs', 'ssl', 'crypto']
    obj.libpath = ['/usr/local/lib']
    obj.rpath   = ['/usr/local/lib']
EOF

python3 scripts/run_std_attacks.py --build

echo
echo "==> Setup complete. Sanity-check with a short run:"
echo "cd $NS3_DIR && ./waf --run-no-build \"scratch/routing/routing --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --architecture=3 --simTime=20 --sim_seed=1\""
