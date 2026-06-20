#!/bin/bash

# Define the percentages to sweep over
PERCENTAGES=(0 20 40 60 80 100)

echo "Starting Attack 2 (Data Plane / Selective Time Delay) Sweep..."

# Make sure we're in the ns-3.35 directory before running waf
# This script should ideally be run from the ns-3.35 directory,
# but we can navigate there if needed.
NS3_DIR="$HOME/ns-allinone-3.35/ns-3.35"
if [ ! -d "$NS3_DIR" ]; then
    echo "Error: ns-3 directory not found at $NS3_DIR"
    exit 1
fi

cd "$NS3_DIR"

for p in "${PERCENTAGES[@]}"; do
    echo "====================================================="
    echo " Running Attack 2 with $p% malicious nodes..."
    echo "====================================================="
    
    # We pass the attack percentage to the script.
    # Note: Make sure --attack2_percentage=X or the relevant flag is accepted by routing.cc.
    # If the user script handles standard command line args:
    ./waf --run "scratch/routing --attack_percentage=$p --active_attack_variant=1" > "results_routing/Attack2_${p}_percent_log.txt" 2>&1
    
    echo " Finished running $p%. Check results_routing/ for outputs."
    sleep 2
done

echo "Sweep completed successfully!"
