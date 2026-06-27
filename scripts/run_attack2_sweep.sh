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
    
    # We pass the attack percentage to the script along with Architecture 3 parameters.
    ./waf --run "scratch/routing --routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --simTime=40 --architecture=3 --attack_number=2 --attack_percentage=$p" > "results_routing/Attack2_${p}_percent_log.txt" 2>&1
    
    # Save the optimization files for each percentage run so they don't get overwritten
    cp scratch/optimization_link_lifetime_data.csv results_routing/optimization_lifetime_Attack2_${p}.csv    
    echo " Finished running $p%. Check results_routing/ for outputs."
    sleep 2
done

echo "Sweep completed successfully!"
