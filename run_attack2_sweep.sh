#!/bin/bash
# run_attack2_sweep.sh
# Runs the full sweep for Attack 2 (Data Plane Selective Time Delay)
# Across percentages: 0, 20, 40, 60, 80, 100

cd ~/ns-allinone-3.35/ns-3.35

percentages=(0 20 40 60 80 100)

for p in "${percentages[@]}"; do
    echo "=================================================="
    echo "Starting Attack 2 Simulation at $p%..."
    echo "=================================================="
    ./waf --run "scratch/routing --routing_test=false --N_Vehicles=200 --N_RSUs=64 --N_Controllers=4 --mobility_scenario=0 --maxspeed=150 --use_sumo_mobility=1 --simTime=16 --architecture=3 --attack_number=2 --attack_percentage=$p" > "results_routing/Attack2_${p}_run.log" 2>&1
    echo "Completed $p%."
done

echo "All simulations finished! Check the results_routing directory for the CSVs."
