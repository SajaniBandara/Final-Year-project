#!/bin/bash
SPEEDS=(0 10 20 30 40 50 60 150)

for S in "${SPEEDS[@]}"; do
    # Convert km/h to m/s
    if [ "$S" -eq 0 ]; then
        MS_SPEED="0.001" # Barely moving to avoid SUMO stationary vehicle departure errors
    else
        MS_SPEED=$(echo "scale=3; $S / 3.6" | bc)
    fi
    echo "============================================="
    echo "Generating trace for ${S} km/h (MaxSpeed = ${MS_SPEED} m/s)..."
    
    # Update maxSpeed in all trip files
    for f in trips_car_1000.xml trips_bus_1000.xml trips_lorry_1000.xml trips_van_1000.xml trips_truck_1000.xml; do
        sed -i "s/maxSpeed=\"[0-9.]*\"/maxSpeed=\"${MS_SPEED}\"/" "$f"
    done
    
    # 1. Run headless SUMO to generate physics data
    echo "Running SUMO simulation..."
    sumo -c test_osm_1000.sumocfg --fcd-output fcd_output_${S}.xml > /dev/null 2>&1
    
    # 2. Convert physics data into NS-3 .tcl format
    echo "Converting to NS-3 format..."
    python3 $SUMO_HOME/tools/traceExporter.py \
      --fcd-input fcd_output_${S}.xml \
      --ns2mobility-output /home/user/mobility/mobility_urban_${S}.tcl \
      --net osm.net.xml
      
    echo "Successfully created: /home/user/mobility/mobility_urban_${S}.tcl!"
done

# Restore original 150 km/h (41.67 m/s) maxSpeed so the repo stays clean
echo "Restoring 150 km/h baseline..."
for f in trips_car_1000.xml trips_bus_1000.xml trips_lorry_1000.xml trips_van_1000.xml trips_truck_1000.xml; do
    sed -i "s/maxSpeed=\"[0-9.]*\"/maxSpeed=\"41.67\"/" "$f"
done

echo "All 7 mobility files successfully generated!"
