# Final Year Project

This project contains an NS-3 based routing simulation with attack-aware routing logic and visualization support through NetAnim. The main focus of this branch is the selective time delay attack scenario, but the simulation also supports baseline runs and other attack variants through command-line flags.

## Project Files

- `routing.cc` - main NS-3 simulation file
- `LDA(2).cc` - related attack and detection logic
- `optimization.py` and `optimization_lifetime.py` - analysis / optimization helpers
- `LDA_security(1) (1).py` and `LDA_PQ_security(1) (1).py` - supporting Python scripts

## Requirements

- NS-3.35
- NetAnim 3.108
- A Linux environment

## Setup

Before running the simulation, copy the updated `routing.cc` into the NS-3 scratch folder:

```bash
cp "/home/user/Final Year Project/1. Attacks/Final-Year-project/routing.cc" ~/ns-allinone-3.35/ns-3.35/scratch/routing.cc
```

If you edit the local file again, repeat the copy step so NS-3 uses the latest version.

## Build

From the NS-3 root directory:

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf configure
./waf build
```

## Running the Simulation

The simulation is launched with `waf` and the `scratch/routing` program.

### Baseline Run

Run the routing model with the default settings:

```bash
./waf --run "scratch/routing"
```

### Selective Time Delay Attack Run

The selective time delay attack is enabled with the following command-line arguments:

```bash
./waf --run "scratch/routing --routing_test=true --routing_algorithm=4 --experiment_number=3 --active_attack_variant=1"
```

This configuration means:

- `routing_test=true` enables the test routing path used for attack verification
- `routing_algorithm=4` selects the proposed routing method
- `experiment_number=3` runs the network size experiment
- `active_attack_variant=1` activates Attack 2, the selective time delay scenario

## Useful Command-Line Flags

The simulation exposes several command-line options through NS-3 `CommandLine` parsing:

- `N_RSUs` - number of RSUs
- `N_Vehicles` - number of vehicles
- `data_transmission_frequency` - packet transmission frequency
- `link_lifetime_threshold` - lifetime threshold used by the routing logic
- `simTime` - total simulation time
- `mobility_scenario` - mobility setting
- `architecture` - routing architecture mode
- `maxspeed` - maximum node speed
- `lambda` - traffic parameter used in the model
- `experiment_number` - experiment selector
- `routing_test` - enables the test routing path
- `routing_algorithm` - selects the routing algorithm

The code currently uses these routing algorithm values:

- `0` - ECMP
- `1` - RR
- `2` - QR-SDN
- `3` - RLMR
- `4` - proposed
- `5` - DCMR

## Attack Variants

The `active_attack_variant` flag controls which attack is active during the run. The code uses 0-based indexing for the attack tag helper, so:

- `0` - Attack 1
- `1` - Attack 2, selective time delay
- `2` - Attack 3
- `3` - Attack 4
- `4` - Attack 5
- `5` - Attack 6
- `6` - Attack 7
- `7` - Attack 8, passive hidden forwarding

If `active_attack_variant` is left at `-1`, the simulation falls back to the baseline configuration.

## NetAnim Visualization

After running the simulation, you can open NetAnim separately:

```bash
~/ns-allinone-3.35/netanim-3.108/NetAnim
```

Load the generated animation file from the NS-3 output directory to inspect node movement, routing behavior, and attack effects.

## Example Workflow

1. Copy the latest `routing.cc` into the NS-3 scratch folder.
2. Build NS-3 if the source changed.
3. Run the selective time delay scenario with the attack flags.
4. Open NetAnim to inspect the generated trace.

Example:

```bash
cp "/home/user/Final Year Project/1. Attacks/Final-Year-project/routing.cc" ~/ns-allinone-3.35/ns-3.35/scratch/routing.cc
cd ~/ns-allinone-3.35/ns-3.35
./waf build
./waf --run "scratch/routing --routing_test=true --routing_algorithm=4 --experiment_number=3 --active_attack_variant=1"
~/ns-allinone-3.35/netanim-3.108/NetAnim
```

## Notes

- Keep the `routing.cc` copy in the NS-3 scratch folder in sync with the project copy.
- If you want to compare attack and no-attack behavior, run the same simulation once with `active_attack_variant=1` and once with `active_attack_variant=-1`.
- The simulation code also contains support for other attack variants, so the README can be extended later with those scenarios if needed.
