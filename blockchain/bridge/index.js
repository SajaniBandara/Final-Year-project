'use strict';
// index.js
// MobiGuard Bridge — main entry point
//
// Startup sequence:
//   1. Read RSU config JSON (positions + node IDs) for current stage.
//   2. Enrol Fabric identity connections for all RSUs in the stage.
//   3. Register RSUs + controllers on-chain via RegisterRSU / RegisterController.
//   4. Run AutoAssignController for each RSU (Eq 3.51, nearest-controller).
//   5. Start real-time tailers for bc_flowmod_log.csv and bc_trust_updates.csv.
//   6. Print startup summary and keep alive until Ctrl-C.
//
// Usage:
//   node index.js                              # uses rsu_config_stage1.json
//   N_RSUS=16 N_CONTROLLERS=2 node index.js   # uses rsu_config_stage2.json
//   N_RSUS=64 N_CONTROLLERS=4 node index.js   # uses rsu_config_stage3.json

const path    = require('path');
const fs      = require('fs');
const fc      = require('./fabric-client');
const flowmod    = require('./tailers/flowmod');
const trust      = require('./tailers/trust');
const detection  = require('./tailers/detection');
const model      = require('./tailers/model');
const dkg        = require('./tailers/dkg');
const anchor     = require('./tailers/anchor');

// ─────────────────────────────────────────────────────────────────────────────
// Config: select stage based on env vars
// ─────────────────────────────────────────────────────────────────────────────
const N_RSUS        = parseInt(process.env.N_RSUS        || '4');
const N_CONTROLLERS = parseInt(process.env.N_CONTROLLERS || '1');

// Stage config files live alongside index.js.
// Each file contains: { rsus: [{id, node_id, lat, lng}], controllers: [{id, lat, lng}] }
const stageName   = `stage${N_RSUS <= 4 ? 1 : N_RSUS <= 16 ? 2 : 3}`;
const configPath  = path.join(__dirname, `rsu_config_${stageName}.json`);

// Sim parameters from routing.cc
const N_VEHICLES  = 200; // N_Vehicles in routing.cc

// ─────────────────────────────────────────────────────────────────────────────
// loadConfig()
// Loads or auto-generates the RSU config for the current stage.
// For Stage 1, generates a minimal 4-RSU / 1-controller config if none exists.
// ─────────────────────────────────────────────────────────────────────────────
function loadConfig() {
    if (fs.existsSync(configPath)) {
        return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }

    // Auto-generate Stage 1 config: 4 RSUs in a 2km×2km grid, 1 central controller.
    // RSU node IDs = N_VEHICLES + rsu_index (matching routing.cc convention).
    // Positions are approximate — replace with actual SUMO coordinates.
    console.warn(`[BRIDGE] ${configPath} not found — generating default Stage 1 config`);
    const config = {
        rsus: [
            { id: 'rsu-200', node_id: 200, lat: 51.500, lng: -0.100 },
            { id: 'rsu-201', node_id: 201, lat: 51.502, lng: -0.100 },
            { id: 'rsu-202', node_id: 202, lat: 51.500, lng: -0.098 },
            { id: 'rsu-203', node_id: 203, lat: 51.502, lng: -0.098 },
        ],
        controllers: [
            { id: 'ctrl-0', lat: 51.501, lng: -0.099 },
        ],
    };
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    return config;
}

// ─────────────────────────────────────────────────────────────────────────────
// buildIdentityMap()
// Returns { node_id: identity_name } for all RSUs in config.
// Identity name matches the wallet directory produced by fabric-ca-client enroll.
// ─────────────────────────────────────────────────────────────────────────────
function buildIdentityMap(rsus) {
    const map = {};
    for (const rsu of rsus) {
        map[rsu.node_id] = rsu.id; // e.g. 200 → 'rsu-200'
    }
    return map;
}

// ─────────────────────────────────────────────────────────────────────────────
// registerNetwork()
// Registers RSUs + controllers on-chain and runs AutoAssignController.
// Called once at bridge startup before tailers start.
// ─────────────────────────────────────────────────────────────────────────────
async function registerNetwork(config) {
    const timestamp = Date.now(); // ms since epoch (used as sim timestamp)

    // Register controllers first (RSU AutoAssign needs them to exist)
    console.log('[BRIDGE] Registering controllers on-chain...');
    for (const ctrl of config.controllers) {
        try {
            await fc.submit('admin', 'RegisterController',
                ctrl.id,
                String(ctrl.lat),
                String(ctrl.lng),
                String(timestamp));
            console.log(`[BRIDGE→BC] RegisterController ${ctrl.id} lat=${ctrl.lat} lng=${ctrl.lng} → status:200`);
        } catch (err) {
            // Ignore "already registered" errors on restart
            if (err.message && err.message.includes('already registered')) {
                console.log(`[BRIDGE→BC] RegisterController ${ctrl.id} → already registered (skip)`);
            } else {
                console.warn(`[BRIDGE→BC] RegisterController ${ctrl.id} → ${err.message}`);
            }
        }
    }

    // Register RSUs + auto-assign to nearest trusted controller (Eq 3.51)
    console.log('[BRIDGE] Registering RSUs and running AutoAssignController...');
    for (const rsu of config.rsus) {
        const identity = rsu.id; // use RSU's own Fabric identity for writes

        // RegisterRSU
        try {
            await fc.submit(identity, 'RegisterRSU',
                rsu.id,
                String(rsu.lat),
                String(rsu.lng),
                String(timestamp));
            console.log(`[BRIDGE→BC] RegisterRSU ${rsu.id} lat=${rsu.lat} lng=${rsu.lng} → status:200`);
        } catch (err) {
            if (err.message && err.message.includes('already registered')) {
                console.log(`[BRIDGE→BC] RegisterRSU ${rsu.id} → already registered (skip)`);
            } else {
                console.warn(`[BRIDGE→BC] RegisterRSU ${rsu.id} → ${err.message}`);
            }
        }

        // AutoAssignController (Eq 3.51: arg min d(rk, ci) over Ctrusted)
        try {
            await fc.submit(identity, 'AutoAssignController',
                rsu.id,
                String(timestamp));
            // Query the assignment for confirmation log
            const raw        = await fc.evaluate(identity, 'QueryControllerAssignment', rsu.id);
            const assignment = JSON.parse(raw);
            console.log(`[BRIDGE→BC] AutoAssignController ${rsu.id} → assigned to ${assignment.controllerId}`);
        } catch (err) {
            console.warn(`[BRIDGE→BC] AutoAssignController ${rsu.id} → ${err.message}`);
        }
    }

    console.log('[BRIDGE] Network registration complete.\n');
}

// ─────────────────────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────────────────────
async function main() {
    console.log('╔══════════════════════════════════════════════════════╗');
    console.log('║  MobiGuard Bridge — NS-3 ↔ Hyperledger Fabric        ║');
    console.log(`║  Stage: ${stageName.padEnd(10)} RSUs: ${N_RSUS}  Controllers: ${N_CONTROLLERS}       ║`);
    console.log('╚══════════════════════════════════════════════════════╝\n');

    // 1. Load RSU/controller config
    const config = loadConfig();
    console.log(`[BRIDGE] Loaded config: ${config.rsus.length} RSUs, ${config.controllers.length} controllers`);

    // 2. Build and share identity map with tailers
    const identityMap = buildIdentityMap(config.rsus);
    flowmod.setIdentityMap(identityMap);
    trust.setIdentityMap(identityMap);
    detection.setIdentityMap(identityMap);
    model.setIdentityMap(identityMap);
    dkg.setIdentityMap(identityMap);
    anchor.setIdentityMap(identityMap);

    // 3. Register network on-chain (idempotent — safe to re-run on restart)
    await registerNetwork(config);

    // 4. Start real-time CSV tailers
    const fmTail     = flowmod.start();
    const tTail      = trust.start();
    const dTail      = detection.start();
    const mTail      = model.start();
    const dkgTail    = dkg.start();
    const anchorTail = anchor.start();

    console.log('\n[BRIDGE] ✅ Real-time tailers active. Waiting for NS-3 events...');
    console.log('[BRIDGE]    FlowMod CSV   → LogFlowMod / EndorseFlowMod / MarkFlowModUnauthorized');
    console.log('[BRIDGE]    Trust CSV     → UpdateTrust → IsActivePeer (demotion/removal check)');
    console.log('[BRIDGE]    Detection CSV → LogDetection (eq:rsu_write, S1-S8 per signal)');
    console.log('[BRIDGE]    Model CSV     → CommitModelHash (Eq 3.39, per training round)');
    console.log('[BRIDGE]    DKG CSV       → CommitDKG (eq:vk_commit / eq:vk_commit_rotated)');
    console.log('[BRIDGE]    Anchor CSV    → AnchorGlobal (eq:anchor_hash, periodic)');
    console.log('[BRIDGE]    Press Ctrl-C to stop.\n');

    // 5. Graceful shutdown
    process.on('SIGINT', () => {
        console.log('\n[BRIDGE] Shutting down...');
        fmTail.unwatch();
        tTail.unwatch();
        dTail.unwatch();
        mTail.unwatch();
        dkgTail.unwatch();
        anchorTail.unwatch();
        fc.close();
        process.exit(0);
    });

    // 6. Keep-alive health snapshot: every 30s query all RSU trust scores
    //    and print a structured evidence table for supervisor verification.
    setInterval(async () => {
        try {
            const wallTime = new Date().toISOString().replace('T',' ').slice(0,23) + ' UTC';
            const raw      = await fc.evaluate('admin', 'QueryPeerSelection');
            const result   = JSON.parse(raw);
            const nActive  = result.activePeers  ? result.activePeers.length  : '?';
            const nDemoted = result.demotedClients? result.demotedClients.length: '?';
            const nRemoved = result.removedNodes  ? result.removedNodes.length  : '?';

            console.log('');
            console.log(`  ┌─────────────────────────────────────────────────────────────┐`);
            console.log(`  │  BLOCKCHAIN STATUS SNAPSHOT  —  ${wallTime}  │`);
            console.log(`  ├──────────────┬────────────┬───────────┬─────────────────────┤`);
            console.log(`  │  RSU ID      │  SCORE     │  STATUS   │  ASSIGNED CTRL      │`);
            console.log(`  ├──────────────┼────────────┼───────────┼─────────────────────┤`);

            // Query each RSU in this stage
            for (const rsu of config.rsus) {
                const id       = rsu.id;
                const nodeId   = String(rsu.node_id);
                const identity = identityMap[rsu.node_id] || 'admin';

                let score  = '?????';
                let status = 'UNKNOWN  ';
                let ctrl   = '?';

                try {
                    const tRaw   = await fc.evaluate(identity, 'QueryTrust', nodeId);
                    const trust  = JSON.parse(tRaw);
                    score = String(trust.score).padStart(5);
                    if (trust.score >= 3000)      status = 'ACTIVE   ';
                    else if (trust.score >= 1000) status = 'DEMOTED  ';
                    else                          status = 'REMOVED  ';
                } catch (_) {}

                try {
                    const aRaw = await fc.evaluate(identity, 'QueryControllerAssignment', id);
                    const asgn = JSON.parse(aRaw);
                    ctrl = asgn.controllerId;
                } catch (_) {}

                console.log(`  │  ${id.padEnd(12)}│  ${score}     │  ${status}│  ${ctrl.padEnd(20)} │`);
            }

            console.log(`  ├──────────────┴────────────┴───────────┴─────────────────────┤`);
            console.log(`  │  Network: active=${nActive}  demoted=${nDemoted}  removed=${nRemoved}                           │`);
            console.log(`  └─────────────────────────────────────────────────────────────┘`);
            console.log('');

        } catch (err) {
            // Non-fatal — just skip this snapshot cycle
        }
    }, 30_000);
}

main().catch((err) => {
    console.error('[BRIDGE] Fatal error:', err);
    process.exit(1);
});
