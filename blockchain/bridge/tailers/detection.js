'use strict';
// tailers/detection.js
// MobiGuard Bridge — Detection event tailer
//
// Tails results_routing/bc_detection_log.csv in real time (written by NS-3
// blockchain_sim.h's bc_write_detection_event() on every LRAD detection).
//
// For each new CSV row this module:
//   1. Calls LogDetection(suspectNode, signatureIdx, timestampMs, rsuSig)
//      using the reporting RSU's own Fabric identity (rsu-<rsu_id>).
//
// Chaincode function used (detection.go):
//   LogDetection(suspectNode, signatureIdx, timestamp, rsuSig)
//
// The chaincode enforces:
//   - RSU-only writes (caller identity checked via requireRSU)
//   - signatureIdx in [1,8] corresponding to S1-S8
//   - No duplicate key {suspectNode}:{timestamp}
//   - Auto-applies trust penalty to suspectNode (eq:trust_update penalty branch)

const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc = require('../fabric-client');

const CSV_PATH = '/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/bc_detection_log.csv';

// Map node_id → fabric identity name.
// Populated by index.js at startup via setIdentityMap().
let identityMap = {};

function setIdentityMap(map) {
    identityMap = map;
}

function identityFor(nodeId) {
    return identityMap[nodeId] || 'admin';
}

function utcNow() { return new Date().toISOString().replace('T', ' ').slice(0, 23) + ' UTC'; }

async function handleRow(row) {
    const rsuId      = parseInt(row.rsu_id);
    const suspect    = row.suspect_node;
    const sigIdx     = parseInt(row.signal_idx);
    const tsMs       = row.timestamp_ms;
    const rsuSig     = row.rsu_sig;
    const identity   = identityFor(rsuId);
    const wallTime   = utcNow();

    try {
        await fc.submit(identity, 'LogDetection', suspect, sigIdx, tsMs, rsuSig);

        console.log('');
        console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
        console.log(`  ║  🔴  DETECTION EVENT COMMITTED TO LEDGER                    ║`);
        console.log(`  ║     time      : ${wallTime}                ║`);
        console.log(`  ║     rsu       : ${String(rsuId).padEnd(56)} ║`);
        console.log(`  ║     suspect   : ${String(suspect).padEnd(56)} ║`);
        console.log(`  ║     signal    : S${sigIdx}  (eq:rsu_write / LogDetection)            ║`);
        console.log(`  ║     action    : trust penalty auto-applied by chaincode      ║`);
        console.log(`  ║     ledger    : COMMITTED                                   ║`);
        console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
        console.log('');

    } catch (err) {
        const msg = err.message || '';
        // Chaincode rejects duplicate key — safe to ignore (same event logged twice)
        if (msg.includes('already logged')) {
            console.log(`[${wallTime}] [DETECT]  DUPLICATE  rsu=${rsuId}  S${sigIdx}  suspect=${suspect}  (skip)`);
        } else if (msg.includes('removed from the system')) {
            console.log(`[${wallTime}] [DETECT]  BLOCKED    rsu=${rsuId}  S${sigIdx}  suspect=${suspect}  reason=already_removed`);
        } else {
            console.warn(`[${wallTime}] [DETECT]  ERROR      rsu=${rsuId}  S${sigIdx}  suspect=${suspect}  → ${msg}`);
        }
    }
}

function start() {
    console.log(`[BRIDGE] Detection tailer watching: ${CSV_PATH}`);

    const tail = new Tail(CSV_PATH, {
        separator: '\n',
        fromBeginning: false,
        useWatchFile: true,
        flushAtEOF: true,
    });

    tail.on('line', async (line) => {
        line = line.trim();
        if (!line || line.startsWith('rsu_id,')) return;

        try {
            const [record] = parse(line, {
                columns: ['rsu_id', 'suspect_node', 'signal_idx', 'timestamp_ms', 'rsu_sig'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(record);
        } catch (err) {
            console.warn(`[BRIDGE] Detection parse error: ${err.message}  line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] Detection tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
