'use strict';
// tailers/model.js
// MobiGuard Bridge — Federated model hash commit tailer
//
// Tails results_routing/bc_model_log.csv in real time (written by NS-3
// blockchain_sim.h's bc_commit_model_hash() on each federated training round).
//
// For each new CSV row this module:
//   1. Calls CommitModelHash(round, hash, committedAt) using the reporting
//      RSU's own Fabric identity (rsu-<rsu_id>).
//
// Chaincode function used (model.go, Eq 3.39):
//   CommitModelHash(round int, hash string, committedAt int64) error
//
// The chaincode enforces:
//   - RSU-only writes (caller identity checked via requireRSU)
//   - Duplicate key rejection: model:{rsuId}:{round} must not already exist
//   - Verified=false on create; VerifyModelHash() sets it true during BRFA-v2

const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc = require('../fabric-client');

const CSV_PATH = '/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/bc_model_log.csv';

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
    const round      = parseInt(row.round);
    const modelHash  = row.model_hash;
    const tsMs       = parseInt(row.timestamp_ms);
    const identity   = identityFor(rsuId);
    const wallTime   = utcNow();

    try {
        await fc.submit(identity, 'CommitModelHash', round, modelHash, tsMs);

        console.log('');
        console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
        console.log(`  ║  🔵  MODEL HASH COMMITTED TO LEDGER  (Eq 3.39)              ║`);
        console.log(`  ║     time      : ${wallTime}                ║`);
        console.log(`  ║     rsu       : ${String(rsuId).padEnd(56)} ║`);
        console.log(`  ║     round     : ${String(round).padEnd(56)} ║`);
        console.log(`  ║     hash[0:8] : ${modelHash.slice(0, 16).padEnd(56)} ║`);
        console.log(`  ║     status    : Verified=false (pending BRFA-v2 step 2)     ║`);
        console.log(`  ║     ledger    : COMMITTED                                   ║`);
        console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
        console.log('');

    } catch (err) {
        const msg = err.message || '';
        if (msg.includes('already exists')) {
            console.log(`[${wallTime}] [MODEL]  DUPLICATE  rsu=${rsuId}  round=${round}  (skip)`);
        } else {
            console.warn(`[${wallTime}] [MODEL]  ERROR      rsu=${rsuId}  round=${round}  → ${msg}`);
        }
    }
}

function start() {
    console.log(`[BRIDGE] Model tailer watching: ${CSV_PATH}`);

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
                columns: ['rsu_id', 'round', 'model_hash', 'timestamp_ms'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(record);
        } catch (err) {
            console.warn(`[BRIDGE] Model parse error: ${err.message}  line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] Model tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
