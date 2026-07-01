'use strict';
// tailers/dkg.js
// MobiGuard Bridge — DKG ceremony / key-rotation commit tailer
//
// Tails results_routing/bc_dkg_log.csv in real time (written by NS-3
// blockchain_sim.h's bc_commit_dkg() on ceremony start and each rotation).
//
// For each new CSV row this module:
//   1. Calls CommitDKG(round, vkZKP, nRSUs, committedAt) using the
//      reporting RSU's Fabric identity (rsu-<rsu_id>).
//
// Chaincode function used (dkg.go, eq:vk_commit / eq:vk_commit_rotated):
//   CommitDKG(round int, vkZKP string, nRSUs int, committedAt int64) error
//
// round=1: initial DKG ceremony (eq:vk_commit)
// round>1: key rotations (eq:vk_commit_rotated, triggered by eq:key_rotation_trigger)

const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc = require('../fabric-client');

const CSV_PATH = '/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/bc_dkg_log.csv';

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
    const vkZKP     = row.vk_zkp;
    const nRSUs     = parseInt(row.n_rsus);
    const tsMs      = parseInt(row.timestamp_ms);
    const identity  = identityFor(rsuId);
    const wallTime  = utcNow();
    const label     = round === 1 ? 'CEREMONY' : `ROTATION (round ${round})`;

    try {
        await fc.submit(identity, 'CommitDKG', round, vkZKP, nRSUs, tsMs);

        console.log('');
        console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
        console.log(`  ║  🔐  DKG ${label.padEnd(52)} ║`);
        console.log(`  ║     time      : ${wallTime}                ║`);
        console.log(`  ║     rsu       : ${String(rsuId).padEnd(56)} ║`);
        console.log(`  ║     round     : ${String(round).padEnd(56)} ║`);
        console.log(`  ║     nRSUs     : ${String(nRSUs).padEnd(56)} ║`);
        console.log(`  ║     vkZKP[0:8]: ${vkZKP.slice(0, 16).padEnd(56)} ║`);
        console.log(`  ║     eq        : ${(round === 1 ? 'eq:vk_commit' : 'eq:vk_commit_rotated').padEnd(56)} ║`);
        console.log(`  ║     ledger    : COMMITTED to global anchor chain            ║`);
        console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
        console.log('');

    } catch (err) {
        const msg = err.message || '';
        if (msg.includes('already exists')) {
            console.log(`[${wallTime}] [DKG]  DUPLICATE  round=${round}  (skip)`);
        } else {
            console.warn(`[${wallTime}] [DKG]  ERROR      round=${round}  → ${msg}`);
        }
    }
}

function start() {
    console.log(`[BRIDGE] DKG tailer watching: ${CSV_PATH}`);

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
                columns: ['rsu_id', 'round', 'vk_zkp', 'n_rsus', 'timestamp_ms'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(record);
        } catch (err) {
            console.warn(`[BRIDGE] DKG parse error: ${err.message}  line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] DKG tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
