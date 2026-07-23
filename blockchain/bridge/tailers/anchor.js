'use strict';
// tailers/anchor.js
// MobiGuard Bridge — Global anchor commit tailer
//
// Tails results_routing/bc_anchor_log.csv in real time (written by NS-3
// blockchain_sim.h's bc_anchor_to_global() on every T_SYNC_INTERVAL tick).
//
// For each new CSV row this module:
//   1. Calls AnchorGlobal(seq, anchorHash, rsuChainLen, committedAt) using
//      the reporting RSU's own Fabric identity (rsu-<rsu_id>).
//
// Chaincode function used (anchor.go, eq:anchor_hash):
//   AnchorGlobal(seq int, anchorHash string, rsuChainLen int, committedAt int64)
//
// H_anchor^(r) = H(H_root^RSU ‖ ts_anchor ‖ H_prev^global)
// Anchors are periodic (every T_SYNC_INTERVAL seconds) and monotonically
// sequenced. Duplicate seq errors are safe to ignore on bridge restart.

const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc = require('../fabric-client');

const CSV_PATH = '/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/bc_anchor_log.csv';

let identityMap = {};

function setIdentityMap(map) {
    identityMap = map;
}

function identityFor(nodeId) {
    return identityMap[nodeId] || 'admin';
}

function utcNow() { return new Date().toISOString().replace('T', ' ').slice(0, 23) + ' UTC'; }

async function handleRow(row) {
    const rsuId       = parseInt(row.rsu_id);
    const seq         = parseInt(row.seq);
    const anchorHash  = row.anchor_hash;
    const rsuChainLen = parseInt(row.rsu_chain_len);
    const tsMs        = parseInt(row.timestamp_ms);
    const identity    = identityFor(rsuId);
    const wallTime    = utcNow();

    try {
        await fc.submit(identity, 'AnchorGlobal', seq, anchorHash, rsuChainLen, tsMs);

        console.log('');
        console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
        console.log(`  ║  ⚓  GLOBAL ANCHOR COMMITTED  (eq:anchor_hash)              ║`);
        console.log(`  ║     time         : ${wallTime}             ║`);
        console.log(`  ║     rsu          : ${String(rsuId).padEnd(56)} ║`);
        console.log(`  ║     seq          : ${String(seq).padEnd(56)} ║`);
        console.log(`  ║     rsuChainLen  : ${String(rsuChainLen).padEnd(56)} ║`);
        console.log(`  ║     hash[0:8]    : ${anchorHash.slice(0, 16).padEnd(56)} ║`);
        console.log(`  ║     ledger       : COMMITTED to global anchor chain         ║`);
        console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
        console.log('');

    } catch (err) {
        const msg = err.message || '';
        if (msg.includes('already committed')) {
            console.log(`[${wallTime}] [ANCHOR]  DUPLICATE  seq=${seq}  (skip)`);
        } else {
            console.warn(`[${wallTime}] [ANCHOR]  ERROR      seq=${seq}  → ${msg}`);
        }
    }
}

function start() {
    console.log(`[BRIDGE] Anchor tailer watching: ${CSV_PATH}`);

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
                columns: ['rsu_id', 'seq', 'anchor_hash', 'rsu_chain_len', 'timestamp_ms'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(record);
        } catch (err) {
            console.warn(`[BRIDGE] Anchor parse error: ${err.message}  line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] Anchor tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
