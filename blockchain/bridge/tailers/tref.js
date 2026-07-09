'use strict';
// tailers/tref.js
// MobiGuard Bridge — Distributed time reference commit tailer
//
// Tails results_routing/bc_tref_log.csv in real time (written by NS-3
// crypto_layer.h's update_T_ref() via bc_commit_tref_to_chain() on every
// T_SYNC_INTERVAL tick).
//
// For each new CSV row this module:
//   1. Calls CommitTRef(seq, tRefValue, epsRef, committedAt) using the
//      reporting RSU's own Fabric identity (rsu-<rsu_id>).
//
// Chaincode function used (tref.go, eq:time_consensus):
//   CommitTRef(seq int, tRefValue float64, epsRef float64, committedAt int64)
//
// T_ref(t) = median_j tau_j(t), j=1..n_RSU (eq:time_consensus). Committing
// it on-chain is what makes eq:delay_updated's "t_send, t_recv anchored to
// T_ref(t)" a genuine defense — once committed, a compromised RSU cannot
// retroactively claim it observed a different T_ref at a given moment.
// Commits are periodic (every T_SYNC_INTERVAL seconds) and monotonically
// sequenced. Duplicate seq errors are safe to ignore on bridge restart.

const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc = require('../fabric-client');

const CSV_PATH = '/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/bc_tref_log.csv';

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
    const tRefValue   = parseFloat(row.t_ref_value);
    const epsRef      = parseFloat(row.eps_ref);
    const tsMs        = parseInt(row.timestamp_ms);
    const identity    = identityFor(rsuId);
    const wallTime    = utcNow();

    try {
        await fc.submit(identity, 'CommitTRef', seq, tRefValue, epsRef, tsMs);

        console.log('');
        console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
        console.log(`  ║  🕒  T_REF COMMITTED  (eq:time_consensus)                   ║`);
        console.log(`  ║     time         : ${wallTime}             ║`);
        console.log(`  ║     rsu          : ${String(rsuId).padEnd(56)} ║`);
        console.log(`  ║     seq          : ${String(seq).padEnd(56)} ║`);
        console.log(`  ║     T_ref        : ${String(tRefValue).padEnd(56)} ║`);
        console.log(`  ║     eps_ref      : ${String(epsRef).padEnd(56)} ║`);
        console.log(`  ║     ledger       : COMMITTED to T_ref audit trail          ║`);
        console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
        console.log('');

    } catch (err) {
        const msg = err.message || '';
        if (msg.includes('already committed')) {
            console.log(`[${wallTime}] [TREF]  DUPLICATE  seq=${seq}  (skip)`);
        } else {
            console.warn(`[${wallTime}] [TREF]  ERROR      seq=${seq}  → ${msg}`);
        }
    }
}

function start() {
    console.log(`[BRIDGE] T_ref tailer watching: ${CSV_PATH}`);

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
                columns: ['rsu_id', 'seq', 't_ref_value', 'eps_ref', 'timestamp_ms'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(record);
        } catch (err) {
            console.warn(`[BRIDGE] T_ref parse error: ${err.message}  line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] T_ref tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
