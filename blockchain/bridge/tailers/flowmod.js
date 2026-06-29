'use strict';
// tailers/flowmod.js
// MobiGuard Bridge — FlowMod tailer
//
// Tails results_routing/bc_flowmod_log.csv in real time (written by NS-3
// tcam_attack_helper.h's bc_log_flowmod() on every TCAM rule install).
//
// For each new CSV row this module:
//   1. Calls LogFlowMod(rsuId, flowModHash, recvTimestampMs) using the RSU's
//      own Fabric identity (rsu-<node_id>).
//   2. If a second distinct RSU logs the same hash → calls EndorseFlowMod()
//      to accumulate f+1=2 endorsements (Eq 3.41).
//   3. If is_malicious=1 → calls MarkFlowModUnauthorized() (Eq 3.44).
//
// Chaincode functions used:
//   LogFlowMod(rsuId, flowModHash, recvTimestampMs)
//   EndorseFlowMod(flowModHash, endorserRsuId)
//   MarkFlowModUnauthorized(flowModHash)

const path   = require('path');
const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc     = require('../fabric-client');

const CSV_PATH = '/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/bc_flowmod_log.csv';

// Track which hashes have already been logged by which RSUs.
// seenHashes[hash] = Set of rsu_ids that called LogFlowMod for this hash.
const seenHashes = {};

// Map node_id → fabric identity name.
// Populated by index.js at startup via setIdentityMap().
let identityMap = {};

function setIdentityMap(map) {
    identityMap = map;
}

// Resolve Fabric identity name for a given sim node_id.
// Falls back to 'admin' (Org1 Admin) if no specific identity enrolled yet.
function identityFor(nodeId) {
    return identityMap[nodeId] || 'admin';
}

function utcNow() { return new Date().toISOString().replace('T',' ').slice(0,23) + ' UTC'; }

async function handleRow(row) {
    const rsuId       = row.rsu_id;
    const hash        = row.flow_mod_hash;
    const timestampMs = row.recv_timestamp_ms;
    const isMalicious = parseInt(row.is_malicious) === 1;
    const identity    = identityFor(parseInt(rsuId));
    const wallTime    = utcNow();

    // ── Step 1: LogFlowMod (first sighting of this hash from this RSU) ────────
    if (!seenHashes[hash]) {
        seenHashes[hash] = new Set();
    }

    if (!seenHashes[hash].has(rsuId)) {
        seenHashes[hash].add(rsuId);
        try {
            await fc.submit(identity, 'LogFlowMod', rsuId, hash, timestampMs);
            console.log(`[${wallTime}] [FLOWMOD] LOGGED    rsu=${rsuId}  hash=${hash}  sim_t=${timestampMs}ms  ledger=COMMITTED`);
        } catch (err) {
            // Chaincode returns error if hash already exists (duplicate log from same RSU).
            console.warn(`[${wallTime}] [FLOWMOD] DUPLICATE rsu=${rsuId}  hash=${hash}  → ${err.message}`);
        }
    }

    // ── Step 2: EndorseFlowMod when a second RSU sees the same hash ───────────
    // f+1 = 2 endorsements needed to commit the FlowMod (Eq 3.41).
    if (seenHashes[hash].size === 2) {
        try {
            await fc.submit(identity, 'EndorseFlowMod', hash, rsuId);
            console.log(`[${wallTime}] [FLOWMOD] ENDORSED   rsu=${rsuId}  hash=${hash}  quorum=REACHED (f+1=2 Eq.3.41)  ledger=COMMITTED`);
        } catch (err) {
            console.warn(`[${wallTime}] [FLOWMOD] ENDORSE_FAIL hash=${hash}  → ${err.message}`);
        }
    }

    // ── Step 3: MarkFlowModUnauthorized for malicious installs (Eq 3.44) ─────
    if (isMalicious) {
        try {
            await fc.submit(identity, 'MarkFlowModUnauthorized', hash);
            console.log('');
            console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
            console.log(`  ║  ⚠  MALICIOUS FLOWMOD DETECTED & FLAGGED ON LEDGER          ║`);
            console.log(`  ║     time   : ${wallTime}                   ║`);
            console.log(`  ║     rsu    : ${String(rsuId).padEnd(8)}                                        ║`);
            console.log(`  ║     hash   : ${hash}  ║`);
            console.log(`  ║     action : MarkFlowModUnauthorized (Eq.3.44)               ║`);
            console.log(`  ║     ledger : COMMITTED                                       ║`);
            console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
            console.log('');
        } catch (err) {
            console.warn(`[${wallTime}] [FLOWMOD] UNAUTHORIZED_FAIL hash=${hash}  → ${err.message}`);
        }
    }
}

function start() {
    console.log(`[BRIDGE] FlowMod tailer watching: ${CSV_PATH}`);

    const tail = new Tail(CSV_PATH, {
        separator: '\n',
        fromBeginning: false,  // only new rows after bridge starts
        useWatchFile: true,
        flushAtEOF: true,
    });

    let headerSkipped = false;

    tail.on('line', async (line) => {
        line = line.trim();
        if (!line) return;

        // Skip CSV header if it appears (file truncated and re-written by NS-3)
        if (line.startsWith('rsu_id,')) {
            headerSkipped = true;
            return;
        }

        try {
            const [records] = parse(line, {
                columns: ['rsu_id','flow_mod_hash','recv_timestamp_ms',
                          'is_malicious','src_ip','dst_ip','src_port','dst_port'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(records);
        } catch (err) {
            console.warn(`[BRIDGE] FlowMod parse error: ${err.message} line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] FlowMod tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
