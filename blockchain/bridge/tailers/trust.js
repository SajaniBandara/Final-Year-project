'use strict';
// tailers/trust.js
// MobiGuard Bridge — Trust update tailer
//
// Tails results_routing/bc_trust_updates.csv in real time (written by NS-3
// bc_blockchain_helper.h's bc_check_s4() and the S3 window check inside
// bc_log_flowmod() on every anomaly detection).
//
// For each new CSV row this module:
//   1. Calls UpdateTrust(rsuId, false, timestampMs) → applies −500 bp penalty.
//   2. After commit, evaluates QueryTrust(rsuId) to read the new score.
//   3. Evaluates IsActivePeer(rsuId) and logs DEMOTED / REMOVED state.
//
// Chaincode functions used (trust.go):
//   UpdateTrust(nodeId, success, timestamp)
//   QueryTrust(nodeId)     → {score, lastUpdate}
//   IsActivePeer(nodeId)   → bool
//   GetQuarantineRecord(nodeId) → {status, demotedAt, removedAt}

const path   = require('path');
const { Tail } = require('tail');
const { parse } = require('csv-parse/sync');
const fc     = require('../fabric-client');

const CSV_PATH = '/home/nipuni/ns-allinone-3.35/ns-3.35/results_routing/bc_trust_updates.csv';

// Map node_id → fabric identity name (set by index.js).
let identityMap = {};
function setIdentityMap(map) { identityMap = map; }
function identityFor(nodeId) { return identityMap[nodeId] || 'admin'; }

// Track lifecycle state per RSU to avoid redundant removal warnings.
const lifecycleState = {}; // nodeId → 'active' | 'demoted' | 'removed'

async function handleRow(row) {
    const rsuId       = row.rsu_id;
    const success     = parseInt(row.success) === 1; // always 0 for S3/S4
    const timestampMs = row.timestamp_ms;
    const reason      = row.reason;     // 'S3' or 'S4'
    const ruleCount   = row.rule_count;
    const rate        = row.rate_per_s;
    const identity    = identityFor(parseInt(rsuId));

    // If node is already removed, chaincode will reject writes.
    // Don't flood bridge logs with repeated 500 errors.
    if (lifecycleState[rsuId] === 'removed') {
        console.log(`[BRIDGE→BC] UpdateTrust rsu=${rsuId} reason=${reason} → SKIPPED (already removed)`);
        return;
    }

    // ── Step 1: UpdateTrust (apply penalty) ──────────────────────────────────
    let updateOk = false;
    try {
        await fc.submit(identity, 'UpdateTrust', rsuId, String(success), timestampMs);
        updateOk = true;
    } catch (err) {
        const msg = err.message || '';
        if (msg.includes('removed from the system')) {
            // Chaincode returned status:500 — node was just permanently removed.
            lifecycleState[rsuId] = 'removed';
            console.log(`[BRIDGE→BC] UpdateTrust rsu=${rsuId} reason=${reason} → status:500 ⛔ NODE REMOVED (writes permanently blocked)`);
        } else {
            console.warn(`[BRIDGE→BC] UpdateTrust rsu=${rsuId} → ERROR: ${msg}`);
        }
        return;
    }

    // ── Step 2: QueryTrust — read new score ─────────────────────────────────
    let score = '?';
    try {
        const raw   = await fc.evaluate(identity, 'QueryTrust', rsuId);
        const trust = JSON.parse(raw);
        score = trust.score;
    } catch (err) {
        console.warn(`[BRIDGE→BC] QueryTrust rsu=${rsuId} → ${err.message}`);
    }

    console.log(`[BRIDGE→BC] UpdateTrust rsu=${rsuId} reason=${reason} rules=${ruleCount} rate=${rate}/s → status:200 score=${score}`);

    // ── Step 3: IsActivePeer — check for lifecycle transition ────────────────
    try {
        const raw    = await fc.evaluate(identity, 'IsActivePeer', rsuId);
        const active = raw.trim() === 'true';

        if (!active && lifecycleState[rsuId] !== 'demoted' && lifecycleState[rsuId] !== 'removed') {
            lifecycleState[rsuId] = 'demoted';
            console.log(`[BRIDGE→BC] IsActivePeer rsu=${rsuId} → false  🔶 DEMOTED (score=${score} < T_demote=3000)`);
            console.log(`[BRIDGE→BC]   Bridge will exclude rsu=${rsuId} from --peerAddresses on future endorsements`);

            // Also log quarantine record for audit
            try {
                const qRaw    = await fc.evaluate(identity, 'GetQuarantineRecord', rsuId);
                const qRecord = JSON.parse(qRaw);
                console.log(`[BRIDGE→BC]   QuarantineRecord: status=${qRecord.status} demotedAt=${qRecord.demotedAt}`);
            } catch (_) {}

        } else if (active && lifecycleState[rsuId] === 'demoted') {
            // Score recovered above T_demote (manual LiftQuarantine was called)
            lifecycleState[rsuId] = 'active';
            console.log(`[BRIDGE→BC] IsActivePeer rsu=${rsuId} → true  ✅ REINSTATED`);
        }

        // Check removal threshold explicitly (score < 1000 while demoted)
        if (typeof score === 'number' && score < 1000 && lifecycleState[rsuId] === 'demoted') {
            lifecycleState[rsuId] = 'removed';
            console.log(`[BRIDGE→BC] IsActivePeer rsu=${rsuId} → false  ⛔ REMOVED (score=${score} < T_remove=1000)`);
            console.log(`[BRIDGE→BC]   Node rsu=${rsuId} permanently ejected — all future writes will be blocked`);
        }

    } catch (err) {
        console.warn(`[BRIDGE→BC] IsActivePeer rsu=${rsuId} → ${err.message}`);
    }
}

function start() {
    console.log(`[BRIDGE] Trust tailer watching: ${CSV_PATH}`);

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
                columns: ['rsu_id','success','timestamp_ms','reason','rule_count','rate_per_s'],
                skip_empty_lines: true,
                from_line: 1,
            });
            await handleRow(record);
        } catch (err) {
            console.warn(`[BRIDGE] Trust parse error: ${err.message} line="${line}"`);
        }
    });

    tail.on('error', (err) => {
        console.error(`[BRIDGE] Trust tailer error: ${err.message}`);
    });

    return tail;
}

module.exports = { start, setIdentityMap };
