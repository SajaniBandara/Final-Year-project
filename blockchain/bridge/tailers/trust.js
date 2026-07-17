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

const CSV_PATH = '/home/sdvn_hidden_attacks/ns3_g13_apsari/ns-allinone-3.35/ns-3.35/results_routing/bc_trust_updates.csv';

// Map node_id → fabric identity name (set by index.js).
let identityMap = {};
function setIdentityMap(map) { identityMap = map; }
function identityFor(nodeId) { return identityMap[nodeId] || 'admin'; }

// Track lifecycle state per RSU to avoid redundant removal warnings.
const lifecycleState = {}; // nodeId → 'active' | 'demoted' | 'removed'

function utcNow() { return new Date().toISOString().replace('T',' ').slice(0,23) + ' UTC'; }

async function handleRow(row) {
    const rsuId       = row.rsu_id;
    const success     = parseInt(row.success) === 1;
    const timestampMs = row.timestamp_ms;
    const reason      = row.reason;     // 'S3' or 'S4'
    const ruleCount   = row.rule_count;
    const rate        = row.rate_per_s;
    const identity    = identityFor(parseInt(rsuId));
    const wallTime    = utcNow();

    if (lifecycleState[rsuId] === 'removed') {
        console.log(`[${wallTime}] [TRUST]   SKIPPED    rsu=${rsuId}  reason=already_removed`);
        return;
    }

    // ── Step 1: UpdateTrust (apply penalty) ─────────────────────────────────────
    let updateOk = false;
    try {
        await fc.submit(identity, 'UpdateTrust', rsuId, String(success), timestampMs);
        updateOk = true;
    } catch (err) {
        const msg = err.message || '';
        if (msg.includes('removed from the system')) {
            lifecycleState[rsuId] = 'removed';
            console.log(`[${wallTime}] [TRUST]   REMOVED    rsu=${rsuId}  reason=${reason}  ⛔ NODE PERMANENTLY REMOVED (writes blocked)`);
        } else {
            console.warn(`[${wallTime}] [TRUST]   ERROR      rsu=${rsuId}  → ${msg}`);
        }
        return;
    }

    // ── Step 2: QueryTrust ──────────────────────────────────────────────────────
    let score = '?';
    try {
        const raw   = await fc.evaluate(identity, 'QueryTrust', rsuId);
        const trust = JSON.parse(raw);
        score = trust.score;
    } catch (err) {
        console.warn(`[${wallTime}] [TRUST]   QUERY_ERR  rsu=${rsuId}  → ${err.message}`);
    }

    console.log(`[${wallTime}] [TRUST]   PENALTY    rsu=${rsuId}  reason=${reason}  rules=${ruleCount}  rate=${rate}/s  new_score=${score}  ledger=COMMITTED`);

    // ── Step 3: IsActivePeer ─────────────────────────────────────────────────────
    try {
        const raw    = await fc.evaluate(identity, 'IsActivePeer', rsuId);
        const active = raw.trim() === 'true';

        if (!active && lifecycleState[rsuId] !== 'demoted' && lifecycleState[rsuId] !== 'removed') {
            lifecycleState[rsuId] = 'demoted';

            console.log('');
            console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
            console.log(`  ║  🟠  RSU DEMOTED  —  TRUST THRESHOLD BREACH DETECTED              ║`);
            console.log(`  ║     time      : ${wallTime}                ║`);
            console.log(`  ║     rsu       : ${String(rsuId).padEnd(56)} ║`);
            console.log(`  ║     score     : ${String(score).padEnd(5)}  (T_demote = 3000)                       ║`);
            console.log(`  ║     action    : RSU excluded from endorsement peers            ║`);
            console.log(`  ║     on-chain  : IsActivePeer=false  (Eq.3.47)                 ║`);
            console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
            console.log('');

            try {
                const qRaw    = await fc.evaluate(identity, 'GetQuarantineRecord', rsuId);
                const qRecord = JSON.parse(qRaw);
                console.log(`[${wallTime}] [QUARANTINE] rsu=${rsuId}  status=${qRecord.status}  demotedAt=${qRecord.demotedAt}`);
            } catch (_) {}

        } else if (active && lifecycleState[rsuId] === 'demoted') {
            lifecycleState[rsuId] = 'active';
            console.log(`[${wallTime}] [TRUST]   REINSTATED rsu=${rsuId}  score=${score}  IsActivePeer=true  ✅`);
        }

        if (typeof score === 'number' && score < 1000 && lifecycleState[rsuId] === 'demoted') {
            lifecycleState[rsuId] = 'removed';
            console.log('');
            console.log(`  ╔══════════════════════════════════════════════════════════════╗`);
            console.log(`  ║  ⛔  RSU PERMANENTLY REMOVED FROM NETWORK                       ║`);
            console.log(`  ║     time      : ${wallTime}                ║`);
            console.log(`  ║     rsu       : ${String(rsuId).padEnd(56)} ║`);
            console.log(`  ║     score     : ${String(score).padEnd(5)}  (T_remove = 1000)                       ║`);
            console.log(`  ║     action    : All future writes from this RSU blocked         ║`);
            console.log(`  ║     on-chain  : Quarantine status=removed  (Eq.3.48)            ║`);
            console.log(`  ╚══════════════════════════════════════════════════════════════╝`);
            console.log('');
        }

    } catch (err) {
        console.warn(`[${wallTime}] [TRUST]   PEER_ERR   rsu=${rsuId}  → ${err.message}`);
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
