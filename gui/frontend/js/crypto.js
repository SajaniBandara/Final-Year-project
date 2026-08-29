/**
 * Crypto & Integrity Overhead tab (M7).
 *
 * Per-operation wall-clock cost of the post-quantum layer: ML-DSA-87 sign and
 * verify, batch verification, STARK hop proofs, and the modelled consensus step.
 *
 * Two presentation problems this module solves rather than papers over:
 *
 * 1. **Four orders of magnitude.** Operation costs run from 1.15 us
 *    (verify_skip_broadcast) to 6627 us (consensus). On one linear axis every
 *    bar but consensus is invisible, and a log axis makes bar length meaningless
 *    because the baseline is no longer zero. The answer is small multiples: two
 *    faceted charts with their own linear scales, split at 100 us. Never a
 *    second axis.
 *
 * 2. **An overloaded result column.** Aggregated naively it reads "85% of crypto
 *    operations failed". The backend annotates each operation with what its
 *    boolean actually means, and this module shows a rate only where one exists.
 */

import { api } from './api.js';
import { renderBarChart } from './charts.js';
import { formatValue } from './format.js';

const state = { runs: [], selected: null };

/** Split point for the small multiples, in microseconds. */
const FACET_SPLIT_US = 100;

const us = (v) => (v >= 1000 ? `${(v / 1000).toFixed(2)} ms` : `${v.toFixed(2)} µs`);

export async function initCrypto(root) {
  root.innerHTML = '<div class="card"><p class="empty">Loading crypto timings…</p></div>';

  let panel;
  try {
    panel = await api.cryptoPanel();
  } catch (error) {
    root.innerHTML = `<div class="card"><p class="empty">${error.message}</p></div>`;
    return;
  }

  if (!panel.available) {
    root.innerHTML = `<div class="card"><p class="empty">
      No <code>crypto_timing_log_*.csv</code> found. These are only written when a run
      reaches per-packet crypto calls.</p></div>`;
    return;
  }

  state.runs = panel.runs;
  state.selected = panel.selected.id;
  render(root, panel);
}

function render(root, panel) {
  root.innerHTML = `
    <div class="layout">
      <aside>
        <div class="card">
          <header><h2>Run</h2></header>
          <div class="field">
            <label for="crypto-run">Crypto timing log</label>
            <select id="crypto-run">
              ${state.runs
                .map(
                  (r) =>
                    `<option value="${r.id}"${r.id === state.selected ? ' selected' : ''}>${r.label}</option>`
                )
                .join('')}
            </select>
          </div>
          <p class="sub">One row per cryptographic or detector event, with its
          wall-clock cost in microseconds.</p>
        </div>
      </aside>
      <section>
        <div class="card" id="crypto-headline"></div>
        <div class="card" id="crypto-charts"></div>
        <div class="card" id="crypto-table"></div>
      </section>
    </div>`;

  root.querySelector('#crypto-run').addEventListener('change', async (event) => {
    state.selected = event.target.value;
    const host = root.querySelector('#crypto-headline');
    host.innerHTML = '<p class="empty">Loading…</p>';
    try {
      render(root, await api.cryptoPanel(state.selected));
    } catch (error) {
      host.innerHTML = `<p class="empty">${error.message}</p>`;
    }
  });

  renderHeadline(root.querySelector('#crypto-headline'), panel);
  renderCharts(root.querySelector('#crypto-charts'), panel.analysis);
  renderTable(root.querySelector('#crypto-table'), panel.analysis);
}

function renderHeadline(host, panel) {
  const a = panel.analysis;
  const sv = a.signature_verification;

  const tiles = a.headline
    .map(
      (op) => `
      <div class="tile">
        <div class="label">${op.label}</div>
        <div class="value">${us(op.mean_us)}</div>
        <div class="sub">${op.count.toLocaleString()} calls · p95 ${us(op.p95_us)}</div>
      </div>`
    )
    .join('');

  host.innerHTML = `
    <header><div><h2>Post-quantum crypto overhead (M7)</h2>
      <span class="sub">${panel.selected.label} · ${a.total_events.toLocaleString()} events</span></div></header>
    <div class="tiles">${tiles}</div>
    ${
      sv
        ? `<div class="tiles" style="margin-top:12px">
             <div class="tile">
               <div class="label">Signature verification</div>
               <div class="value">${((1 - sv.fail_rate) * 100).toFixed(2)}<span class="unit">% passed</span></div>
               <div class="sub">${sv.passed.toLocaleString()} of ${sv.attempts.toLocaleString()} genuine attempts</div>
             </div>
           </div>`
        : ''
    }
    <div class="caveat" style="margin-top:14px"><span aria-hidden="true">⚠</span><div>
      <strong>There is no single crypto pass/fail rate.</strong> ${a.note}
      The figure above counts only <code>verify</code>, the one operation whose
      result flag records a genuine cryptographic outcome.
    </div></div>`;
}

function renderCharts(host, analysis) {
  const slow = analysis.operations.filter((o) => o.mean_us >= FACET_SPLIT_US);
  const fast = analysis.operations.filter((o) => o.mean_us < FACET_SPLIT_US);

  host.innerHTML = `
    <header><div><h2>Mean cost per operation</h2>
      <span class="sub">Split into two panels — costs span four orders of magnitude,
      so one axis would hide everything but consensus</span></div></header>
    <h3>Above ${FACET_SPLIT_US} µs</h3>
    <div id="chart-slow"></div>
    <h3 style="margin-top:18px">Below ${FACET_SPLIT_US} µs</h3>
    <div id="chart-fast"></div>`;

  for (const [selector, ops] of [['#chart-slow', slow], ['#chart-fast', fast]]) {
    renderBarChart(host.querySelector(selector), {
      bars: ops.map((o) => ({ label: o.op, value: o.mean_us })),
      unit: 'count',
      yLabel: 'Mean wall-clock (µs)',
    });
  }
}

function renderTable(host, analysis) {
  const caveat = analysis.stark_hop_caveat;

  const rows = analysis.operations
    .map((o) => {
      const rate =
        o.ok_rate === null
          ? `<span class="undefined" title="${o.note || 'no pass/fail meaning'}">n/a</span>`
          : `${(o.ok_rate * 100).toFixed(1)}%`;
      return `<tr>
        <td><code>${o.op}</code><div class="sub">${o.label}</div></td>
        <td>${o.count.toLocaleString()}</td>
        <td>${o.mean_us.toFixed(2)}</td>
        <td>${o.median_us.toFixed(2)}</td>
        <td>${o.p95_us.toFixed(2)}</td>
        <td>${o.max_us.toFixed(2)}</td>
        <td>${rate}</td>
        <td style="text-align:left">${o.rate_meaning ? `“ok” = ${o.rate_meaning}` : '—'}
          ${o.note ? `<div class="sub">${o.note}</div>` : ''}</td>
      </tr>`;
    })
    .join('');

  host.innerHTML = `
    <header><div><h2>All operations</h2>
      <span class="sub">Wall-clock in microseconds</span></div></header>
    ${
      caveat && caveat.counts_line_up
        ? `<div class="caveat"><span aria-hidden="true">⚠</span><div>
             <strong>STARK hop proof: the raw
             ${(caveat.raw_fail_rate * 100).toFixed(1)}% “fail” rate is not a proof-failure rate.</strong>
             ${caveat.explanation}
             <div class="sub" style="margin-top:6px">
               stark_hop ok = ${caveat.stark_ok.toLocaleString()} = genuine verifications;
               stark_hop fail = ${caveat.stark_fail.toLocaleString()} = broadcast overhears
               (${caveat.broadcast_overhears.toLocaleString()}). Exact match.
             </div>
           </div></div>`
        : ''
    }
    <div class="table-scroll" style="margin-top:12px">
      <table class="data">
        <thead><tr><th>Operation</th><th>Calls</th><th>Mean</th><th>Median</th>
          <th>p95</th><th>Max</th><th>“ok” rate</th><th>What “ok” means</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}
