/**
 * Offline Analytics tab.
 *
 * Two panels: a metric-vs-attack-percentage sweep across attacks, and a
 * per-run detail view (KPI tiles, per-cycle trend, confusion matrix and its
 * independent recomputation).
 *
 * Colour follows the entity, not the rank: attack N always takes categorical
 * slot N, so deselecting one attack never repaints the others.
 */

import { api } from './api.js';
import { renderLineChart, renderTable, seriesColor } from './charts.js';
import { attackLabel, attackShortLabel, formatValue, prettyColumn } from './format.js';

const state = {
  catalog: null,
  attacks: [1],
  metric: 'avg_MCC',
  columnsByAttack: new Map(),
  sweepData: [],
  sweepUnit: 'count',
  sweepCaveat: null,
  sweepTableView: false,
  runId: null,
  runTableView: false,
};

/**
 * Colour for one attack, fixed to the entity.
 *
 * Attack N takes categorical slot N, so deselecting an attack never repaints
 * the others. The benign baseline is deliberately NOT given a slot: there are
 * nine possible entities (baseline + 8 attacks) against eight validated hues,
 * and inventing a ninth would be indistinguishable under CVD. The baseline is
 * context rather than a peer series, so it takes the de-emphasis grey -- the
 * emphasis pattern, which is also the honest encoding.
 */
function colorForAttack(attackId) {
  return attackId === 0 ? 'var(--text-muted)' : seriesColor(attackId - 1);
}

/** Metrics worth offering first; the rest stay available in the full list. */
const HEADLINE_METRICS = [
  'avg_MCC', 'avg_DR', 'avg_FPR', 'avg_PDR', 'avg_lat_ms', 'avg_mit_ms',
  'avg_TVR', 'avg_UCR', 'avg_trust_score', 'UFCR',
  'max_tcam_util', 'avg_tcam_util', 'global_chain_len', 'escalation_count',
];

export async function initOffline(root, catalog) {
  state.catalog = catalog;
  state.attacks = catalog.attacks.slice(0, 1);
  state.runId = catalog.runs.length ? catalog.runs[0].id : null;

  root.innerHTML = `
    <div class="layout">
      <aside>
        <div class="card">
          <header><h2>Sweep</h2></header>
          <div class="field">
            <label for="metric-select">Metric</label>
            <select id="metric-select"></select>
          </div>
          <div class="field">
            <label>Attacks</label>
            <div class="checks" id="attack-checks"></div>
          </div>
        </div>
        <div class="card">
          <header><h2>Run detail</h2></header>
          <div class="field">
            <label for="run-select">Run</label>
            <select id="run-select"></select>
          </div>
        </div>
      </aside>

      <section>
        <div class="card">
          <header>
            <div>
              <h2 id="sweep-title">Sweep</h2>
              <span class="sub" id="sweep-sub"></span>
            </div>
            <button class="table-toggle" id="sweep-toggle">Show table</button>
          </header>
          <div id="sweep-body"><p class="empty">Loading…</p></div>
          <div id="sweep-caveat"></div>
        </div>

        <div class="card">
          <header>
            <div>
              <h2 id="run-title">Run detail</h2>
              <span class="sub" id="run-sub"></span>
            </div>
            <button class="table-toggle" id="run-toggle">Show table</button>
          </header>
          <div class="tiles" id="run-tiles"></div>
          <div id="run-body" style="margin-top:16px"><p class="empty">Loading…</p></div>
          <div id="run-verify" style="margin-top:16px"></div>
        </div>
      </section>
    </div>
  `;

  buildAttackChecks(root);
  buildRunSelect(root);

  root.querySelector('#metric-select').addEventListener('change', (e) => {
    state.metric = e.target.value;
    loadSweep(root);
    loadRun(root);
  });
  root.querySelector('#sweep-toggle').addEventListener('click', () => {
    state.sweepTableView = !state.sweepTableView;
    drawSweep(root);
  });
  root.querySelector('#run-select').addEventListener('change', (e) => {
    state.runId = e.target.value;
    loadRun(root);
  });
  root.querySelector('#run-toggle').addEventListener('click', () => {
    state.runTableView = !state.runTableView;
    drawRun(root);
  });

  await refreshMetricOptions(root);
  await Promise.all([loadSweep(root), loadRun(root)]);
}

function buildAttackChecks(root) {
  const host = root.querySelector('#attack-checks');
  host.innerHTML = '';
  for (const attackId of state.catalog.attacks) {
    const label = document.createElement('label');
    label.className = 'check';
    label.innerHTML =
      `<input type="checkbox" value="${attackId}" ${state.attacks.includes(attackId) ? 'checked' : ''}>` +
      `<span class="swatch" style="background:${colorForAttack(attackId)}"></span>` +
      `<span>${attackShortLabel(attackId)}</span>`;
    label.querySelector('input').addEventListener('change', async (e) => {
      const id = Number(e.target.value);
      if (e.target.checked) {
        // Eight validated slots; past that a generated hue would be
        // indistinguishable under CVD, so refuse rather than degrade.
        if (id !== 0 && state.attacks.filter((a) => a !== 0).length >= 8) {
          e.target.checked = false;
          return;
        }
        state.attacks.push(id);
      } else {
        state.attacks = state.attacks.filter((a) => a !== id);
      }
      state.attacks.sort((a, b) => a - b);
      await refreshMetricOptions(root);
      loadSweep(root);
    });
    host.appendChild(label);
  }
}

function buildRunSelect(root) {
  const select = root.querySelector('#run-select');
  select.innerHTML = state.catalog.runs
    .map((r) => `<option value="${r.id}">${r.label}</option>`)
    .join('');
  if (state.runId) select.value = state.runId;
}

/**
 * Offer only metrics valid for every selected attack.
 *
 * Attacks 3, 4 and the baseline carry nine extra TCAM columns, so the union
 * would offer a column that 400s for the others. The intersection is the only
 * honest option list.
 */
async function refreshMetricOptions(root) {
  for (const attackId of state.attacks) {
    if (!state.columnsByAttack.has(attackId)) {
      const meta = await api.metrics(attackId);
      state.columnsByAttack.set(attackId, meta.columns);
    }
  }

  const lists = state.attacks.map((a) => state.columnsByAttack.get(a) || []);
  const first = lists[0] || [];
  const shared = first.filter((col) =>
    lists.every((list) => list.some((c) => c.name === col.name))
  );

  const ordered = [
    ...HEADLINE_METRICS.filter((m) => shared.some((c) => c.name === m)),
    ...shared.map((c) => c.name).filter((n) => !HEADLINE_METRICS.includes(n) && n !== 'cycle'),
  ];

  const select = root.querySelector('#metric-select');
  select.innerHTML = ordered
    .map((name) => {
      const col = shared.find((c) => c.name === name);
      const flag = col && col.caveat ? ' ◦ diagnostic' : '';
      return `<option value="${name}">${prettyColumn(name)}${flag}</option>`;
    })
    .join('');

  if (!ordered.includes(state.metric)) state.metric = ordered[0] || 'avg_PDR';
  select.value = state.metric;
}

async function loadSweep(root) {
  const body = root.querySelector('#sweep-body');
  if (!state.attacks.length) {
    body.innerHTML = '<p class="empty">Select at least one attack.</p>';
    root.querySelector('#sweep-caveat').innerHTML = '';
    return;
  }
  body.innerHTML = '<p class="empty">Loading…</p>';

  try {
    const results = await Promise.all(
      state.attacks.map((attack) => api.sweep({ attack, metric: state.metric }))
    );
    state.sweepData = results;
    state.sweepUnit = results[0].unit;
    state.sweepCaveat = results[0].caveat;
    drawSweep(root);
  } catch (error) {
    body.innerHTML = `<p class="empty">${error.message}</p>`;
  }
}

function sweepSeries() {
  return state.sweepData.map((result) => {
    return {
      key: `attack-${result.attack}`,
      name: attackLabel(result.attack),
      color: colorForAttack(result.attack),
      points: result.pct.map((pct, i) => ({
        x: pct,
        y: result.mean[i],
        lo: result.ci95[i] === null ? undefined : result.mean[i] - result.ci95[i],
        hi: result.ci95[i] === null ? undefined : result.mean[i] + result.ci95[i],
        n: result.n[i],
      })),
    };
  });
}

function drawSweep(root) {
  const body = root.querySelector('#sweep-body');
  const series = sweepSeries();
  const unit = state.sweepUnit;

  root.querySelector('#sweep-title').textContent = prettyColumn(state.metric);

  const singleSeed = state.sweepData.every((r) => r.single_seed);
  const seedNote = singleSeed
    ? 'n=1 per point — no confidence interval available. Copy seeds 2–5 from the HPC for error bars.'
    : 'Error bars are 95% CI across seeds (Student-t, matching plot_hf_results.py).';
  root.querySelector('#sweep-sub').textContent = `vs attacker percentage · ${seedNote}`;

  root.querySelector('#sweep-toggle').textContent = state.sweepTableView
    ? 'Show chart'
    : 'Show table';

  if (state.sweepTableView) {
    renderTable(body, { series, xHeader: 'Attackers (%)', unit });
  } else {
    renderLineChart(body, {
      series,
      unit,
      yLabel: `${prettyColumn(state.metric)}`,
      xLabel: 'Malicious node percentage',
      categoricalX: true,
      errorBars: !singleSeed,
    });
  }

  renderCaveat(root.querySelector('#sweep-caveat'), state.sweepCaveat);
}

function renderCaveat(host, text) {
  host.innerHTML = text
    ? `<div class="caveat"><span aria-hidden="true">⚠</span><div>
         <strong>Diagnostic metric, not the thesis metric.</strong> ${text}
       </div></div>`
    : '';
}

/**
 * Columns to plot as the run trend: the cur_/avg_ pair of the selected metric.
 *
 * The run picker is independent of the sweep's attack checkboxes, so the
 * selected metric may not exist in the selected run's schema (avg_tcam_util
 * while viewing an attack-1 run, say). Falling back here keeps the panel
 * populated instead of surfacing a 400 the reader cannot act on.
 */
function trendColumnsFor(runId) {
  const run = state.catalog.runs.find((r) => r.id === runId);
  const available = state.columnsByAttack.get(run ? run.attack : null);
  const base = state.metric.replace(/^(avg|cur)_/, '');
  const pair = [`cur_${base}`, `avg_${base}`];

  if (!available) return pair;
  const known = new Set(available.map((c) => c.name));
  return pair.every((name) => known.has(name)) ? pair : ['cur_MCC', 'avg_MCC'];
}

async function loadRun(root) {
  if (!state.runId) return;
  const body = root.querySelector('#run-body');
  body.innerHTML = '<p class="empty">Loading…</p>';
  try {
    const run = state.catalog.runs.find((r) => r.id === state.runId);
    if (run && !state.columnsByAttack.has(run.attack)) {
      const meta = await api.metrics(run.attack);
      state.columnsByAttack.set(run.attack, meta.columns);
    }
    const [summary, series] = await Promise.all([
      api.summary(state.runId),
      api.series(state.runId, trendColumnsFor(state.runId)),
    ]);
    state.runSummary = summary;
    state.runSeries = series;
    drawRun(root);
  } catch (error) {
    body.innerHTML = `<p class="empty">${error.message}</p>`;
  }
}

function drawRun(root) {
  const { runSummary: summary, runSeries: series } = state;
  if (!summary || !series) return;

  root.querySelector('#run-title').textContent = summary.run.label;
  root.querySelector('#run-sub').textContent =
    `${summary.cycles} routing cycles · file modified ${summary.run.modified.slice(0, 10)}`;
  root.querySelector('#run-toggle').textContent = state.runTableView
    ? 'Show chart'
    : 'Show table';

  // KPI tiles. The detection three are marked as diagnostics on the tile
  // itself, so a screenshot of this panel cannot be mistaken for M1.
  const tiles = [
    ['avg_MCC', 'fraction', true], ['avg_DR', 'percent', true], ['avg_FPR', 'percent', true],
    ['avg_PDR', 'percent', false], ['avg_lat_ms', 'ms', false], ['avg_mit_ms', 'ms', false],
    ['avg_trust_score', 'fraction', false], ['UFCR', 'percent', false],
  ];
  root.querySelector('#run-tiles').innerHTML = tiles
    .filter(([name]) => name in summary.final)
    .map(
      ([name, unit, diagnostic]) => `
      <div class="tile" data-diagnostic="${diagnostic}">
        <div class="label">${prettyColumn(name).replace(' (average)', '')}</div>
        <div class="value">${formatValue(summary.final[name], unit)}</div>
      </div>`
    )
    .join('');

  // Per-cycle trend: cur vs avg of one metric = one measure at two smoothings,
  // so two shades of a single hue rather than two categorical slots.
  const names = Object.keys(series.columns);
  const curName = names.find((n) => n.startsWith('cur_')) || names[0];
  const avgName = names.find((n) => n.startsWith('avg_')) || names[names.length - 1];
  const unit = series.units[avgName] || 'count';

  const trend = [
    {
      key: curName,
      name: 'Per cycle',
      color: 'var(--shade-light)',
      points: series.cycles.map((c, i) => ({ x: c, y: series.columns[curName][i] })),
    },
    {
      key: avgName,
      name: 'Cumulative average',
      color: 'var(--shade-dark)',
      points: series.cycles.map((c, i) => ({ x: c, y: series.columns[avgName][i] })),
    },
  ];

  const body = root.querySelector('#run-body');
  if (state.runTableView) {
    renderTable(body, { series: trend, xHeader: 'Cycle', unit });
  } else {
    renderLineChart(body, {
      series: trend,
      unit,
      yLabel: prettyColumn(avgName).replace(' (average)', ''),
      xLabel: 'Routing cycle (1 s each)',
      vlines: [{ x: series.attack_start_s, label: 'attack starts' }],
    });
  }

  drawVerification(root, summary);
}

/**
 * Confusion matrix plus the recomputation check.
 *
 * The point is not the matrix, it is that MCC/DR/FPR are re-derived here from
 * raw TP/FP/TN/FN and shown next to what the simulator reported. A reader can
 * see the detector was not simply believed.
 */
function drawVerification(root, summary) {
  const c = summary.confusion;
  const worst = summary.verification.max_delta;
  const agrees = worst < 1e-3;

  root.querySelector('#run-verify').innerHTML = `
    <h3>Confusion matrix (per-node, final cycle)</h3>
    <div class="table-scroll">
      <table class="data confusion">
        <thead><tr><th></th><th>Predicted malicious</th><th>Predicted benign</th></tr></thead>
        <tbody>
          <tr><td>Actually malicious</td>
              <td class="count tp">${c.TP}</td><td class="count fn">${c.FN}</td></tr>
          <tr><td>Actually benign</td>
              <td class="count fp">${c.FP}</td><td class="count tn">${c.TN}</td></tr>
        </tbody>
      </table>
    </div>

    <h3 style="margin-top:16px">Independent recomputation</h3>
    <div class="table-scroll">
      <table class="data">
        <thead><tr><th>Metric</th><th>Reported</th><th>Recomputed</th><th>Δ</th></tr></thead>
        <tbody>
          ${summary.verification.discrepancies
            .map(
              (d) => `<tr>
                <td>${d.metric}</td>
                <td>${d.reported.toFixed(6)}</td>
                <td>${d.recomputed.toFixed(6)}</td>
                <td>${d.delta.toExponential(2)}</td>
              </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
    <div class="banner" data-status="${agrees ? 'good' : 'critical'}" style="margin-top:12px">
      <span class="glyph" aria-hidden="true">${agrees ? '✓' : '✗'}</span>
      <div>
        <strong>${
          agrees
            ? 'Reported metrics match their recomputation'
            : 'Reported metrics disagree with their recomputation'
        }</strong>
        <span class="detail">Largest gap ${worst.toExponential(2)} across all cycles.
        ${summary.verification.note}</span>
      </div>
    </div>
  `;
}
