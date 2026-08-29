/**
 * TCAM Occupancy tab — the 8×8 RSU grid over time.
 *
 * The grid is the most direct picture of a TCAM-exhaustion attack: rules
 * accumulate per RSU until occupancy crosses S4's gate and the signature fires.
 *
 * Three correctness points inherited from the backend, all easy to get wrong:
 *
 *   - Cells are RSUs only. The CSV's `rsu_id` column is a *simulation node
 *     index* over all 268 nodes, so the backend slices ids 200–263.
 *   - Utilisation is `counted_rule_count / 1500`, the capacity-occupying count
 *     the S3/S4 detector reads — not `total_rule_count`, which includes passive
 *     ip-hook observations.
 *   - Layout is row-major, 8 wide (`GridWidth=8`, `RowFirst`), so RSU r sits at
 *     column r%8, row r/8. Column-major would look fine and be wrong.
 *
 * Cells above the S4 gate carry a ring and a marker, not just a darker colour —
 * a threshold crossing must not rest on hue alone.
 */

import { api } from './api.js';
import { renderLineChart, sequentialColor } from './charts.js';

const state = { runs: [], selected: null, analysis: null, frame: 0, timer: null };

const pct = (v) => `${(v * 100).toFixed(2)}%`;

export async function initTcam(root) {
  root.innerHTML = '<div class="card"><p class="empty">Loading TCAM occupancy…</p></div>';

  let panel;
  try {
    panel = await api.tcamPanel();
  } catch (error) {
    root.innerHTML = `<div class="card"><p class="empty">${error.message}</p></div>`;
    return;
  }
  if (!panel.available) {
    root.innerHTML =
      '<div class="card"><p class="empty">No <code>tcam_occupancy_*.csv</code> found.</p></div>';
    return;
  }

  state.runs = panel.runs;
  render(root, panel);
}

function render(root, panel) {
  stopPlayback();
  state.selected = panel.selected.id;
  state.analysis = panel.analysis;
  state.frame = panel.analysis.frames.length - 1; // open on the fullest grid

  root.innerHTML = `
    <div class="layout">
      <aside>
        <div class="card">
          <header><h2>Run</h2></header>
          <div class="field">
            <label for="tcam-run">Occupancy log</label>
            <select id="tcam-run">
              ${state.runs
                .map((r) => `<option value="${r.id}"${r.id === state.selected ? ' selected' : ''}>${r.label}</option>`)
                .join('')}
            </select>
          </div>
          <div class="field">
            <label for="tcam-time">Simulated second
              <span id="tcam-time-label"></span></label>
            <input type="range" id="tcam-time" min="0"
                   max="${panel.analysis.frames.length - 1}" value="${state.frame}">
          </div>
          <button class="icon-button" id="tcam-play" style="width:100%">▶ Play</button>
          <p class="sub" style="margin-top:10px">
            Capacity ${panel.analysis.capacity} rules per RSU.
            S4 fires above ${pct(panel.analysis.s4_threshold)} occupancy.
          </p>
        </div>
      </aside>
      <section>
        <div class="card" id="tcam-tiles"></div>
        <div class="card" id="tcam-grid-card">
          <header><div><h2>RSU grid — TCAM occupancy</h2>
            <span class="sub">8×8, row-major, as laid out by the simulation</span></div>
            <span id="tcam-frame-label" class="sub"></span></header>
          <div id="tcam-grid"></div>
          <div id="tcam-legend"></div>
        </div>
        <div class="card">
          <header><div><h2>Occupancy over time</h2>
            <span class="sub">Mean and peak across the 64 RSUs</span></div></header>
          <div id="tcam-chart"></div>
        </div>
      </section>
    </div>`;

  root.querySelector('#tcam-run').addEventListener('change', async (event) => {
    try {
      render(root, await api.tcamPanel(event.target.value));
    } catch (error) {
      root.querySelector('#tcam-grid').innerHTML = `<p class="empty">${error.message}</p>`;
    }
  });

  const slider = root.querySelector('#tcam-time');
  slider.addEventListener('input', () => {
    stopPlayback(root);
    state.frame = Number(slider.value);
    drawFrame(root);
  });

  root.querySelector('#tcam-play').addEventListener('click', () => {
    if (state.timer) stopPlayback(root);
    else startPlayback(root);
  });

  drawTiles(root);
  drawChart(root);
  drawFrame(root);
}

function startPlayback(root) {
  const frames = state.analysis.frames.length;
  root.querySelector('#tcam-play').textContent = '❚❚ Pause';
  state.timer = setInterval(() => {
    state.frame = (state.frame + 1) % frames;
    root.querySelector('#tcam-time').value = String(state.frame);
    drawFrame(root);
  }, 400);
}

function stopPlayback(root) {
  if (state.timer) {
    clearInterval(state.timer);
    state.timer = null;
    if (root) root.querySelector('#tcam-play').textContent = '▶ Play';
  }
}

/** Stop the timer when the tab is left, so it does not run in a hidden panel. */
export function stopTcam() {
  stopPlayback();
}

function drawTiles(root) {
  const a = state.analysis;
  const last = a.series[a.series.length - 1];
  const firstOver = a.series.find((s) => s.over_threshold > 0);

  root.querySelector('#tcam-tiles').innerHTML = `
    <header><div><h2>TCAM exhaustion (S3 / S4)</h2>
      <span class="sub">${a.note}</span></div></header>
    <div class="tiles">
      <div class="tile"><div class="label">Peak occupancy</div>
        <div class="value">${pct(a.peak.max_util)}</div>
        <div class="sub">at t=${a.peak.t}s, of ${a.capacity} rules</div></div>
      <div class="tile"><div class="label">Final mean</div>
        <div class="value">${pct(last.mean_util)}</div>
        <div class="sub">across ${a.n_rsus} RSUs</div></div>
      <div class="tile"><div class="label">RSUs over S4 gate</div>
        <div class="value" style="color:${last.over_threshold ? 'var(--status-critical)' : 'inherit'}">
          ${last.over_threshold}<span class="unit"> / ${a.n_rsus}</span></div>
        <div class="sub">${firstOver ? `first at t=${firstOver.t}s` : 'never crossed'}</div></div>
      <div class="tile"><div class="label">Install rejections</div>
        <div class="value">${last.cum_rejections}</div>
        <div class="sub">cumulative TABLE_FULL</div></div>
    </div>`;
}

function drawChart(root) {
  const a = state.analysis;
  renderLineChart(root.querySelector('#tcam-chart'), {
    series: [
      {
        key: 'max',
        name: 'Peak RSU',
        color: 'var(--shade-dark)',
        points: a.series.map((s) => ({ x: s.t, y: s.max_util })),
      },
      {
        key: 'mean',
        name: 'Mean across RSUs',
        color: 'var(--shade-light)',
        points: a.series.map((s) => ({ x: s.t, y: s.mean_util })),
      },
    ],
    unit: 'fraction',
    yLabel: 'TCAM occupancy (fraction of capacity)',
    xLabel: 'Simulated second',
    hlines: [{ y: a.s4_threshold, label: `S4 gate ${pct(a.s4_threshold)}` }],
  });
}

function drawFrame(root) {
  const a = state.analysis;
  const frame = a.frames[state.frame];
  const width = a.grid_width;

  root.querySelector('#tcam-time-label').textContent = `t = ${frame.t}s`;
  root.querySelector('#tcam-frame-label').textContent =
    `t = ${frame.t}s · ${frame.counts.filter((c) => c > 0).length} of ${a.n_rsus} RSUs holding rules`;

  // Scale colour against the run's own peak so the ramp uses its full range;
  // the S4 gate is marked separately rather than being encoded as colour.
  const peakCount = Math.max(1, ...a.frames.map((f) => Math.max(...f.counts)));

  const cells = frame.counts
    .map((count, r) => {
      const util = count / a.capacity;
      const over = util > a.s4_threshold;
      const bg = count === 0 ? 'var(--surface-page)' : sequentialColor(count / peakCount);
      const ink = count / peakCount > 0.55 ? '#ffffff' : 'var(--text-primary)';
      return `<div class="rsu-cell${over ? ' rsu-over' : ''}"
                   style="background:${bg};color:${ink}"
                   title="RSU ${r} (node ${a.rsu_node_range[0] + r}) — ${count} rules, ${pct(util)}${
                     over ? ' — above S4 gate' : ''
                   }">
                <span class="rsu-id">${r}</span>
                <span class="rsu-count">${count}</span>
                ${over ? '<span class="rsu-flag" aria-label="above S4 gate">▲</span>' : ''}
              </div>`;
    })
    .join('');

  root.querySelector('#tcam-grid').innerHTML =
    `<div class="rsu-grid" style="grid-template-columns:repeat(${width}, minmax(0, 1fr))">${cells}</div>`;

  root.querySelector('#tcam-legend').innerHTML = `
    <div class="legend">
      <span class="item"><span class="swatch" style="background:${sequentialColor(0.1)};height:12px"></span>fewer rules</span>
      <span class="item"><span class="swatch" style="background:${sequentialColor(1)};height:12px"></span>more rules</span>
      <span class="item"><span class="rsu-flag">▲</span> above the S4 occupancy gate</span>
    </div>`;
}
