/**
 * Live PEM Monitor -- the realtime half of the supervisor's brief.
 *
 * Streams one run's cycles over a WebSocket and updates KPI tiles, a rolling
 * chart, a detection-event feed and a crypto/blockchain strip as they arrive.
 *
 * Replay and live share one message contract, so this module does not branch on
 * which is feeding it. It does, however, always *say* which one is: the source
 * badge is deliberate. "Is this actually running, or a recording?" is a
 * question a viva will ask, and the answer should already be on screen.
 */

import { api } from './api.js';
import { renderLineChart } from './charts.js';
import { formatValue, prettyColumn } from './format.js';

const state = {
  catalog: null,
  socket: null,
  meta: null,
  cycles: [],
  rows: [],
  events: [],
  chartMetric: 'cur_MCC',
  connected: false,
};

/** Counters whose per-cycle increase is a detection event worth announcing. */
const EVENT_LABELS = {
  d_obu_count: 'OBU detection',
  d_rsu_count: 'RSU detection',
  escalation_count: 'Escalation to RSU',
};

/** Metrics offered for the rolling chart. All are per-cycle. */
const CHART_METRICS = [
  'cur_MCC', 'cur_DR', 'cur_FPR', 'cur_PDR', 'cur_lat_ms', 'cur_mit_ms', 'cur_TVR',
];

export function initLive(root, catalog) {
  state.catalog = catalog;

  root.innerHTML = `
    <div class="layout">
      <aside>
        <div class="card">
          <header><h2>Stream</h2></header>
          <div class="field">
            <label for="live-run">Run</label>
            <select id="live-run">
              ${catalog.runs.map((r) => `<option value="${r.id}">${r.label}</option>`).join('')}
            </select>
          </div>
          <div class="field">
            <label for="live-mode">Source</label>
            <select id="live-mode">
              <option value="replay">Replay a recorded run</option>
              <option value="live">Live — tail a running simulation</option>
            </select>
          </div>
          <div class="field" id="speed-field">
            <label for="live-speed">Replay speed</label>
            <select id="live-speed">
              <option value="1">1× (real time, 1 cycle/s)</option>
              <option value="2">2×</option>
              <option value="5" selected>5×</option>
              <option value="10">10×</option>
            </select>
          </div>
          <div class="field">
            <label for="live-metric">Chart metric</label>
            <select id="live-metric">
              ${CHART_METRICS.map(
                (m) => `<option value="${m}"${m === state.chartMetric ? ' selected' : ''}>${prettyColumn(m)}</option>`
              ).join('')}
            </select>
          </div>
          <button class="icon-button" id="live-toggle" style="width:100%">Watch</button>
          <p class="sub" id="live-hint" style="margin-top:10px">
            Live mode follows the CSV as ns-3 appends to it — one row per simulated second.
          </p>
          <p class="sub" style="margin-top:6px">
            This only detaches the viewer — it does not stop the simulation itself.
            To actually terminate a running simulation, use <strong>Stop</strong> on the
            Run Simulation tab, next to that run's progress bar.
          </p>
        </div>
      </aside>

      <section>
        <div id="live-status"></div>

        <div class="card">
          <header>
            <div><h2>Performance evaluation metrics</h2>
              <span class="sub" id="live-sub">Not started.</span></div>
            <span class="source-badge" id="live-badge" hidden></span>
          </header>
          <div class="tiles" id="live-tiles"></div>
          <div id="live-caveat"></div>
        </div>

        <div class="card">
          <header><div><h2 id="live-chart-title">Trend</h2>
            <span class="sub">Per routing cycle, as received</span></div></header>
          <div id="live-chart"><p class="empty">Start a stream to see metrics arrive.</p></div>
        </div>

        <div class="card">
          <header><div><h2>Integrity &amp; consensus</h2>
            <span class="sub">Crypto and blockchain counters, live</span></div></header>
          <div class="tiles" id="live-crypto"></div>
        </div>

        <div class="card">
          <header><div><h2>Detection events</h2>
            <span class="sub">Derived from per-cycle counter increases</span></div></header>
          <div id="live-events"><p class="empty">No events yet.</p></div>
        </div>
      </section>
    </div>
  `;

  const modeSelect = root.querySelector('#live-mode');
  modeSelect.addEventListener('change', () => {
    root.querySelector('#speed-field').hidden = modeSelect.value !== 'replay';
    root.querySelector('#live-hint').textContent =
      modeSelect.value === 'live'
        ? 'Live mode follows the CSV as ns-3 appends to it — one row per simulated second.'
        : 'Replay emits the real rows of a recorded run at wall-clock speed.';
  });

  root.querySelector('#live-metric').addEventListener('change', (e) => {
    state.chartMetric = e.target.value;
    drawChart(root);
  });

  root.querySelector('#live-toggle').addEventListener('click', () => {
    if (state.connected) disconnect(root);
    else connect(root);
  });
}

function connect(root) {
  const runId = root.querySelector('#live-run').value;
  const mode = root.querySelector('#live-mode').value;
  const speed = root.querySelector('#live-speed').value;

  state.cycles = [];
  state.rows = [];
  state.events = [];
  state.meta = null;

  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const url =
    `${scheme}://${location.host}/ws/stream` +
    `?run_id=${encodeURIComponent(runId)}&mode=${mode}&speed=${speed}`;

  const socket = new WebSocket(url);
  state.socket = socket;
  setStatus(root, 'good', 'Connecting…', 'Opening the stream.');

  socket.addEventListener('open', () => {
    state.connected = true;
    root.querySelector('#live-toggle').textContent = 'Stop watching';
  });

  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (message.type === 'meta') onMeta(root, message);
    else if (message.type === 'cycle') onCycle(root, message);
    else if (message.type === 'end') onEnd(root);
    else if (message.type === 'error') onError(root, message.detail);
  });

  socket.addEventListener('close', () => {
    state.connected = false;
    root.querySelector('#live-toggle').textContent = 'Watch';
  });

  socket.addEventListener('error', () => {
    onError(root, 'WebSocket error — is the backend still running?');
  });
}

function disconnect(root) {
  if (state.socket) state.socket.close();
  state.connected = false;
  root.querySelector('#live-toggle').textContent = 'Watch';
  setStatus(root, 'good', 'Stopped', `${state.cycles.length} cycles received.`);
}

function onMeta(root, meta) {
  state.meta = meta;
  const badge = root.querySelector('#live-badge');
  badge.hidden = false;
  badge.dataset.mode = meta.mode;
  // Never let the reader guess which source is feeding the chart.
  badge.textContent = meta.mode === 'live' ? '● LIVE — tailing ns-3' : '▶ REPLAY — recorded run';
  root.querySelector('#live-sub').textContent = meta.run.label;

  const caveat = meta.caveats && meta.caveats.cur_MCC;
  root.querySelector('#live-caveat').innerHTML = caveat
    ? `<div class="caveat"><span aria-hidden="true">⚠</span><div>
         <strong>MCC / DR / FPR here are per-node diagnostics.</strong> ${caveat}
       </div></div>`
    : '';

  setStatus(
    root,
    'good',
    meta.mode === 'live' ? 'Live stream open' : 'Replaying recorded run',
    meta.mode === 'live'
      ? 'Waiting for the simulator to append cycles.'
      : 'Emitting the recorded run’s real rows at wall-clock speed.'
  );
}

function onCycle(root, message) {
  if (message.restarted) {
    // ios::app started a new run in the same file; do not draw across it.
    state.cycles = [];
    state.rows = [];
  }
  const previous = state.rows[state.rows.length - 1];
  state.cycles.push(message.cycle);
  state.rows.push(message.cols);

  if (previous) recordEvents(message, previous);

  drawTiles(root, message.cols);
  drawCrypto(root, message.cols);
  drawChart(root);
  drawEvents(root);

  root.querySelector('#live-sub').textContent =
    `${state.meta.run.label} · cycle ${message.cycle}`;
}

/** Turn monotone counter increases into a readable event feed. */
function recordEvents(message, previous) {
  for (const [column, label] of Object.entries(EVENT_LABELS)) {
    const delta = (message.cols[column] ?? 0) - (previous[column] ?? 0);
    if (delta > 0) {
      state.events.unshift({ cycle: message.cycle, label, delta });
    }
  }
  state.events = state.events.slice(0, 40);
}

function onEnd(root) {
  setStatus(root, 'good', 'Stream complete', `${state.cycles.length} cycles received.`);
  root.querySelector('#live-toggle').textContent = 'Watch';
  state.connected = false;
}

function onError(root, detail) {
  setStatus(root, 'critical', 'Stream failed', detail);
  root.querySelector('#live-toggle').textContent = 'Watch';
  state.connected = false;
}

function setStatus(root, status, title, detail) {
  root.querySelector('#live-status').innerHTML = `
    <div class="banner" data-status="${status}">
      <span class="glyph" aria-hidden="true">${
        status === 'critical' ? '✗' : status === 'warning' ? '⚠' : '✓'
      }</span>
      <div><strong>${title}</strong><span class="detail">${detail}</span></div>
    </div>`;
}

function drawTiles(root, cols) {
  const units = state.meta.units || {};
  root.querySelector('#live-tiles').innerHTML = state.meta.kpi_columns
    .filter((name) => name in cols)
    .map((name) => {
      const diagnostic = Boolean(state.meta.caveats && state.meta.caveats[name]);
      return `
        <div class="tile" data-diagnostic="${diagnostic}">
          <div class="label">${prettyColumn(name).replace(' (current)', '')}</div>
          <div class="value">${formatValue(cols[name], units[name] || 'count')}</div>
        </div>`;
    })
    .join('');
}

function drawCrypto(root, cols) {
  const units = state.meta.units || {};
  const wanted = [
    'sig_valid_rate', 'flowmod_endorsement_rate', 'rsu_chain_len', 'global_chain_len',
    'stark_timing_fail_count', 'stark_hop_fail_count',
  ];
  root.querySelector('#live-crypto').innerHTML = wanted
    .filter((name) => name in cols)
    .map(
      (name) => `
      <div class="tile">
        <div class="label">${prettyColumn(name)}</div>
        <div class="value">${formatValue(cols[name], units[name] || 'count')}</div>
      </div>`
    )
    .join('');
}

function drawChart(root) {
  const host = root.querySelector('#live-chart');
  if (!state.rows.length) return;

  const metric = state.chartMetric;
  if (!(metric in state.rows[0])) {
    host.innerHTML = `<p class="empty">${prettyColumn(metric)} is not in this run's schema.</p>`;
    return;
  }

  const unit = (state.meta.units && state.meta.units[metric]) || 'count';
  root.querySelector('#live-chart-title').textContent = prettyColumn(metric);

  renderLineChart(host, {
    series: [
      {
        key: metric,
        name: prettyColumn(metric).replace(' (current)', ''),
        color: 'var(--shade-dark)',
        points: state.cycles.map((c, i) => ({ x: c, y: state.rows[i][metric] })),
      },
    ],
    unit,
    yLabel: prettyColumn(metric).replace(' (current)', ''),
    xLabel: 'Routing cycle (1 s each)',
    vlines: [{ x: state.meta.attack_start_s, label: 'attack starts' }],
  });
}

function drawEvents(root) {
  const host = root.querySelector('#live-events');
  if (!state.events.length) {
    host.innerHTML = '<p class="empty">No events yet.</p>';
    return;
  }
  host.innerHTML = `
    <div class="table-scroll">
      <table class="data">
        <thead><tr><th>Cycle</th><th>Event</th><th>New this cycle</th></tr></thead>
        <tbody>
          ${state.events
            .map(
              (e) =>
                `<tr><td>${e.cycle}</td><td>${e.label}</td><td>+${e.delta}</td></tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>`;
}

/** Close any open stream, e.g. when the user switches away from the tab. */
export function stopLive() {
  if (state.socket && state.connected) state.socket.close();
}
