/**
 * Attack Lab: the map, and the four things the panel actually touches.
 *
 * Built as one tab rather than four because they are one activity. The panel
 * picks a scenario, watches it play, guesses who the attackers are, sees the
 * reveal, then switches a defence layer off and watches the same scenario go
 * wrong. Splitting that across tabs would break the thread.
 *
 * What is real and what is not, since a panel will ask:
 *
 * - The map is real. Vehicle positions are integrated from the same SUMO trace
 *   ns-3 replays; RSU and controller positions are the simulator's own layout.
 * - The accusations are real. Every edge is a row of `bc_detection_log`, an
 *   actual RSU naming an actual suspect via an actual signature.
 * - The reveal is real, when it is available. Ground truth comes from the
 *   simulator's own `declare_attackers()` output, and the UI says plainly when
 *   a run predates that capture rather than inventing an answer.
 * - The defence-layer comparison is real: each toggle maps to a published
 *   ablation config, so switching one off selects a run that was measured, not
 *   a model of what would happen.
 */

import { api, ApiError } from './api.js';
import { NetworkMap, signalLegend } from './mapview.js';
import { renderLineChart } from './charts.js';
import { fmt, prettyColumn } from './format.js';

let map = null;
let scene = null;
let options = null;
let catalog = null;
let timer = null;
let currentRunId = null;

const state = {
  playing: false,
  speed: 4,
  guessMode: false,
  revealed: false,
};

// -- PEM-over-time panel state -------------------------------------------
// Columns available per attack (attacks 3/4/baseline carry extra TCAM
// fields), fetched once and cached the same way offline.js does it.
const columnsByAttack = new Map();
//: One metric name per grid cell; defaults are the headline PEMs -- present
// on every attack variant (they live in schema.BASE_HEAD, not the
// attack-specific TCAM block) -- so the grid is never empty on first load.
const PEM_DEFAULTS = ['avg_DR', 'avg_FPR', 'avg_MCC', 'avg_lat_ms'];
const pemSelection = [...PEM_DEFAULTS];

export async function initLab(root) {
  root.innerHTML = shell();
  bindStaticControls(root);

  const canvas = root.querySelector('#map-canvas');
  map = new NetworkMap(canvas, {
    onSelect: (hit) => onSelect(root, hit),
    onGuess: () => renderGuessPanel(root),
  });

  initPemPanel(root);

  try {
    [options, catalog] = await Promise.all([api.simOptions(), api.catalog()]);
  } catch (error) {
    root.querySelector('#lab-status').textContent = error.message;
    return;
  }

  initScenarioConfigurator(root);
  renderDefenceBoard(root);

  window.addEventListener('mobiguard:tab-changed', (e) => {
    if (e.detail?.tab === 'lab' && map) {
      setTimeout(() => {
        map._resize();
        map.draw();
      }, 50);
    }
  });

  window.addEventListener('mobiguard:catalog-updated', async () => {
    try {
      catalog = await api.catalog();
      updateConfiguratorStatus(root);
    } catch {
      /* ignore */
    }
  });

  window.addEventListener('mobiguard:open-run-map', async (event) => {
    try {
      // 1. Switch active tab to Attack Lab FIRST so panel is visible in DOM
      const labTab = document.querySelector('.tab[data-tab="lab"]');
      if (labTab) {
        labTab.click();
      }
      // Re-scan results directory so mid-demo simulation runs appear immediately
      try {
        await api.refresh();
      } catch {
        /* ignore refresh error, fall back to existing catalog */
      }
      catalog = await api.catalog();
      updateConfiguratorStatus(root);

      const runId = event.detail?.run_id;
      const metricsFile = event.detail?.metrics_file;
      const attack = event.detail?.attack;

      let targetRun = null;

      // 1. Try finding by metrics_file name or stem
      if (metricsFile) {
        const stem = metricsFile.replace(/\.csv$/, '');
        targetRun = (catalog.runs || []).find(
          (r) => r.id === stem || r.file === metricsFile || (r.file && r.file.includes(stem)) || r.id === runId
        );
      }

      // 2. Try finding by runId
      if (!targetRun && runId) {
        targetRun = (catalog.runs || []).find(
          (r) => r.id === runId || (r.file && r.file.includes(runId))
        );
      }

      // 3. Fallback to attack number
      if (!targetRun && attack !== undefined) {
        const runs = (catalog.runs || []).filter((r) => r.attack === Number(attack));
        if (runs.length) {
          runs.sort((a, b) => b.pct - a.pct);
          targetRun = runs[0];
        }
      }

      // 4. Fallback to latest run in catalog
      if (!targetRun && catalog.runs && catalog.runs.length > 0) {
        targetRun = catalog.runs[catalog.runs.length - 1];
      }

      if (targetRun) {
        await loadRun(root, targetRun);
      }

      // Ensure canvas is resized and drawn after DOM layout stabilizes
      if (map) {
        setTimeout(() => {
          map._resize();
          map.draw();
        }, 50);
      }
    } catch (err) {
      console.error('Error handling mobiguard:open-run-map:', err);
    }
  });

  const first = pickDefaultRun();
  if (first) {
    await loadRun(root, first);
  } else {
    // No real results — load the synthetic demo so the map is never just blank.
    await loadDemoScene(root);
  }
}

// -- markup -----------------------------------------------------------------

function shell() {
  return `
  <div class="lab">
    <header class="lab-head">
      <h2>Attack Lab</h2>
    </header>

    <section class="panel" id="scenario-panel">
      <div class="scenario-configurator">
        <div class="cfg-row">
          <label class="param">
            <span class="param-label">Attack</span>
            <select id="cfg-attack"></select>
          </label>
          <label class="param">
            <span class="param-label">Attacker percentage</span>
            <select id="cfg-pct"></select>
          </label>
          <label class="param">
            <span class="param-label">Simulation time (s)</span>
            <input type="number" id="cfg-simtime" min="5" max="330" step="1">
          </label>
        </div>
        <div class="cfg-actions">
          <div id="cfg-status" class="cfg-status"></div>
          <div class="row">
            <button class="btn primary" id="cfg-load" disabled>▶ Load recorded run</button>
            <button class="btn" id="cfg-launch">⚙ Configure &amp; launch new run →</button>
          </div>
        </div>
      </div>
    </section>

    <div class="lab-body">
     <div class="lab-top">
      <section class="panel map-panel">
        <div class="map-status-bar" id="lab-status"></div>

        <div class="map-toolbar">
          <button class="btn primary" id="map-play">▶ Play</button>
          <label class="inline">
            Speed
            <select id="map-speed">
              <option value="1">1×</option>
              <option value="2">2×</option>
              <option value="4" selected>4×</option>
              <option value="8">8×</option>
              <option value="16">16×</option>
            </select>
          </label>
          <input type="range" id="map-time" min="0" max="0" value="0" step="1">
          <output id="map-clock" class="clock">t = 0 s</output>
        </div>

        <div class="map-stage">
          <div class="map-canvas-wrap">
            <canvas id="map-canvas"></canvas>
          </div>

          <div class="map-sidebar">
          <div class="map-overlay" id="map-overlay"></div>

          <div class="map-legend">
            <div class="legend-group">
              <span class="legend-label">Signatures</span>
              <div id="signal-legend" class="chips">${signalLegend()}</div>
            </div>
            <div class="legend-group">
              <span class="legend-label">Symbols</span>
              <div class="chips static">
                <span class="chip">
                  <svg class="legend-icon" viewBox="0 0 16 16" width="14" height="14">
                    <path d="M3.5,3.5 A5.5,5.5 0 0,1 12.5,3.5" fill="none" stroke="var(--text-muted)" stroke-width="1.3" stroke-linecap="round"/>
                    <path d="M5.5,5.5 A3,3 0 0,1 10.5,5.5" fill="none" stroke="var(--text-muted)" stroke-width="1.3" stroke-linecap="round"/>
                    <rect x="7.2" y="6" width="1.6" height="7" fill="var(--axis)"/>
                    <circle cx="8" cy="13.5" r="2" fill="var(--axis)"/>
                  </svg>
                  RSU (tower height = load)
                </span>
                <span class="chip">
                  <svg class="legend-icon" viewBox="0 0 16 16" width="14" height="14">
                    <polygon points="8,1.2 14.5,4.8 14.5,11.2 8,14.8 1.5,11.2 1.5,4.8" fill="var(--series-7)" stroke="var(--surface-raised)" stroke-width="1.2"/>
                    <line x1="4.5" y1="6" x2="11.5" y2="6" stroke="var(--surface-raised)" stroke-width="1.1" stroke-linecap="round" opacity="0.8"/>
                    <line x1="4.5" y1="8" x2="11.5" y2="8" stroke="var(--surface-raised)" stroke-width="1.1" stroke-linecap="round" opacity="0.8"/>
                    <line x1="4.5" y1="10" x2="11.5" y2="10" stroke="var(--surface-raised)" stroke-width="1.1" stroke-linecap="round" opacity="0.8"/>
                  </svg>
                  Controller
                </span>
                <span class="chip">
                  <svg class="legend-icon" viewBox="0 0 18 12" width="16" height="11">
                    <rect x="1" y="1" width="16" height="10" rx="2.5" fill="var(--series-2)" stroke="var(--surface-raised)" stroke-width="0.8"/>
                    <rect x="5.5" y="2.5" width="6.5" height="7" rx="1.2" fill="rgba(0,0,0,0.35)"/>
                    <rect x="15" y="2" width="1.5" height="2.5" fill="rgba(255,245,160,0.95)" rx="0.4"/>
                    <rect x="15" y="7.5" width="1.5" height="2.5" fill="rgba(255,245,160,0.95)" rx="0.4"/>
                  </svg>
                  Vehicle
                </span>
                <span class="chip">
                  <svg class="legend-icon" viewBox="0 0 20 14" width="18" height="12">
                    <!-- outer dashed warning halo -->
                    <rect x="0.5" y="0.5" width="19" height="13" rx="4" fill="rgba(239,68,68,0.22)" stroke="rgba(239,68,68,0.85)" stroke-width="0.8" stroke-dasharray="2 1.5"/>
                    <!-- car body -->
                    <rect x="2.5" y="2" width="15" height="10" rx="2.5" fill="var(--status-critical)" stroke="#ffffff" stroke-width="0.8"/>
                    <rect x="6.5" y="3.5" width="6.5" height="7" rx="1.2" fill="rgba(60,0,0,0.55)"/>
                    <!-- yellow beacon -->
                    <circle cx="9.75" cy="7" r="1.5" fill="#fde047" stroke="#ffffff" stroke-width="0.4"/>
                    <rect x="16" y="3" width="1.5" height="2.5" fill="rgba(255,220,220,0.95)" rx="0.4"/>
                    <rect x="16" y="8.5" width="1.5" height="2.5" fill="rgba(255,220,220,0.95)" rx="0.4"/>
                  </svg>
                  Accused vehicle (warning halo + beacon)
                </span>
              </div>
            </div>
            <div class="legend-group">
              <span class="legend-label">Layers</span>
              <div class="chips">
                <label class="chip"><input type="checkbox" id="toggle-coverage" checked> RSU coverage</label>
                <label class="chip"><input type="checkbox" id="toggle-control" checked> Control plane</label>
              </div>
            </div>
          </div>
          </div>
        </div>
      </section>

      <div class="lab-right">
        <section class="panel pem-panel">
          <h3>📈 Performance Metrics Over Time</h3>
          <p class="hint">How the loaded run's own metrics evolved cycle by cycle -- the same per-cycle series the Live PEM Monitor streams, read back after the fact.</p>
          <div id="pem-grid" class="pem-grid"></div>
          <div id="pem-note" class="pem-note"></div>
        </section>
      </div>
     </div>

      <aside class="lab-side">
        <section class="panel" id="guess-panel">
          <h3>🎯 Spot the Attacker</h3>
          <div class="row">
            <button class="btn" id="guess-toggle">Start guessing</button>
            <button class="btn" id="guess-reveal" disabled>Reveal</button>
            <button class="btn ghost" id="guess-clear">Clear</button>
          </div>
          <p class="hint" id="guess-hint"></p>
          <div id="guess-result"></div>
        </section>

        <section class="panel" id="inspector-panel">
          <h3>🔍 Node Inspector</h3>
          <div id="inspector">
            <p class="empty">Click any node on the map.</p>
          </div>
        </section>

        <section class="panel" id="defence-panel">
          <h3>🛡 Defence Layers</h3>
          <div id="defence-board"></div>
        </section>
      </aside>
    </div>
  </div>`;
}

// -- scenario configurator ----------------------------------------------------

/**
 * Attack / percentage / simulation-time, picked directly rather than through
 * nine fixed scenario cards. Two ways out of it:
 *
 * - **Load recorded run**, when a matching run already exists on disk --
 *   opens it on the map immediately, same as the old cards did.
 * - **Configure & launch new run**, always available -- hands the exact
 *   combination to the Run Simulation tab (which is where `simTime` actually
 *   takes effect; a recorded run's duration is fixed, so browsing one plays
 *   it at whatever length it was captured at).
 *
 * The percentage list matches `attack_percentage`'s own choices in
 * `params.py` (0/20/40/60/80/100) rather than the free-form catalog values --
 * anything picked here is guaranteed launchable, not just guaranteed to have
 * existed once as an ablation run.
 */
const STANDARD_PERCENTAGES = [0, 20, 40, 60, 80, 100];

function initScenarioConfigurator(root) {
  const attackSelect = root.querySelector('#cfg-attack');
  const pctSelect = root.querySelector('#cfg-pct');
  const simTimeInput = root.querySelector('#cfg-simtime');

  attackSelect.innerHTML = (options.attacks || [])
    .map((a) => `<option value="${a.number}">${a.number} — ${a.name}${a.plane && a.plane !== '--' ? ` (${a.plane})` : ''}</option>`)
    .join('');
  pctSelect.innerHTML = STANDARD_PERCENTAGES
    .map((p) => `<option value="${p}">${p}%${p === 0 ? ' (no attack)' : ''}</option>`)
    .join('');

  const simTimeParam = (options.groups || [])
    .flatMap((g) => g.params || [])
    .find((p) => p.name === 'simTime');
  simTimeInput.value = String(simTimeParam?.default ?? 40);
  if (simTimeParam?.min != null) simTimeInput.min = String(simTimeParam.min);
  if (simTimeParam?.max != null) simTimeInput.max = String(simTimeParam.max);

  attackSelect.addEventListener('change', () => updateConfiguratorStatus(root));
  pctSelect.addEventListener('change', () => updateConfiguratorStatus(root));

  root.querySelector('#cfg-load').addEventListener('click', async () => {
    const best = bestMatchingRun(currentSelection(root));
    if (best) {
      const simTime = Number(simTimeInput.value);
      await loadRun(root, best, { trimTo: Number.isFinite(simTime) && simTime > 0 ? simTime : undefined });
    }
  });

  root.querySelector('#cfg-launch').addEventListener('click', () => {
    const { attack, pct } = currentSelection(root);
    const simTime = Number(simTimeInput.value) || undefined;
    window.dispatchEvent(
      new CustomEvent('mobiguard:configure-run', {
        detail: { attack, pct, simTime },
      })
    );
    document.querySelector('.tab[data-tab="simulation"]')?.click();
  });

  updateConfiguratorStatus(root);
}

function currentSelection(root) {
  return {
    attack: Number(root.querySelector('#cfg-attack').value),
    pct: Number(root.querySelector('#cfg-pct').value),
  };
}

function matchingRuns(attack, pct) {
  return (catalog.runs || []).filter((r) => r.attack === attack && r.pct === pct);
}

/** Prefer an untagged, higher-seed-count run over a one-off ablation variant. */
function bestMatchingRun({ attack, pct }) {
  const runs = matchingRuns(attack, pct);
  if (!runs.length) return null;
  const score = (run) =>
    (run.tag ? 0 : 100) + ((run.tag || '').startsWith('GUI') ? 400 : 0) +
    Math.min(run.size_bytes || 0, 500_000) / 1000;
  return [...runs].sort((a, b) => score(b) - score(a))[0];
}

/** Sets the selects to reflect a scene already on the map, without loading anything. */
function syncConfiguratorSelection(root, scene) {
  const attackSelect = root.querySelector('#cfg-attack');
  const pctSelect = root.querySelector('#cfg-pct');
  if (!attackSelect || !pctSelect) return;
  if ([...attackSelect.options].some((o) => Number(o.value) === scene.attack_id)) {
    attackSelect.value = String(scene.attack_id);
  }
  if ([...pctSelect.options].some((o) => Number(o.value) === scene.attack_percentage)) {
    pctSelect.value = String(scene.attack_percentage);
  }
  updateConfiguratorStatus(root);
}

function updateConfiguratorStatus(root) {
  const status = root.querySelector('#cfg-status');
  const loadBtn = root.querySelector('#cfg-load');
  if (!status || !loadBtn) return;
  const selection = currentSelection(root);
  const runs = matchingRuns(selection.attack, selection.pct);
  loadBtn.disabled = runs.length === 0;
  status.innerHTML = runs.length
    ? `<span class="good">✓ ${runs.length} recorded run${runs.length === 1 ? '' : 's'}</span> at this exact combination — Load opens the best one.`
    : `<span class="warn">No recorded run</span> at this combination yet — Configure &amp; launch to collect one.`;
}

function pickDefaultRun() {
  const runs = (catalog.runs || []).filter((r) => r.attack > 0);
  if (!runs.length) return (catalog.runs || [])[0] || null;
  // Rank rather than filter: a GUI-launched run carries an attacker roster, so
  // the reveal works on arrival, but a two-row GUI test run is a worse opening
  // than a full sweep run. Size stands in for duration -- the catalog does not
  // carry a cycle count, and rows are fixed width.
  // A GUI-launched run carries an attacker roster, so the reveal works on
  // arrival -- worth a lot, but not unconditionally: a 20-row GUI smoke test is
  // a worse opening than a full sweep run. The bonus is therefore comparable to
  // a large run's size score rather than dominating it. Size stands in for
  // duration; the catalog carries no cycle count and rows are fixed width.
  const score = (run) =>
    ((run.tag || '').startsWith('GUI') ? 400 : 0) +
    Math.min(run.size_bytes || 0, 500_000) / 1000 +
    run.pct;
  return [...runs].sort((a, b) => score(b) - score(a))[0];
}

// -- run loading -------------------------------------------------------------

async function loadDemoScene(root) {
  const status = root.querySelector('#lab-status');
  status.innerHTML = `<span class="spinner"></span> Loading demo scene…`;
  stopPlayback(root);
  currentRunId = 'demo';
  try {
    scene = await api.mapDemoScene();
  } catch (error) {
    status.innerHTML = `<span class="bad">${error.message}</span>`;
    return;
  }

  map.setScene(scene);
  map.setFrame(0);

  const slider = root.querySelector('#map-time');
  slider.max = String(Math.max(0, scene.frames.length - 1));
  slider.value = '0';

  state.revealed = false;
  map.revealed = null;
  root.querySelector('#guess-reveal').disabled = false;
  root.querySelector('#guess-result').innerHTML = '';
  renderGuessPanel(root);
  renderOverlay(root);
  updateClock(root);
  syncConfiguratorSelection(root, scene);
  loadPemPanel(root);

  status.innerHTML = `
    <div class="run-badge demo-badge">
      ⚠ <strong>Demo</strong> — synthetic data.
      <span class="good">5 hidden attackers</span> · vehicles 3, 7, 12, 18, 25 · attack starts at t = 10 s
    </div>`;
}

async function loadRun(root, run, { trimTo } = {}) {
  const status = root.querySelector('#lab-status');
  status.innerHTML = `<span class="spinner"></span> Building the map for ${run.id}…`;
  stopPlayback(root);
  currentRunId = run.id;
  try {
    // `trimTo` only trims playback of this already-recorded run to the first
    // N seconds -- it does not shorten how long the run itself took to
    // produce. Changing "Simulation time" alone never re-runs anything; that
    // only happens through "Configure & launch new run".
    scene = await api.mapScene(run.id, trimTo ? { end: trimTo } : {});
  } catch (error) {
    status.innerHTML = `<span class="bad">${error.message}</span>`;
    return;
  }

  map.setScene(scene);
  map.setFrame(0);

  const slider = root.querySelector('#map-time');
  slider.max = String(Math.max(0, scene.frames.length - 1));
  slider.value = '0';

  state.revealed = false;
  map.revealed = null;
  root.querySelector('#guess-reveal').disabled = !scene.ground_truth.known;
  root.querySelector('#guess-result').innerHTML = '';
  renderGuessPanel(root);
  renderOverlay(root);
  updateClock(root);

  syncConfiguratorSelection(root, scene);
  loadPemPanel(root);

  const gt = scene.ground_truth;
  status.innerHTML = `
    <div class="run-badge">
      <strong>Attack ${scene.attack_id}</strong> at ${scene.attack_percentage}%,
      seed ${scene.seed} · ${fmt.int(scene.event_count)} accusations over
      ${fmt.num(scene.duration, 0)} s
      ${trimTo ? `<span class="warn"> (trimmed to first ${fmt.num(trimTo, 0)} s of the recorded run — it still ran its full length when captured)</span>` : ''}
    </div>
    <div class="run-sources">
      ${gt.known
        ? `<span class="good">Ground truth available</span> (${gt.attackers.length} attackers, ${gt.source})`
        : `<span class="warn">Ground truth not recorded</span>${
            gt.expected_count === null
              ? ' — and the count is not derivable for this variant either: it depends on which RSUs were on-path at injection time.'
              : ` — expected ${gt.expected_count} attackers.`
          } ${gt.source}`}
    </div>
    <div style="margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap; align-items: center;">
      <span class="scenario-plane-pill ctrl" style="font-size: 11px;">🛡 MOBIGUARD Defense Pipeline Active:</span>
      <span class="sig" style="font-size: 11px;">L1 Rule Signatures</span>
      <span class="sig" style="font-size: 11px;">L2 Fed-LSTM</span>
      <span class="sig" style="font-size: 11px;">L3 STARK ZKP</span>
      <span class="sig" style="font-size: 11px;">L4 BFT Voting</span>
    </div>
    ${(scene.notes || []).map((n) => `<div class="note">${n}</div>`).join('')}`;
}

// -- playback ----------------------------------------------------------------

function bindStaticControls(root) {
  root.querySelector('#map-play').addEventListener('click', () => {
    if (state.playing) stopPlayback(root);
    else startPlayback(root);
  });
  root.querySelector('#map-speed').addEventListener('change', (e) => {
    state.speed = Number(e.target.value);
    if (state.playing) {
      stopPlayback(root);
      startPlayback(root);
    }
  });
  root.querySelector('#map-time').addEventListener('input', (e) => {
    stopPlayback(root);
    map.setFrame(Number(e.target.value));
    updateClock(root);
    renderOverlay(root);
    drawPemAtTime(root);
  });
  root.querySelector('#toggle-coverage').addEventListener('change', (e) => {
    map.showCoverage = e.target.checked;
    map.draw();
  });
  root.querySelector('#toggle-control').addEventListener('change', (e) => {
    map.showControlPlane = e.target.checked;
    map.draw();
  });
  root.querySelector('#signal-legend').addEventListener('click', (e) => {
    const chip = e.target.closest('.sig-chip');
    if (!chip) return;
    const signal = chip.dataset.signal;
    map.filterSignal = map.filterSignal === signal ? null : signal;
    root.querySelector('#signal-legend').innerHTML = signalLegend(map.filterSignal);
    map.draw();
    renderOverlay(root);
  });

  root.querySelector('#guess-toggle').addEventListener('click', () => {
    state.guessMode = !state.guessMode;
    map.guessMode = state.guessMode;
    renderGuessPanel(root);
  });
  root.querySelector('#guess-clear').addEventListener('click', () => {
    map.guesses.clear();
    map.revealed = null;
    state.revealed = false;
    root.querySelector('#guess-result').innerHTML = '';
    map.draw();
    renderGuessPanel(root);
  });
  root.querySelector('#guess-reveal').addEventListener('click', () => reveal(root));
}

function startPlayback(root) {
  if (!scene || !scene.frames.length) return;
  // At the end already (e.g. a previous playthrough ran out, or the time
  // slider was dragged to the last frame) -- Play means "play from the
  // start" here, not "advance past the last frame and immediately stop".
  if (map.frameIndex >= scene.frames.length - 1) {
    map.setFrame(0);
    root.querySelector('#map-time').value = '0';
    updateClock(root);
    renderOverlay(root);
    drawPemAtTime(root);
  }
  state.playing = true;
  root.querySelector('#map-play').textContent = '❚❚ Pause';
  const period = 1000 / state.speed;
  timer = setInterval(() => {
    const next = map.frameIndex + 1;
    if (next >= scene.frames.length) {
      stopPlayback(root);
      return;
    }
    map.setFrame(next);
    root.querySelector('#map-time').value = String(next);
    updateClock(root);
    renderOverlay(root);
    drawPemAtTime(root);
  }, period);
}

function stopPlayback(root) {
  state.playing = false;
  if (timer) clearInterval(timer);
  timer = null;
  const button = root.querySelector('#map-play');
  if (button) button.textContent = '▶ Play';
}

export function stopLab() {
  state.playing = false;
  if (timer) clearInterval(timer);
  timer = null;
}

function updateClock(root) {
  const out = root.querySelector('#map-clock');
  if (!out || !scene) return;
  const t = map.time;
  const dur = scene.duration ?? 0;
  const attackStarted = t >= 10;
  out.innerHTML = `t = ${fmt.num(t, 0)} s / ${fmt.num(dur, 0)} s ${
    attackStarted
      ? '<span class="tag attack">attack active</span>'
      : '<span class="tag benign">benign baseline</span>'
  }`;
}

/** Live counters over the currently visible window. */
function renderOverlay(root) {
  const host = root.querySelector('#map-overlay');
  if (!host || !map.frame) return;
  // The events currently *drawn*, which is the fade window rather than the
  // single current second -- otherwise the panel reads "0 accusations" while
  // edges are visibly lit on the map.
  const events = map.visibleEvents();
  const bySignal = {};
  for (const e of events) bySignal[e.signal] = (bySignal[e.signal] || 0) + 1;
  const suspects = new Set(events.map((e) => e.suspect));
  const load = Object.values(map.frame.density || {});
  const peak = load.length ? Math.max(...load.map(Number)) : 0;

  host.innerHTML = `
    <div class="overlay-card">
      <div class="overlay-row"><span>Accusations (last 3 s)</span><strong>${events.length}</strong></div>
      <div class="overlay-row"><span>Distinct suspects</span><strong>${suspects.size}</strong></div>
      <div class="overlay-row"><span>Busiest RSU</span><strong>${peak} vehicles</strong></div>
      <div class="overlay-sigs">
        ${Object.entries(bySignal)
          .sort()
          .map(([s, n]) => `<span class="sig sig-${s}">${s} ${n}</span>`)
          .join('') || '<span class="quiet">no accusations</span>'}
      </div>
    </div>`;
}

// -- spot the attacker -------------------------------------------------------

function renderGuessPanel(root) {
  const button = root.querySelector('#guess-toggle');
  if (button) {
    button.textContent = state.guessMode ? 'Stop guessing' : 'Start guessing';
    button.classList.toggle('primary', state.guessMode);
  }
  const revealBtn = root.querySelector('#guess-reveal');
  if (revealBtn) {
    revealBtn.disabled = !scene || !scene.ground_truth || !scene.ground_truth.known;
  }
  const count = map?.guesses?.size ?? 0;
  const hint = root.querySelector('#guess-hint') || root.querySelector('#guess-panel .hint');
  if (hint) {
    if (state.guessMode) {
      hint.innerHTML = `<strong>Guessing mode ON.</strong> Click nodes on map.
        ${count} selected${
          scene && scene.ground_truth && scene.ground_truth.expected_count !== null
            ? ` (expected ${scene.ground_truth.expected_count})`
            : ''
        }.`;
    } else {
      hint.innerHTML = count > 0 ? `${count} node(s) selected.` : '';
    }
  }
}

async function reveal(root) {
  if (!scene || !currentRunId) return;
  const host = root.querySelector('#guess-result');
  host.innerHTML = '<span class="spinner"></span> Scoring…';
  let result;
  try {
    result = await api.mapGuess(currentRunId, [...map.guesses]);
  } catch (error) {
    host.innerHTML = `<p class="bad">${error.message}</p>`;
    return;
  }

  if (!result.scored) {
    host.innerHTML = `
      <p class="warn">Cannot score this guess: ${result.reason}</p>
      <p class="hint">${
        result.expected_count === null
          ? 'The attacker count is not derivable for this variant either — Hidden Forwarding picks its attackers from whichever RSUs were on-path at injection time.'
          : `This run should have had <strong>${result.expected_count}</strong> attackers; that number is derivable from the attacker percentage even when the identities are not.`
      } Launch a run from the Simulation tab to get an exact roster.</p>`;
    return;
  }

  state.revealed = true;
  map.revealed = new Set(scene.ground_truth.attackers);
  map.guessMode = false;
  state.guessMode = false;
  map.draw();
  renderGuessPanel(root);

  host.innerHTML = `
    <div class="score">
      <div class="score-grid">
        <div class="score-cell good"><span>${result.tp}</span><label>caught</label></div>
        <div class="score-cell warn"><span>${result.fp}</span><label>false alarms</label></div>
        <div class="score-cell bad"><span>${result.fn}</span><label>missed</label></div>
      </div>
      <table class="mini">
        <tr><th>Precision</th><td>${fmt.pct(result.precision * 100)}</td></tr>
        <tr><th>Recall</th><td>${fmt.pct(result.recall * 100)}</td></tr>
        <tr><th>F1</th><td>${fmt.num(result.f1, 3)}</td></tr>
        <tr><th>Actual attackers</th><td>${result.actual_count}</td></tr>
      </table>
      <p class="hint">On the map: a <em>green ring</em> is an attacker you found,
        a <em>red ring</em> one you missed, an <em>amber cross</em> a node you
        accused that was innocent.</p>
    </div>`;
}

// -- inspector ---------------------------------------------------------------

async function onSelect(root, hit) {
  const host = root.querySelector('#inspector');
  if (!hit) {
    host.innerHTML = '<p class="empty">Nothing selected.</p>';
    return;
  }
  host.innerHTML = `<span class="spinner"></span> Loading ${hit.label}…`;
  let detail;
  try {
    detail = await api.mapNode(currentRunId, hit.id);
  } catch (error) {
    host.innerHTML = `<p class="bad">${error.message}</p>`;
    return;
  }

  const truth =
    detail.ground_truth_known
      ? detail.is_attacker
        ? '<span class="tag attack">attacker (ground truth)</span>'
        : '<span class="tag benign">benign (ground truth)</span>'
      : '<span class="tag unknown">ground truth not recorded</span>';

  const sigRow = (signals) =>
    Object.entries(signals || {})
      .map(([s, n]) => `<span class="sig sig-${s}">${s} ${n}</span>`)
      .join('') || '<span class="quiet">none</span>';

  const dl = detail.defence_layers || {};
  const lstmBadge = dl.lstm_anomaly_score > 0.5
    ? `<span class="tag attack">High Anomaly (${(dl.lstm_anomaly_score * 100).toFixed(1)}%)</span>`
    : `<span class="tag benign">Normal (${(dl.lstm_anomaly_score * 100).toFixed(1)}%)</span>`;
  const zkpBadge = dl.zkp_status?.includes('Invalid')
    ? `<span class="tag attack">${dl.zkp_status}</span>`
    : `<span class="tag benign">${dl.zkp_status || 'Verified Valid'}</span>`;
  const bftBadge = dl.bft_status?.includes('Quarantined')
    ? `<span class="tag attack">${dl.bft_status}</span>`
    : `<span class="tag benign">${dl.bft_status || 'Active Roster'}</span>`;

  host.innerHTML = `
    <div class="node-head">
      <strong>${hit.label}</strong> ${truth}
      <span class="kind">${detail.kind}</span>
    </div>
    ${detail.position
      ? `<p class="quiet">at (${fmt.num(detail.position.x, 0)}, ${fmt.num(detail.position.y, 0)}) m${
          detail.grid ? ` · grid r${detail.grid.row} c${detail.grid.col}` : ''
        }${detail.controller !== undefined ? ` · controller c${detail.controller + 1}` : ''}</p>`
      : ''}
    <h4>🛡 Proposed Defense Pipeline</h4>
    <table class="mini">
      <tr><th>Layer 1 (Signatures)</th><td>${sigRow(detail.accused.signals)}</td></tr>
      <tr><th>Layer 2 (Fed-LSTM)</th><td>${lstmBadge}</td></tr>
      <tr><th>Layer 3 (STARK ZKP)</th><td>${zkpBadge}</td></tr>
      <tr><th>Layer 4 (BFT Voting)</th><td>${bftBadge}</td></tr>
    </table>
    ${detail.kind === 'rsu'
      ? `<h4>Accusations raised</h4>
         <table class="mini">
           <tr><th>Times</th><td>${fmt.int(detail.raised.count)}</td></tr>
           <tr><th>Distinct suspects</th><td>${detail.raised.suspects.length}</td></tr>
           <tr><th>Signatures</th><td>${sigRow(detail.raised.signals)}</td></tr>
         </table>`
      : ''}`;
}

// -- performance metrics over time -------------------------------------------

/**
 * Four small per-cycle time-series charts beside the map, each with its own
 * metric picker. Reuses `renderLineChart` from charts.js (the same primitive
 * Offline Analytics draws its trend chart with) rather than a bespoke
 * sparkline, so the mark specs, crosshair and 2px-line conventions stay one
 * system rather than two.
 */
function initPemPanel(root) {
  const grid = root.querySelector('#pem-grid');
  grid.innerHTML = pemSelection
    .map(
      (_, slot) => `
      <div class="pem-cell" data-slot="${slot}">
        <select class="pem-metric-select" data-slot="${slot}"></select>
        <div class="pem-chart" data-slot="${slot}"></div>
      </div>`
    )
    .join('');

  grid.querySelectorAll('.pem-metric-select').forEach((select) => {
    select.addEventListener('change', () => {
      pemSelection[Number(select.dataset.slot)] = select.value;
      renderPemCharts(root);
    });
  });
}

/** Fetch this attack's column list (cached) and populate all four selects. */
async function ensurePemColumns(root, attackId) {
  if (!columnsByAttack.has(attackId)) {
    try {
      const meta = await api.metrics(attackId);
      columnsByAttack.set(attackId, meta.columns);
    } catch {
      return null;
    }
  }
  const columns = columnsByAttack.get(attackId);
  const known = new Set(columns.map((c) => c.name));

  // A metric picked under a previous (TCAM-wide) attack may not exist here;
  // fall back to that slot's default, and only as a last resort to whatever
  // the schema offers first, so a select is never left without a value.
  pemSelection.forEach((name, slot) => {
    if (!known.has(name)) {
      pemSelection[slot] = known.has(PEM_DEFAULTS[slot]) ? PEM_DEFAULTS[slot] : columns[0]?.name;
    }
  });

  root.querySelectorAll('.pem-metric-select').forEach((select) => {
    const slot = Number(select.dataset.slot);
    select.innerHTML = columns
      .map((c) => `<option value="${c.name}"${c.name === pemSelection[slot] ? ' selected' : ''}>${prettyColumn(c.name)}</option>`)
      .join('');
  });
  return columns;
}

/** Load the current run's PEM panel from scratch: columns, then series, then draw. */
async function loadPemPanel(root) {
  const note = root.querySelector('#pem-note');
  if (!scene) return;

  pemSeries = null;
  pemSeriesRunId = null;

  if (currentRunId === 'demo') {
    root.querySelectorAll('.pem-chart').forEach((c) => (c.innerHTML = ''));
    note.textContent = 'Per-cycle metrics need a real recorded run -- the synthetic demo scene has none to read back.';
    return;
  }

  note.textContent = '';
  const columns = await ensurePemColumns(root, scene.attack_id);
  if (!columns) {
    note.textContent = 'Could not load this attack’s metric list.';
    return;
  }
  await renderPemCharts(root);
}

//: The current run's full fetched series, so scrubbing/playing the map only
// re-slices already-fetched data instead of re-requesting on every frame.
// Keyed to the run it belongs to, so a fetch that resolves after the user has
// already switched runs is never drawn against the wrong one.
let pemSeries = null;
let pemSeriesRunId = null;

/** Fetch the four selected columns for the current run (one request), then draw. */
async function renderPemCharts(root) {
  if (!currentRunId || currentRunId === 'demo') return;
  const note = root.querySelector('#pem-note');
  const metrics = [...new Set(pemSelection.filter(Boolean))];
  if (!metrics.length) return;

  const forRunId = currentRunId;
  let series;
  try {
    series = await api.series(forRunId, metrics);
  } catch (error) {
    note.textContent = error.message;
    return;
  }
  if (forRunId !== currentRunId) return; // superseded by a later run switch

  pemSeries = series;
  pemSeriesRunId = forRunId;
  drawPemAtTime(root);
}

/**
 * Redraw the four charts up to the map's current playhead (`map.time`),
 * exactly the way Live PEM Monitor's chart grows as cycles stream in --
 * scrubbing or playing the map advances these the same way watching a live
 * stream would, just replayed from an already-fetched run instead of a
 * WebSocket.
 */
function drawPemAtTime(root) {
  if (!pemSeries || pemSeriesRunId !== currentRunId || !map) return;
  const note = root.querySelector('#pem-note');
  const t = map.time ?? 0;
  const count = pemSeries.cycles.filter((c) => c <= t).length;
  const cycles = pemSeries.cycles.slice(0, count);

  const caveats = new Set();
  pemSelection.forEach((name, slot) => {
    const cell = root.querySelector(`.pem-chart[data-slot="${slot}"]`);
    if (!cell || !name) return;
    const values = pemSeries.columns[name];
    if (!values) {
      cell.innerHTML = '<p class="empty">Not in this attack’s columns.</p>';
      return;
    }
    if (pemSeries.caveats[name]) caveats.add(pemSeries.caveats[name]);

    renderLineChart(cell, {
      // Compact: this panel sits beside the map, at map height, not below
      // it at page width -- narrow again, so the cramped-viewBox style
      // (see charts.js) is what stays legible here.
      compact: true,
      series: [{
        key: name,
        name: prettyColumn(name),
        color: 'var(--series-1)',
        points: cycles.map((c, i) => ({ x: c, y: values[i] })),
      }],
      unit: pemSeries.units[name] || 'count',
      yLabel: prettyColumn(name),
      xLabel: 's',
      // Only draw the marker once the playhead has reached it, same as a
      // live stream never shows "attack starts" before cycle 10 arrives.
      vlines: t >= pemSeries.attack_start_s ? [{ x: pemSeries.attack_start_s, label: 'attack starts' }] : [],
    });
  });

  note.innerHTML = caveats.size
    ? `<span class="warn">⚠</span> ${[...caveats].join(' ')}`
    : '';
}

// -- defence board -----------------------------------------------------------

/**
 * The toggle board. Each switch names its ablation and what turning it off
 * costs, and links to the runs that measured it.
 */
function renderDefenceBoard(root) {
  const host = root.querySelector('#defence-board');
  host.innerHTML = (options.defences || [])
    .map(
      (layer) => `
      <div class="defence-row" data-key="${layer.key}">
        <label class="switch" title="${layer.blurb}">
          <input type="checkbox" ${layer.default ? 'checked' : ''} data-layer="${layer.key}">
          <span class="track"></span>
        </label>
        <div class="defence-text">
          <strong>${layer.label}</strong>
          <span class="ablation">${layer.ablation}</span>
        </div>
      </div>`
    )
    .join('') +
    `<p class="hint" id="defence-summary">All layers on — full MOBIGUARD config.</p>
     <button class="btn primary" id="defence-send" style="width: 100%; margin-top: 10px;">Send to Simulation →</button>`;

  host.querySelectorAll('input[data-layer]').forEach((input) => {
    input.addEventListener('change', () => updateDefenceSummary(root));
  });
  host.querySelector('#defence-send').addEventListener('click', () => {
    const defences = collectDefences(root);
    window.dispatchEvent(
      new CustomEvent('mobiguard:configure-run', {
        detail: { defences, attack: scene?.attack_id, pct: scene?.attack_percentage },
      })
    );
    const simTab = document.querySelector('.tab[data-tab="simulation"]');
    if (simTab) simTab.click();
  });
}

export function collectDefences(root) {
  const out = {};
  root.querySelectorAll('input[data-layer]').forEach((input) => {
    out[input.dataset.layer] = input.checked;
  });
  return out;
}

function updateDefenceSummary(root) {
  const defences = collectDefences(root);
  const off = (options.defences || [])
    .filter((layer) => defences[layer.key] === false)
    .map((layer) => `${layer.label} (${layer.ablation})`);
  const summary = root.querySelector('#defence-summary');
  summary.innerHTML = off.length
    ? `<strong>${off.length} disabled:</strong> ${off.map((l) => l.split(' (')[0]).join(', ')}.`
    : 'All layers on — full MOBIGUARD config.';
}
