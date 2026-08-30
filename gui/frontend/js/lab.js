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
import { fmt } from './format.js';

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

export async function initLab(root) {
  root.innerHTML = shell();
  bindStaticControls(root);

  const canvas = root.querySelector('#map-canvas');
  map = new NetworkMap(canvas, {
    onSelect: (hit) => onSelect(root, hit),
    onGuess: () => renderGuessPanel(root),
  });

  try {
    [options, catalog] = await Promise.all([api.simOptions(), api.catalog()]);
  } catch (error) {
    root.querySelector('#lab-status').textContent = error.message;
    return;
  }

  renderScenarioPicker(root);
  renderDefenceBoard(root);

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
      <div>
        <h2>Attack Lab</h2>
        <p class="lede">
          The live network, the attacks running on it, and the signatures that
          catch them. Everything drawn here comes from a simulation that ran.
        </p>
      </div>
      <div class="lab-status" id="lab-status"></div>
    </header>

    <section class="panel" id="scenario-panel">
      <h3>1 · Pick a scenario</h3>
      <div id="scenario-picker" class="scenario-grid"></div>
    </section>

    <div class="lab-body">
      <section class="panel map-panel">
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
          <canvas id="map-canvas"></canvas>
          <div class="map-overlay" id="map-overlay"></div>
        </div>

        <div class="map-legend">
          <div class="legend-group">
            <span class="legend-label">Signatures</span>
            <div id="signal-legend" class="chips">${signalLegend()}</div>
          </div>
          <div class="legend-group">
            <span class="legend-label">Layers</span>
            <div class="chips">
              <label class="chip"><input type="checkbox" id="toggle-coverage" checked> RSU coverage</label>
              <label class="chip"><input type="checkbox" id="toggle-control" checked> Control plane</label>
            </div>
          </div>
          <div class="legend-group">
            <span class="legend-label">Symbols</span>
            <div class="chips static">
              <span class="chip"><span class="mark node-rsu"></span>RSU (size = vehicles served)</span>
              <span class="chip"><span class="mark node-ctrl"></span>Controller</span>
              <span class="chip"><span class="mark node-veh"></span>Vehicle</span>
              <span class="chip"><span class="mark node-acc"></span>Currently accused</span>
            </div>
          </div>
        </div>
      </section>

      <aside class="lab-side">
        <section class="panel" id="guess-panel">
          <h3>2 · Spot the attacker</h3>
          <p class="hint">
            Turn this on and click the nodes you think are malicious. Then reveal
            and see how your guess scores against the same confusion matrix
            MOBIGUARD is judged by.
          </p>
          <div class="row">
            <button class="btn" id="guess-toggle">Start guessing</button>
            <button class="btn" id="guess-reveal" disabled>Reveal</button>
            <button class="btn ghost" id="guess-clear">Clear</button>
          </div>
          <div id="guess-result"></div>
        </section>

        <section class="panel" id="inspector-panel">
          <h3>3 · Inspect a node</h3>
          <p class="hint">Click any node on the map for its full detection story.</p>
          <div id="inspector">
            <p class="empty">Nothing selected.</p>
          </div>
        </section>

        <section class="panel" id="defence-panel">
          <h3>4 · Switch a defence off</h3>
          <p class="hint">
            Each switch maps to a published ablation, so the comparison is
            measured rather than modelled.
          </p>
          <div id="defence-board"></div>
        </section>
      </aside>
    </div>
  </div>`;
}

// -- scenario picker ---------------------------------------------------------

/**
 * One card per attack variant, showing what data exists for it.
 *
 * Variants with no run on disk are shown disabled rather than hidden: their
 * absence is information, and a panel asking "what about attack 6?" deserves
 * "no run has been collected for it here" rather than a menu that quietly
 * omits it.
 */
function renderScenarioPicker(root) {
  const byAttack = new Map();
  for (const run of catalog.runs || []) {
    if (!byAttack.has(run.attack)) byAttack.set(run.attack, []);
    byAttack.get(run.attack).push(run);
  }

  root.querySelector('#scenario-picker').innerHTML = (options.attacks || [])
    .map((attack) => {
      const runs = byAttack.get(attack.number) || [];
      const available = runs.length > 0;
      const sigs = attack.signatures.length
        ? attack.signatures.map((s) => `<span class="sig sig-${s}">${s}</span>`).join('')
        : '<span class="sig sig-none">baseline</span>';
      return `
      <button class="scenario-card${available ? '' : ' is-empty'}"
              data-attack="${attack.number}" ${available ? '' : 'disabled'}>
        <span class="scenario-num">${attack.number}</span>
        <span class="scenario-name">${attack.name}</span>
        <span class="scenario-plane">${attack.plane}</span>
        <span class="scenario-sigs">${sigs}</span>
        <span class="scenario-runs">${
          available ? `${runs.length} run${runs.length === 1 ? '' : 's'}` : 'no data'
        }</span>
      </button>`;
    })
    .join('');

  root.querySelectorAll('.scenario-card').forEach((card) => {
    card.addEventListener('click', async () => {
      const attack = Number(card.dataset.attack);
      const runs = (catalog.runs || []).filter((r) => r.attack === attack);
      if (!runs.length) return;
      // Highest attacker percentage first: the most visible instance of the
      // attack is the one worth opening on.
      runs.sort((a, b) => b.pct - a.pct);
      await loadRun(root, runs[0]);
    });
  });
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

  status.innerHTML = `
    <div class="run-badge">
      <strong>⚠ Demo mode</strong> — synthetic data, not a real simulation run.
      Copy results_routing/ CSVs from the HPC and hit <em>Refresh data</em> to use real data.
    </div>
    <div class="run-sources">
      <span class="good">Ground truth available</span>
      (${scene.ground_truth.attackers.length} synthetic attackers —
      vehicles ${scene.ground_truth.attackers.join(', ')})
    </div>
    <div class="note">Attack starts at t = 10 s. Press ▶ Play and watch the red accusations appear.</div>`;
}

async function loadRun(root, run) {
  const status = root.querySelector('#lab-status');
  status.innerHTML = `<span class="spinner"></span> Building the map for ${run.id}…`;
  stopPlayback(root);
  currentRunId = run.id;
  try {
    scene = await api.mapScene(run.id);
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

  const gt = scene.ground_truth;
  status.innerHTML = `
    <div class="run-badge">
      <strong>Attack ${scene.attack_id}</strong> at ${scene.attack_percentage}%,
      seed ${scene.seed} · ${fmt.int(scene.event_count)} accusations over
      ${fmt.num(scene.duration, 0)} s
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
  const attackStarted = t >= 10;
  out.innerHTML = `t = ${fmt.num(t, 0)} s ${
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
  button.textContent = state.guessMode ? 'Stop guessing' : 'Start guessing';
  button.classList.toggle('primary', state.guessMode);
  const count = map.guesses.size;
  const hint = root.querySelector('#guess-panel .hint');
  if (state.guessMode) {
    hint.innerHTML = `<strong>Guessing is on.</strong> Click nodes on the map.
      ${count} selected${
        scene && scene.ground_truth.expected_count !== null
          ? ` of ${scene.ground_truth.expected_count} attackers in this run`
          : ''
      }.`;
  } else {
    hint.innerHTML = `Turn this on and click the nodes you think are malicious.
      Then reveal and see how your guess scores against the same confusion
      matrix MOBIGUARD is judged by.`;
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
    <h4>Accused</h4>
    <table class="mini">
      <tr><th>Times</th><td>${fmt.int(detail.accused.count)}</td></tr>
      <tr><th>First / last</th><td>${fmt.num(detail.accused.first_t, 1)} s – ${fmt.num(detail.accused.last_t, 1)} s</td></tr>
      <tr><th>By</th><td>${detail.accused.accusers.length} RSU(s)</td></tr>
      <tr><th>Signatures</th><td>${sigRow(detail.accused.signals)}</td></tr>
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
        <label class="switch">
          <input type="checkbox" ${layer.default ? 'checked' : ''} data-layer="${layer.key}">
          <span class="track"></span>
        </label>
        <div class="defence-text">
          <strong>${layer.label}</strong>
          <span class="ablation">${layer.ablation}</span>
          <p>${layer.blurb}</p>
        </div>
      </div>`
    )
    .join('') +
    `<p class="hint" id="defence-summary">
       Toggling here composes a configuration. Send it to the Simulation tab to
       run it, or compare against the ablation runs already on disk.
     </p>
     <button class="btn" id="defence-send">Send this configuration to Simulation →</button>`;

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
    ? `<strong>${off.length} layer(s) disabled:</strong> ${off.join(', ')}.
       This is the configuration those ablations measured.`
    : 'All layers on — the full MOBIGUARD configuration.';
}
