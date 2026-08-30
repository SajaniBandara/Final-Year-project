/**
 * Simulation control: compose a run, launch it, watch it.
 *
 * This is the tab that makes "online mode" literal. The form is generated from
 * the backend's parameter registry rather than hand-written, so a flag added to
 * `params.py` appears here with its bounds and help text and cannot drift out
 * of sync with what the binary accepts.
 *
 * Three things are deliberate:
 *
 * 1. **The command line is always visible.** It updates on every change, before
 *    anything is launched. A panel asking "what exactly are you running?" gets
 *    an answer they can read, and the GUI doubles as a way to compose a command
 *    to run by hand later.
 * 2. **Warnings come from the server, not from here.** The conditions worth
 *    warning about (detector windows below 90 s, LSTM weights missing, a delay
 *    below S2's threshold) are properties of the simulator, so they live beside
 *    the code that knows them.
 * 3. **Progress is polled, not streamed.** A run emits one row per simulated
 *    second, roughly every four wall-seconds; a WebSocket for that cadence
 *    would be machinery without benefit, and polling survives a dropped
 *    connection without reconnect logic.
 */

import { api } from './api.js';
import { fmt } from './format.js';

let options = null;
let environment = null;
let poller = null;
let logCursor = 0;
let activeUid = null;

const values = {};
const defences = {};

export async function initSimulation(root) {
  root.innerHTML = '<p class="loading"><span class="spinner"></span> Checking the simulator…</p>';
  try {
    [options, environment] = await Promise.all([api.simOptions(), api.simEnvironment()]);
  } catch (error) {
    root.innerHTML = `<p class="bad">${error.message}</p>`;
    return;
  }

  seedDefaults();
  root.innerHTML = shell();
  renderEnvironment(root);
  renderPresets(root);
  renderForm(root);
  renderDefences(root);
  bind(root);
  await refreshPlan(root);
  await refreshRuns(root);

  // The Attack Lab's defence board can hand a configuration over.
  window.addEventListener('mobiguard:configure-run', (event) => {
    Object.assign(defences, event.detail.defences || {});
    if (event.detail.attack !== undefined) values.attack_number = event.detail.attack;
    if (event.detail.pct !== undefined) values.attack_percentage = event.detail.pct;
    renderForm(root);
    renderDefences(root);
    bind(root);
    refreshPlan(root);
  });
}

export function stopSimulation() {
  if (poller) clearInterval(poller);
  poller = null;
}

function seedDefaults() {
  for (const group of options.groups) {
    for (const param of group.params) values[param.name] = param.default;
  }
  for (const layer of options.defences) defences[layer.key] = layer.default;
}

// -- markup ------------------------------------------------------------------

function shell() {
  return `
  <div class="sim">
    <header class="sim-head">
      <div class="sim-title-group">
        <h2>Run Simulation</h2>
        <span class="sim-subtitle">Configure, launch, and monitor real-time ns-3 simulations</span>
      </div>
      <div id="sim-env"></div>
    </header>

    <div class="sim-body">
      <section class="panel sim-form">
        <div class="sim-section-header">
          <span class="step-num">1</span>
          <h3>Select Scenario</h3>
        </div>
        <div id="sim-presets" class="preset-grid"></div>

        <div class="sim-section-header" style="margin-top: 18px;">
          <span class="step-num">2</span>
          <h3>Simulation Settings</h3>
        </div>
        <div id="sim-groups"></div>

        <details class="sim-advanced-details">
          <summary class="advanced-summary">
            <span class="glyph">⚙️</span>
            <span>Advanced Parameters & Flags</span>
            <label class="inline advanced-toggle" onclick="event.stopPropagation()">
              <input type="checkbox" id="show-advanced"> Enable all
            </label>
          </summary>
          <div id="sim-advanced-groups" class="advanced-body"></div>
        </details>

        <div class="sim-section-header" style="margin-top: 18px;">
          <span class="step-num">3</span>
          <h3>Defense Layers</h3>
        </div>
        <div id="sim-defences" class="defence-compact"></div>
      </section>

      <section class="panel sim-launch">
        <div class="launch-hero">
          <button class="btn primary launch-btn" id="sim-start">
            <span class="launch-icon">▶</span> Launch Simulation
          </button>
          <div id="sim-estimate" class="estimate-pill"></div>
        </div>

        <div id="sim-warnings"></div>

        <details class="sim-command-details">
          <summary><span class="glyph">💻</span> View Generated CLI Command</summary>
          <pre class="command" id="sim-command">—</pre>
        </details>

        <div class="sim-section-header" style="margin-top: 18px;">
          <h3>Active Run & Status</h3>
        </div>
        <div id="sim-active"></div>

        <div class="sim-section-header" style="margin-top: 18px;">
          <h3>Recent Runs</h3>
        </div>
        <div id="sim-runs"></div>

        <details class="log-details">
          <summary><span class="glyph">📄</span> Terminal Output Log</summary>
          <pre class="log" id="sim-log"></pre>
        </details>
      </section>
    </div>
  </div>`;
}

function renderEnvironment(root) {
  const host = root.querySelector('#sim-env');
  const host_ = environment.host || {};
  if (!environment.ready) {
    host.innerHTML = `
      <div class="banner" data-status="critical">
        <span class="glyph">⚠</span>
        <div>
          <strong>Cannot launch simulations from this machine</strong>
          <ul class="problems">
            ${(environment.problems || []).map((p) => `<li>${p}</li>`).join('')}
          </ul>
          <span class="detail">
            The rest of the GUI works: it only reads files. Point
            <code>MOBIGUARD_NS3_DIR</code> at an ns-3 tree to enable this tab.
          </span>
        </div>
      </div>`;
    root.querySelector('#sim-start')?.setAttribute('disabled', 'disabled');
    return;
  }
  const heavy = host_.load1 > host_.cores * 0.75;
  host.innerHTML = `
    <div class="env-card">
      <div class="env-row"><span>Simulator</span><strong class="good">ready</strong></div>
      <div class="env-row">
        <span>Build profile</span>
        <strong class="${environment.build_profile === 'optimized' ? 'good' : 'warn'}">
          ${environment.build_profile}
        </strong>
      </div>
      <div class="env-row">
        <span>Host load</span>
        <strong class="${heavy ? 'warn' : ''}">${host_.load1} / ${host_.cores} cores</strong>
      </div>
      <div class="env-row"><span>Free memory</span><strong>${host_.free_gb} GB</strong></div>
      <div class="env-row">
        <span>Simulations running</span>
        <strong>${host_.simulations_on_host}</strong>
      </div>
      ${host_.simulations_on_host > 0
        ? `<p class="hint">Some are not this GUI's — this is a shared host.</p>`
        : ''}
    </div>`;
}

const PRESET_ICONS = {
  quick: '⚡',
  fast: '⚡',
  standard: '🛡️',
  eval: '🛡️',
  stress: '🚨',
  heavy: '🚨',
  full: '🔬',
  default: '🧪'
};

function renderPresets(root) {
  const container = root.querySelector('#sim-presets');
  if (!container) return;
  container.innerHTML = options.presets
    .map((preset) => {
      const iconKey = Object.keys(PRESET_ICONS).find((k) => preset.key.toLowerCase().includes(k)) || 'default';
      const icon = PRESET_ICONS[iconKey];
      return `
      <button class="preset-card" data-preset="${preset.key}">
        <div class="preset-head">
          <span class="preset-icon">${icon}</span>
          <strong class="preset-title">${preset.label}</strong>
        </div>
        <span class="preset-eta">⏱ ${fmt.duration(preset.est_wall_s)}</span>
      </button>`;
    })
    .join('');

  root.querySelectorAll('[data-preset]').forEach((button) => {
    button.addEventListener('click', () => {
      root.querySelectorAll('[data-preset]').forEach((b) => b.classList.remove('is-selected'));
      button.classList.add('is-selected');
      const preset = options.presets.find((p) => p.key === button.dataset.preset);
      if (preset) {
        Object.assign(values, preset.values);
        renderForm(root);
        renderDefences(root);
        bind(root);
        refreshPlan(root);
      }
    });
  });
}

function renderForm(root) {
  const showAdvanced = root.querySelector('#show-advanced')?.checked;
  const groupsContainer = root.querySelector('#sim-groups');
  const advancedContainer = root.querySelector('#sim-advanced-groups');
  
  if (groupsContainer) {
    groupsContainer.innerHTML = options.groups
      .filter((group) => group.key !== 'defence')
      .map((group) => {
        const params = group.params.filter((p) => !p.advanced);
        if (!params.length) return '';
        return `
        <fieldset class="param-group">
          <legend>${group.label}</legend>
          <div class="param-grid">${params.map(field).join('')}</div>
        </fieldset>`;
      })
      .join('');
  }

  if (advancedContainer) {
    advancedContainer.innerHTML = options.groups
      .filter((group) => group.key !== 'defence')
      .map((group) => {
        const params = group.params.filter((p) => p.advanced || showAdvanced);
        if (!params.length) return '';
        return `
        <fieldset class="param-group advanced-group">
          <legend>${group.label} (Advanced)</legend>
          <div class="param-grid">${params.map(field).join('')}</div>
        </fieldset>`;
      })
      .join('');
  }

  root.querySelectorAll('[data-param]').forEach((input) => {
    input.addEventListener('change', () => {
      const name = input.dataset.param;
      values[name] =
        input.type === 'checkbox'
          ? input.checked
          : input.dataset.kind === 'int'
            ? Number(input.value)
            : input.dataset.kind === 'float'
              ? Number(input.value)
              : input.dataset.kind === 'choice'
                ? maybeNumber(input.value)
                : input.value;
      refreshPlan(root);
    });
    if (input.type === 'range') {
      input.addEventListener('input', () => {
        const out = input.parentElement.querySelector('output');
        if (out) out.textContent = input.value;
      });
    }
  });
}

const maybeNumber = (raw) => (raw !== '' && !Number.isNaN(Number(raw)) ? Number(raw) : raw);

function field(param) {
  const value = values[param.name];
  const help = param.help.replace(/"/g, '&quot;');
  const label = `<span class="param-label" title="${help}">${param.label} <span class="info-glyph" title="${help}">ⓘ</span></span>`;

  if (param.kind === 'bool') {
    return `
      <label class="param param-bool">
        <label class="switch">
          <input type="checkbox" data-param="${param.name}" data-kind="bool" ${value ? 'checked' : ''}>
          <span class="track"></span>
        </label>
        ${label}
      </label>`;
  }
  if (param.kind === 'choice') {
    return `
      <label class="param">
        ${label}
        <select data-param="${param.name}" data-kind="choice">
          ${param.choices
            .map(
              (choice) =>
                `<option value="${choice.value}"${choice.value === value ? ' selected' : ''}>${choice.label}</option>`
            )
            .join('')}
        </select>
      </label>`;
  }
  if (param.kind === 'text') {
    return `
      <label class="param">
        ${label}
        <input type="text" data-param="${param.name}" data-kind="text"
               value="${value ?? ''}" placeholder="(auto)">
      </label>`;
  }
  const step = param.kind === 'int' ? 1 : 'any';
  if (param.min !== null && param.max !== null && param.max - param.min <= 1000) {
    return `
      <label class="param param-range">
        <div class="range-head">${label} <output>${value}</output></div>
        <input type="range" data-param="${param.name}" data-kind="${param.kind}"
               min="${param.min}" max="${param.max}" step="${step}" value="${value}">
      </label>`;
  }
  return `
    <label class="param">
      ${label}
      <input type="number" data-param="${param.name}" data-kind="${param.kind}"
             value="${value}" step="${step}"
             ${param.min !== null ? `min="${param.min}"` : ''}
             ${param.max !== null ? `max="${param.max}"` : ''}>
    </label>`;
}

function renderDefences(root) {
  const container = root.querySelector('#sim-defences');
  if (!container) return;
  container.innerHTML = options.defences
    .map(
      (layer) => `
      <div class="defence-card-row" title="${layer.blurb.replace(/"/g, '&quot;')}">
        <label class="switch">
          <input type="checkbox" data-defence="${layer.key}" ${defences[layer.key] ? 'checked' : ''}>
          <span class="track"></span>
        </label>
        <div class="defence-info">
          <strong>${layer.label}</strong>
          <span class="ablation">${layer.ablation}</span>
        </div>
      </div>`
    )
    .join('');

  root.querySelectorAll('[data-defence]').forEach((input) => {
    input.addEventListener('change', () => {
      defences[input.dataset.defence] = input.checked;
      refreshPlan(root);
    });
  });
}

function bind(root) {
  root.querySelector('#show-advanced')?.addEventListener('change', () => {
    renderForm(root);
  });
  root.querySelector('#sim-start')?.addEventListener('click', () => launch(root));
}

// -- plan and launch ---------------------------------------------------------

async function refreshPlan(root) {
  const commandHost = root.querySelector('#sim-command');
  const warnHost = root.querySelector('#sim-warnings');
  const estHost = root.querySelector('#sim-estimate');
  let plan;
  try {
    plan = await api.simPlan(values, defences);
  } catch (error) {
    if (commandHost) commandHost.textContent = '—';
    if (warnHost) warnHost.innerHTML = `<p class="bad">${error.message}</p>`;
    return;
  }
  if (commandHost) commandHost.textContent = plan.argv.join(' \\\n  ');
  if (estHost) {
    estHost.innerHTML = `<span class="est-badge">⏱ Est: ${fmt.duration(plan.est_wall_s)}</span>`;
  }
  if (warnHost) {
    warnHost.innerHTML = (plan.warnings || [])
      .map((w) => `<p class="warn-line">⚠ ${w}</p>`)
      .join('');
  }
}

async function launch(root) {
  const button = root.querySelector('#sim-start');
  button.disabled = true;
  button.textContent = 'Starting…';
  try {
    const record = await api.simStart(values, defences);
    activeUid = record.run_id;
    logCursor = 0;
    root.querySelector('#sim-log').textContent = '';
    startPolling(root);
  } catch (error) {
    root.querySelector('#sim-warnings').innerHTML = `<p class="bad">${error.message}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = '▶ Launch simulation';
  }
}

function startPolling(root) {
  if (poller) clearInterval(poller);
  poller = setInterval(() => tick(root), 1500);
  tick(root);
}

async function tick(root) {
  if (!activeUid) return;
  let record;
  try {
    record = await api.simStatus(activeUid);
  } catch {
    return; // transient; the next tick retries
  }
  renderActive(root, record);
  await pumpLog(root);
  if (['finished', 'failed', 'cancelled'].includes(record.state)) {
    clearInterval(poller);
    poller = null;
    await refreshRuns(root);
    // The new run's CSVs are on disk now; let the rest of the GUI see them.
    try {
      await api.refresh();
    } catch {
      /* the banner will still be right on the next manual refresh */
    }
  }
}

async function pumpLog(root) {
  try {
    const { lines, cursor } = await api.simLog(activeUid, logCursor);
    if (lines.length) {
      const host = root.querySelector('#sim-log');
      host.textContent += lines.join('\n') + '\n';
      // Only autoscroll when already at the bottom, so reading back through
      // the log is not yanked away every 1.5 s.
      const atBottom = host.scrollHeight - host.scrollTop - host.clientHeight < 40;
      if (atBottom) host.scrollTop = host.scrollHeight;
      logCursor = cursor;
    }
  } catch {
    /* ignore; next tick */
  }
}

function renderActive(root, record) {
  const host = root.querySelector('#sim-active');
  const pct = Math.round(record.progress * 100);
  const stateClass =
    record.state === 'failed' ? 'bad'
      : record.state === 'finished' ? 'good'
        : record.state === 'cancelled' ? 'warn' : '';

  host.innerHTML = `
    <div class="active-run">
      <div class="active-head">
        <strong class="${stateClass}">${record.state}</strong>
        <code>${record.metrics_file}</code>
        ${record.state === 'running'
          ? `<button class="btn ghost small" id="sim-stop">Stop</button>`
          : ''}
      </div>
      <div class="progress"><div class="bar" style="width:${pct}%"></div></div>
      <div class="active-stats">
        <span>${record.cycles_done} / ${fmt.num(record.sim_time, 0)} cycles</span>
        <span>${pct}%</span>
        <span>elapsed ${fmt.duration(record.elapsed_s)}</span>
        ${record.eta_s !== null && record.state === 'running'
          ? `<span>eta ${fmt.duration(record.eta_s)}</span>` : ''}
        ${record.attackers.length
          ? `<span>${record.attackers.length} attackers declared</span>` : ''}
      </div>
      ${record.error ? `<p class="bad">${record.error}</p>` : ''}
      ${record.notable.length
        ? `<div class="event-rail">
             ${record.notable.slice(-6).map((n) => `<div class="event">${escapeHtml(n)}</div>`).join('')}
           </div>`
        : ''}
    </div>`;

  root.querySelector('#sim-stop')?.addEventListener('click', async () => {
    try {
      await api.simStop(activeUid);
    } catch {
      /* the poll will show the real state */
    }
  });
}

async function refreshRuns(root) {
  let payload;
  try {
    payload = await api.simRuns();
  } catch {
    return;
  }
  const host = root.querySelector('#sim-runs');
  if (!payload.runs.length) {
    host.innerHTML = '<p class="empty">No runs launched from this GUI yet.</p>';
    return;
  }
  host.innerHTML = `
    <table class="runs">
      <thead><tr><th>State</th><th>Configuration</th><th>Cycles</th><th>Elapsed</th></tr></thead>
      <tbody>
        ${payload.runs
          .slice(0, 8)
          .map(
            (r) => `
          <tr data-uid="${r.run_id}" class="${r.run_id === activeUid ? 'is-active' : ''}">
            <td><span class="state ${r.state}">${r.state}</span></td>
            <td><code>${r.metrics_file}</code></td>
            <td>${r.cycles_done}</td>
            <td>${fmt.duration(r.elapsed_s)}</td>
          </tr>`
          )
          .join('')}
      </tbody>
    </table>`;
  host.querySelectorAll('tr[data-uid]').forEach((row) => {
    row.addEventListener('click', () => {
      activeUid = row.dataset.uid;
      logCursor = 0;
      root.querySelector('#sim-log').textContent = '';
      startPolling(root);
    });
  });
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
