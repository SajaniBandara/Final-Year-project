/**
 * Application bootstrap: theme, tabs, health banner, catalog load.
 *
 * The health banner is not decoration. results_routing/ is copied from the HPC
 * by hand, and a month-old copy renders exactly like a fresh one, so the age of
 * the data is stated on screen rather than left to be assumed.
 */

import { api, ApiError } from './api.js';
import { initLive, stopLive } from './live.js';
import { initCrypto } from './crypto.js';
import { initTcam, stopTcam } from './tcam.js';
import { initLstm } from './lstm.js';
import { initOffline } from './offline.js';
import { initLab, stopLab } from './lab.js';
import { initSimulation, stopSimulation } from './simulation.js';
import { initBaselines } from './baselines.js';

const THEME_KEY = 'mobiguard-gui-theme';

function initTheme() {
  const button = document.querySelector('#theme-toggle');
  let stored = null;
  try {
    stored = localStorage.getItem(THEME_KEY);
  } catch {
    /* private window or blocked storage: fall back to the OS setting */
  }
  if (stored === 'light' || stored === 'dark') {
    document.documentElement.dataset.theme = stored;
  }

  button.addEventListener('click', () => {
    const current =
      document.documentElement.dataset.theme ||
      (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* nothing to do: the toggle still works for this session */
    }
  });
}

function renderHealth(health) {
  const host = document.querySelector('#health-banner');
  const stale = health.stale;
  host.innerHTML = `
    <div class="banner" data-status="${stale ? 'warning' : 'good'}">
      <span class="glyph" aria-hidden="true">${stale ? '⚠' : '✓'}</span>
      <div>
        <strong>${
          stale
            ? `Results copy is ${health.age_days} days old`
            : `Results copy is current (${health.age_days ?? 0} days old)`
        }</strong>
        <span class="detail">
          ${health.run_count} runs indexed from <code>${health.results_dir}</code>.
          ${
            stale
              ? 'These CSVs are copied from the HPC by hand — charts may not reflect the current simulator.'
              : ''
          }
        </span>
      </div>
    </div>`;
}

function renderFatal(message) {
  document.querySelector('#health-banner').innerHTML = `
    <div class="banner" data-status="critical">
      <span class="glyph" aria-hidden="true">✗</span>
      <div><strong>Cannot load results</strong><span class="detail">${message}</span></div>
    </div>`;
}

function initTabs(panels) {
  const buttons = [...document.querySelectorAll('.tab')];
  const select = (name) => {
    for (const button of buttons) {
      button.setAttribute('aria-selected', String(button.dataset.tab === name));
    }
    for (const [key, node] of Object.entries(panels)) {
      node.hidden = key !== name;
    }
    // Leaving the Live tab closes the socket: a stream left running in a
    // hidden panel keeps the server busy and confuses the next connection.
    if (name !== 'live') stopLive();
    // Same reason: a grid animating in a hidden panel is wasted work.
    if (name !== 'tcam') stopTcam();
    // The map's playback timer and the run poller are the same class of
    // problem: work continuing behind a hidden panel.
    if (name !== 'lab') stopLab();
    if (name !== 'simulation') stopSimulation();
  };
  for (const button of buttons) {
    button.addEventListener('click', () => select(button.dataset.tab));
  }
  select('lab');
}

async function main() {
  initTheme();

  const panels = {
    lab: document.querySelector('#panel-lab'),
    simulation: document.querySelector('#panel-simulation'),
    offline: document.querySelector('#panel-offline'),
    baselines: document.querySelector('#panel-baselines'),
    live: document.querySelector('#panel-live'),
    lstm: document.querySelector('#panel-lstm'),
    crypto: document.querySelector('#panel-crypto'),
    tcam: document.querySelector('#panel-tcam'),
  };
  initTabs(panels);

  document.querySelector('#refresh').addEventListener('click', async (event) => {
    event.target.disabled = true;
    try {
      renderHealth(await api.refresh());
      const catalog = await api.catalog();
      await initOffline(panels.offline, catalog);
    } catch (error) {
      renderFatal(error.message);
    } finally {
      event.target.disabled = false;
    }
  });

  try {
    const [health, catalog] = await Promise.all([api.health(), api.catalog()]);
    renderHealth(health);

    if (!catalog.runs.length) {
      panels.offline.innerHTML =
        '<div class="card"><p class="empty">No metrics CSVs found. Copy them from the HPC into results_routing/.</p></div>';
    } else {
      await initOffline(panels.offline, catalog);
      initLive(panels.live, catalog);
    }
    // Attack Lab always initialises — it falls back to the synthetic demo
    // scene when there are no real runs, so it is never left blank.
    await initLab(panels.lab);
    // Independent of the results directory: the run form comes from the
    // parameter registry, and the tab explains itself when no simulator is
    // reachable rather than being hidden.
    await initSimulation(panels.simulation);
    await initBaselines(panels.baselines);
    await initLstm(panels.lstm);
    await initTcam(panels.tcam);
    await initCrypto(panels.crypto);
  } catch (error) {
    const hint =
      error instanceof ApiError && error.status === 503
        ? ' Copy the CSVs from the HPC, or set MOBIGUARD_RESULTS_DIR.'
        : '';
    renderFatal(error.message + hint);
  }
}

main();
