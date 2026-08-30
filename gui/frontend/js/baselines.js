/**
 * Baselines & Ablations: the offline summary half of the brief.
 *
 * Two questions, answered separately because they are answered by different
 * evidence: how MOBIGUARD compares to prior work (B1 TAP, B2 SFTO, B3 eFADE),
 * and how much each of its own layers contributes (the AB* ablation runs).
 *
 * The design decision worth defending: there is no single "MOBIGUARD vs. the
 * state of the art" bar chart across all eight variants, because no baseline
 * covers all eight. TAP is comparable on Attack 2 only, eFADE is scoped to the
 * four Hidden Forwarding variants by construction, and SFTO's pipeline covers
 * the TCAM pair. Drawing one chart across eight would imply coverage that does
 * not exist -- the exact question a panel is best placed to catch. So each
 * comparator gets its own block, stating what it covers and on what basis it is
 * comparable at all.
 *
 * SFTO in particular is shown with its sample size attached everywhere. Its
 * reported MCC is 1.000, which reads as "beats everything" until you see it was
 * over 22 samples.
 */

import { api } from './api.js';
import { fmt, formatValue } from './format.js';

let panel = null;

export async function initBaselines(root) {
  root.innerHTML = '<p class="loading"><span class="spinner"></span> Reading baselines and ablations…</p>';
  try {
    panel = await api.baselinesPanel();
  } catch (error) {
    root.innerHTML = `<div class="panel"><p class="bad">${error.message}</p></div>`;
    return;
  }
  root.innerHTML = render();
  bind(root);
}

function render() {
  return `
  <div class="baselines">
    <header class="lab-head">
      <div>
        <h2>Baselines &amp; Ablations</h2>
        <p class="lede">
          How MOBIGUARD compares to prior work, and what each of its layers is
          worth. Two questions, two kinds of evidence.
        </p>
      </div>
    </header>

    ${panel.notes.length
      ? `<section class="panel notes-panel">
           <h3>Read this first</h3>
           ${panel.notes.map((n) => `<p class="note">${n}</p>`).join('')}
         </section>`
      : ''}

    <section class="panel">
      <h3>Coverage</h3>
      <p class="hint">
        Which comparator can speak to which attack variant. Blank means the
        baseline does not address that variant at all — not that it scored zero.
      </p>
      ${coverageMatrix()}
    </section>

    <section class="panel">
      <h3>Head to head</h3>
      ${comparisonBlocks()}
    </section>

    <section class="panel">
      <h3>eFADE (B3) detail</h3>
      ${fadeBlock()}
    </section>

    <section class="panel">
      <h3>Ablations</h3>
      <p class="hint">
        Each AB family removes one layer. Arms (A/B/C) are variations within the
        same ablation, not separate ones. Compared against the full-stack run
        for the same variant and attacker percentage where one exists.
      </p>
      <div class="row" id="ablation-filter"></div>
      <div id="ablation-table"></div>
    </section>
  </div>`;
}

function coverageMatrix() {
  const variants = [1, 2, 3, 4, 5, 6, 7, 8];
  const haveData = (key) => {
    if (key === 'B1') return new Set(panel.tap.map((t) => t.attack_id));
    if (key === 'B3') return new Set(panel.fade.map((f) => f.attack_id));
    return new Set(panel.sfto.filter((s) => s.attack_id).map((s) => s.attack_id));
  };
  return `
    <div class="table-scroll">
      <table class="grid-table">
        <thead>
          <tr><th>Baseline</th>${variants.map((v) => `<th>A${v}</th>`).join('')}</tr>
        </thead>
        <tbody>
          ${panel.baselines
            .map((baseline) => {
              const collected = haveData(baseline.key);
              return `
              <tr>
                <th>${baseline.key} · ${baseline.name}</th>
                ${variants
                  .map((v) => {
                    if (!baseline.covers.includes(v)) {
                      return '<td class="cov-na" title="not addressed by this baseline">—</td>';
                    }
                    return collected.has(v)
                      ? '<td class="cov-have" title="data collected">●</td>'
                      : '<td class="cov-missing" title="in scope, but no data collected">○</td>';
                  })
                  .join('')}
              </tr>`;
            })
            .join('')}
        </tbody>
      </table>
    </div>
    <p class="quiet">
      ● data collected · ○ in scope but not yet run · — outside this baseline's scope
    </p>`;
}

function comparisonBlocks() {
  if (!panel.comparisons.length) {
    return '<p class="empty">No baseline runs to compare against yet.</p>';
  }
  return panel.comparisons
    .map((comparison) => {
      const ref = comparison.mobiguard;
      return `
      <div class="compare-block">
        <div class="compare-head">
          <strong>${comparison.baseline} · ${comparison.name}</strong>
          <span class="quiet">Attack ${comparison.attack_id}${
            comparison.attack_percentage !== null
              ? ` at ${comparison.attack_percentage}%`
              : ''
          }</span>
          ${comparison.comparable
            ? '<span class="tag benign">like for like</span>'
            : '<span class="tag unknown">not directly comparable</span>'}
        </div>
        <p class="hint">${comparison.basis}</p>
        <div class="table-scroll">
          <table class="grid-table">
            <thead>
              <tr>
                <th></th>
                ${panel.compare_columns.map((c) => `<th>${c}</th>`).join('')}
                <th>TP</th><th>FP</th><th>TN</th><th>FN</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th>${comparison.name}${comparison.n ? ` <span class="quiet">(n=${comparison.n})</span>` : ''}</th>
                ${metricCells(comparison.baseline_metrics)}
                ${confusionCells(comparison.baseline_confusion)}
              </tr>
              <tr class="is-reference">
                <th>MOBIGUARD${ref ? '' : ' <span class="quiet">(no matching run)</span>'}</th>
                ${ref ? metricCells(ref.metrics) : blankCells(panel.compare_columns.length)}
                ${ref ? confusionCells(ref.confusion) : blankCells(4)}
              </tr>
            </tbody>
          </table>
        </div>
      </div>`;
    })
    .join('');
}

const UNITS = { avg_MCC: 'fraction', avg_DR: 'percent', avg_FPR: 'percent' };

function metricCells(metrics) {
  return panel.compare_columns
    .map((column) => {
      const caveat = panel.caveats[column];
      return `<td class="num"${caveat ? ` title="${caveat.replace(/"/g, '&quot;')}"` : ''}>
        ${formatValue(metrics?.[column] ?? null, UNITS[column] || 'count')}
        ${caveat ? '<span class="caveat-mark">◦</span>' : ''}
      </td>`;
    })
    .join('');
}

function confusionCells(confusion) {
  return ['TP', 'FP', 'TN', 'FN']
    .map((k) => `<td class="num">${fmt.int(confusion?.[k])}</td>`)
    .join('');
}

const blankCells = (n) => '<td class="num">—</td>'.repeat(n);

function fadeBlock() {
  if (!panel.fade.length) {
    return `
      <p class="empty">No eFADE results with data rows.</p>
      <p class="hint">
        ${fmt.int(panel.fade_empty_files)} <code>fade_results_*.csv</code> files
        exist but are header-only. eFADE's detection loop only arms when both
        LRAD engines are off, so a run with the full MOBIGUARD stack writes the
        header and nothing else. Collect it with
        <code>python -m scripts.gui_demo_runs --batch baselines</code>.
      </p>`;
  }
  return `
    <div class="table-scroll">
      <table class="grid-table">
        <thead>
          <tr>
            <th>Attack</th><th>%</th><th>Flows</th><th>Detected</th>
            <th>Detection rate</th><th>Localised</th><th>Mean detection time</th>
          </tr>
        </thead>
        <tbody>
          ${panel.fade
            .map(
              (f) => `
            <tr>
              <td>A${f.attack_id}</td>
              <td class="num">${f.attack_percentage}</td>
              <td class="num">${f.flows}</td>
              <td class="num">${f.detected}</td>
              <td class="num">${f.detection_rate === null ? '—' : fmt.pct(f.detection_rate * 100)}</td>
              <td class="num">${f.localised}</td>
              <td class="num">${f.mean_detection_time_s === null ? '—' : fmt.num(f.mean_detection_time_s, 2) + ' s'}</td>
            </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
    <p class="quiet">
      "Localised" counts flows where eFADE named the duplicating node, not merely
      that something was anomalous — its headline claim over plain anomaly
      detection, so it is counted separately from detection.
    </p>`;
}

// -- ablations ---------------------------------------------------------------

let activeFamily = null;

function bind(root) {
  renderAblationFilter(root);
  renderAblationTable(root);
}

function renderAblationFilter(root) {
  const host = root.querySelector('#ablation-filter');
  if (!host) return;
  host.innerHTML =
    `<button class="chip${activeFamily === null ? ' is-active' : ''}" data-family="">All</button>` +
    panel.ablation_families
      .map((family) => {
        const label = (panel.ablations.find((a) => a.ablation === family) || {}).label || family;
        return `<button class="chip${activeFamily === family ? ' is-active' : ''}"
                        data-family="${family}" title="${label}">${family}</button>`;
      })
      .join('');
  host.querySelectorAll('[data-family]').forEach((button) => {
    button.addEventListener('click', () => {
      activeFamily = button.dataset.family || null;
      renderAblationFilter(root);
      renderAblationTable(root);
    });
  });
}

function renderAblationTable(root) {
  const host = root.querySelector('#ablation-table');
  if (!host) return;
  const rows = panel.ablations.filter(
    (a) => activeFamily === null || a.ablation === activeFamily
  );
  if (!rows.length) {
    host.innerHTML = '<p class="empty">No ablation runs match.</p>';
    return;
  }
  rows.sort(
    (a, b) =>
      a.ablation.localeCompare(b.ablation, undefined, { numeric: true }) ||
      a.arm.localeCompare(b.arm) ||
      a.attack_id - b.attack_id ||
      a.attack_percentage - b.attack_percentage
  );
  host.innerHTML = `
    <div class="table-scroll">
      <table class="grid-table">
        <thead>
          <tr>
            <th>Ablation</th><th>Arm</th><th>Removes</th><th>Attack</th><th>%</th>
            ${panel.compare_columns.map((c) => `<th>${c}</th>`).join('')}
            <th>TP</th><th>FP</th><th>TN</th><th>FN</th>
          </tr>
        </thead>
        <tbody>
          ${rows
            .map(
              (a) => `
            <tr>
              <td><span class="ablation">${a.ablation}</span></td>
              <td>${a.arm}</td>
              <td>${a.label}</td>
              <td>A${a.attack_id}</td>
              <td class="num">${a.attack_percentage}</td>
              ${metricCells(a.metrics)}
              ${confusionCells(a.confusion)}
            </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
    <p class="quiet">
      ${rows.length} run(s). Columns marked ◦ are the simulator's inline
      per-node diagnostics, not the thesis's per-RSU windowed M1 — hover for the
      full caveat.
    </p>`;
}
