/**
 * Federated LSTM tab.
 *
 * Reads the committed lstm_pipeline JSONs, which are git-tracked and current --
 * so this is the one tab unaffected by the staleness of the CSV copy.
 *
 * Two presentation rules the backend hands down and this module must not
 * soften:
 *
 *   - An MCC whose denominator is zero is **undefined**, not zero. A6
 *     DP-ActiveHF stores 0.0 beside a detection rate of 86%, because its
 *     evaluation set contains no true negatives. It is drawn as a gap with the
 *     reason, never as a zero-height bar.
 *   - A3/A4 are caught by the S3/S4 rules, not by the model. They are badged,
 *     so an "LSTM detection quality" panel never claims credit for them.
 */

import { api } from './api.js';
import { renderBarChart, renderStackedBar, seriesColor, sequentialColor } from './charts.js';
import { formatValue } from './format.js';

const pct = (v) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(2)}%`);
const frac = (v) => (v === null || v === undefined ? '—' : v.toFixed(4));

export async function initLstm(root) {
  root.innerHTML = '<div class="card"><p class="empty">Loading federated LSTM results…</p></div>';

  let panel;
  try {
    panel = await api.lstmPanel();
  } catch (error) {
    root.innerHTML = `<div class="card"><p class="empty">${error.message}</p></div>`;
    return;
  }

  if (!panel.available) {
    root.innerHTML = `<div class="card"><p class="empty">
      No pipeline results found in ${panel.source_dir}. Run lstm_pipeline/src/pipeline.py.
    </p></div>`;
    return;
  }

  root.innerHTML = `
    <div class="banner" data-status="good">
      <span class="glyph" aria-hidden="true">✓</span>
      <div><strong>Committed pipeline results</strong>
        <span class="detail">Read from <code>lstm_pipeline/*.json</code>, which are tracked in git —
        independent of the hand-copied <code>results_routing/</code>, so these numbers are current.</span>
      </div>
    </div>

    <div class="card" id="poison-hero"></div>
    <div class="card" id="quality"></div>
    <div class="card" id="federation"></div>
    <div class="card" id="poison-grid"></div>
    <div class="card" id="ablations"></div>
    <div class="card" id="mobility"></div>
  `;

  renderPoisonHero(root.querySelector('#poison-hero'), panel.poisoning);
  renderQuality(root.querySelector('#quality'), panel.evaluation);
  renderFederation(root.querySelector('#federation'), panel.federation);
  renderPoisonGrid(root.querySelector('#poison-grid'), panel.poisoning);
  renderAblations(root.querySelector('#ablations'), panel.ablations);
  renderMobility(root.querySelector('#mobility'), panel.mobility);
}

/** M8 headline: the one number this contribution leads with. */
function renderPoisonHero(host, poisoning) {
  if (!poisoning || !poisoning.selected) {
    host.innerHTML = '<p class="empty">No poisoning sweep results.</p>';
    return;
  }
  const s = poisoning.selected;
  const held = s.delta_poison === 0;
  host.innerHTML = `
    <header><div><h2>Byzantine robustness (M8)</h2>
      <span class="sub">BRFA-v2 under ${poisoning.poison_mode} poisoning,
      ${pct(poisoning.malicious_fraction)} of RSUs malicious</span></div></header>
    <div style="display:flex;gap:28px;flex-wrap:wrap;align-items:flex-end">
      <div>
        <div class="hero-figure" style="color:${held ? 'var(--status-good)' : 'var(--status-critical)'}">
          ${s.delta_poison.toFixed(4)}
        </div>
        <div class="sub">MCC lost to poisoning</div>
      </div>
      <div class="tiles" style="flex:1;min-width:280px">
        <div class="tile"><div class="label">MCC clean</div><div class="value">${frac(s.mcc_clean)}</div></div>
        <div class="tile"><div class="label">MCC poisoned</div><div class="value">${frac(s.mcc_poisoned)}</div></div>
        <div class="tile"><div class="label">Updates accepted</div>
          <div class="value">${s.n_accepted_poisoned}<span class="unit"> / ${s.n_total}</span></div></div>
      </div>
    </div>
    <p class="sub" style="margin-top:12px">${poisoning.note}</p>
  `;
}

function renderQuality(host, evaluation) {
  const variants = evaluation.variants.filter((v) => !v.is_overall);
  const overall = evaluation.variants.find((v) => v.is_overall);

  host.innerHTML = `
    <header><div><h2>Detection quality by variant</h2>
      <span class="sub">Window-level, W=10 s / stride 5 s</span></div></header>
    <div id="quality-chart"></div>
    <div id="quality-table" style="margin-top:16px"></div>
    <div class="caveat" style="margin-top:14px"><span aria-hidden="true">⚠</span><div>
      ${evaluation.note}
    </div></div>
  `;

  // Detection rate is defined for every variant, so it is the honest bar chart.
  // MCC is not, which is exactly why it lives in the table with its reason.
  renderBarChart(host.querySelector('#quality-chart'), {
    bars: variants.map((v) => ({ label: v.name.split(' ')[0], value: v.dr })),
    unit: 'fraction',
    yLabel: 'Detection rate',
  });

  const rows = evaluation.variants
    .map((v) => {
      const mccCell = v.mcc_defined
        ? frac(v.mcc)
        : `<span class="undefined" title="${v.mcc_note}">undefined</span>`;
      const badge =
        v.source === 'rule_based'
          ? '<span class="badge badge-rule">S3/S4 rule</span>'
          : '<span class="badge">LSTM</span>';
      const ref = v.reference_only
        ? `<div class="sub">LSTM classifier, reference only: MCC ${frac(v.reference_only.M1_MCC)}</div>`
        : '';
      return `<tr${v.is_overall ? ' class="row-total"' : ''}>
        <td>${v.name}${ref}</td>
        <td>${badge}</td>
        <td>${mccCell}</td>
        <td>${frac(v.dr)}</td>
        <td>${frac(v.fpr)}</td>
        <td>${v.tp ?? '—'}</td><td>${v.tn ?? '—'}</td>
        <td>${v.fp ?? '—'}</td><td>${v.fn ?? '—'}</td>
      </tr>`;
    })
    .join('');

  host.querySelector('#quality-table').innerHTML = `
    <div class="table-scroll">
      <table class="data">
        <thead><tr><th>Variant</th><th>Detector</th><th>MCC</th><th>DR</th><th>FPR</th>
          <th>TP</th><th>TN</th><th>FP</th><th>FN</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="sub" style="margin-top:8px">
      “undefined” means MCC’s denominator has a zero factor — hover for the reason.
      It is not a score of zero: A6 detects ${pct(
        (variants.find((v) => v.name.startsWith('A6')) || {}).dr
      )} of its attack windows.
    </p>`;
}

function renderFederation(host, federation) {
  if (!federation) {
    host.innerHTML = '<p class="empty">No federated round summary.</p>';
    return;
  }
  const colors = [
    'var(--series-3)', 'var(--series-2)', 'var(--series-4)', 'var(--series-8)',
  ];
  host.innerHTML = `
    <header><div><h2>Federated aggregation</h2>
      <span class="sub">Which RSU updates survived BRFA-v2 screening</span></div></header>
    <div class="tiles" style="margin-bottom:14px">
      <div class="tile"><div class="label">RSUs total</div><div class="value">${federation.n_total}</div></div>
      <div class="tile"><div class="label">Accepted</div><div class="value">${federation.accepted}</div></div>
      <div class="tile"><div class="label">Byzantine bound f</div><div class="value">${federation.byzantine_bound_f}</div></div>
      <div class="tile"><div class="label">Rounds</div><div class="value">${federation.selected_rounds}</div></div>
      <div class="tile"><div class="label">Global θ</div>
        <div class="value">${federation.global_theta ? federation.global_theta.toFixed(4) : '—'}</div></div>
    </div>
    <div id="fed-stack"></div>
  `;
  renderStackedBar(host.querySelector('#fed-stack'), {
    segments: federation.breakdown.map((b, i) => ({ ...b, color: colors[i] })),
    total: federation.n_total,
  });
}

function renderPoisonGrid(host, poisoning) {
  if (!poisoning || !poisoning.grid.length) {
    host.innerHTML = '<p class="empty">No poisoning sweep grid.</p>';
    return;
  }
  const sel = poisoning.selected || {};
  const rows = poisoning.grid
    .map((g) => {
      const chosen = g.gamma === sel.gamma && g.t_min === sel.t_min;
      return `<tr${chosen ? ' class="row-selected"' : ''}>
        <td>${g.gamma}${chosen ? ' <span class="badge">selected</span>' : ''}</td>
        <td>${g.t_min}</td>
        <td>${frac(g.mcc_clean)}</td>
        <td>${frac(g.mcc_poisoned)}</td>
        <td>${frac(g.delta_poison)}</td>
        <td>${g.n_accepted_poisoned} / ${g.n_total}</td>
      </tr>`;
    })
    .join('');
  host.innerHTML = `
    <header><div><h2>BRFA-v2 parameter sweep</h2>
      <span class="sub">Krum threshold γ and trust floor t<sub>min</sub></span></div></header>
    <div class="table-scroll">
      <table class="data">
        <thead><tr><th>γ</th><th>t_min</th><th>MCC clean</th><th>MCC poisoned</th>
          <th>Δ poison</th><th>Accepted</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderAblations(host, ablations) {
  const blocks = [
    ['ab2', 'AB2 — centralised vs federated'],
    ['ab3', 'AB3 — feature ablation'],
  ]
    .filter(([key]) => ablations[key])
    .map(([key, title]) => {
      const a = ablations[key];
      const rows = a.rows
        .map((r) => {
          const delta =
            r.a.mcc !== null && r.b.mcc !== null && r.a.mcc !== undefined && r.b.mcc !== undefined
              ? (r.b.mcc - r.a.mcc).toFixed(4)
              : '—';
          return `<tr><td>${r.variant}</td>
            <td>${frac(r.a.mcc)}</td><td>${frac(r.b.mcc)}</td><td>${delta}</td></tr>`;
        })
        .join('');
      return `
        <h3 style="margin-top:14px">${title}</h3>
        <div class="table-scroll">
          <table class="data">
            <thead><tr><th>Variant</th><th>${a.arm_a} MCC</th><th>${a.arm_b} MCC</th><th>Δ</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    })
    .join('');

  host.innerHTML = `
    <header><div><h2>Ablations</h2>
      <span class="sub">Same measure under two configurations</span></div></header>
    ${blocks || '<p class="empty">No ablation results.</p>'}`;
}

function renderMobility(host, mobility) {
  if (!mobility) {
    host.innerHTML = '<p class="empty">No mobility-stratified results.</p>';
    return;
  }
  const byKey = new Map(mobility.cells.map((c) => [`${c.variant}||${c.bin}`, c]));

  const header = mobility.bins.map((b) => `<th>${b.replace(/rho=|v_bar=/g, '')}</th>`).join('');
  const rows = mobility.variants
    .map((variant) => {
      const cells = mobility.bins
        .map((bin) => {
          const cell = byKey.get(`${variant}||${bin}`);
          if (!cell || cell.mcc === null || cell.mcc === undefined) {
            // Absent mobility combination -- a gap, never a zero.
            return '<td class="cell-empty" title="not present in the trace">—</td>';
          }
          // Sequential single hue: magnitude, so darker = higher MCC.
          const bg = sequentialColor(cell.mcc);
          const ink = cell.mcc > 0.55 ? '#ffffff' : '#0b0b0b';
          return `<td class="cell-heat" style="background:${bg};color:${ink}"
                     title="${variant} · ${bin} · n=${cell.n}">${cell.mcc.toFixed(3)}</td>`;
        })
        .join('');
      return `<tr><td>${variant}</td>${cells}</tr>`;
    })
    .join('');

  host.innerHTML = `
    <header><div><h2>MCC by mobility regime</h2>
      <span class="sub">Density ρ × mean speed v̄ — sequential scale, darker is higher</span></div></header>
    <div class="table-scroll">
      <table class="data heatmap">
        <thead><tr><th>Variant</th>${header}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="sub" style="margin-top:8px">${mobility.note}</p>`;
}
