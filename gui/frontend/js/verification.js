/**
 * Verification & Evidence tab.
 *
 * Answers the question no metric chart can: does the code implement the thesis?
 * scripts/audit_equations.py walks every eq:/alg: label in docs/main.tex and
 * either points at the implementing symbol, confirms the parameter plumbing, or
 * declares it paper-only -- plus a coverage self-check that fails when the paper
 * grows a label the audit table has not caught up with.
 *
 * The audit currently FAILS, and this tab leads with that. A verification panel
 * that showed a pass count and hid three failures would be worse than no panel:
 * it would be the one screen in the demo that actively misleads.
 */

import { api } from './api.js';

const STATUS_GLYPH = { PASS: '✓', FAIL: '✗', INFO: 'i' };

export async function initVerification(root) {
  root.innerHTML = '<div class="card"><p class="empty">Loading verification evidence…</p></div>';

  let panel;
  try {
    panel = await api.verification();
  } catch (error) {
    root.innerHTML = `<div class="card"><p class="empty">${error.message}</p></div>`;
    return;
  }
  render(root, panel);
}

function render(root, panel) {
  const audit = panel.audit;

  root.innerHTML = `
    <div id="verify-headline"></div>
    <div class="card" id="verify-audit"></div>
    <div class="card" id="verify-functional"></div>
  `;

  renderHeadline(root.querySelector('#verify-headline'), audit);
  renderAudit(root.querySelector('#verify-audit'), audit);
  renderFunctional(root.querySelector('#verify-functional'), panel.functional);

  const button = root.querySelector('#rerun-audit');
  if (button) {
    button.addEventListener('click', async () => {
      button.disabled = true;
      button.textContent = 'Running audit… (~15 s)';
      try {
        const fresh = await api.rerunAudit();
        render(root, { ...panel, audit: fresh });
      } catch (error) {
        button.textContent = 'Re-run failed';
        button.title = error.message;
        button.disabled = false;
      }
    });
  }
}

function renderHeadline(host, audit) {
  if (!audit.available) {
    host.innerHTML = `
      <div class="banner" data-status="warning">
        <span class="glyph" aria-hidden="true">⚠</span>
        <div><strong>Equation audit has not been generated</strong>
          <span class="detail">Run <code>${audit.command}</code></span></div>
      </div>`;
    return;
  }

  const counts = audit.counts_reported || audit.counts_parsed;
  const failed = counts.FAIL > 0;

  host.innerHTML = `
    <div class="banner" data-status="${failed ? 'critical' : 'good'}">
      <span class="glyph" aria-hidden="true">${failed ? '✗' : '✓'}</span>
      <div>
        <strong>${
          failed
            ? `Equation audit FAILS — ${counts.FAIL} check${counts.FAIL === 1 ? '' : 's'} did not hold`
            : 'Equation audit passes'
        }</strong>
        <span class="detail">
          ${counts.PASS} passing checks across every <code>eq:</code> and
          <code>alg:</code> label in <code>docs/main.tex</code>.
          ${
            audit.counts_agree
              ? ''
              : '<strong>Parsed counts disagree with the script’s own tally — treat this view with suspicion.</strong>'
          }
        </span>
      </div>
    </div>`;
}

function renderAudit(host, audit) {
  if (!audit.available) {
    host.innerHTML = '<p class="empty">No audit log.</p>';
    return;
  }

  const counts = audit.counts_reported || audit.counts_parsed;
  const summaryRows = Object.entries(audit.summary || {})
    .map(([k, v]) => `<tr><td>${k}</td><td style="text-align:left">${v}</td></tr>`)
    .join('');

  const failures = audit.failures.length
    ? audit.failures
        .map(
          (f) => `
          <div class="failure">
            <div class="failure-head"><span class="glyph">✗</span><code>${f.label}</code> ${f.text}</div>
            ${f.details.map((d) => `<div class="failure-detail">${d}</div>`).join('')}
            <div class="sub">${f.section}</div>
          </div>`
        )
        .join('')
    : '<p class="sub">No failing checks.</p>';

  host.innerHTML = `
    <header>
      <div><h2>Equation &amp; algorithm presence audit</h2>
        <span class="sub">Every thesis equation traced to its implementing symbol</span></div>
      <button class="icon-button" id="rerun-audit">Re-run audit</button>
    </header>

    <div class="tiles" style="margin-bottom:16px">
      <div class="tile"><div class="label">Passing</div>
        <div class="value" style="color:var(--status-good)">${counts.PASS}</div></div>
      <div class="tile"><div class="label">Failing</div>
        <div class="value" style="color:${counts.FAIL ? 'var(--status-critical)' : 'inherit'}">${counts.FAIL}</div></div>
      <div class="tile"><div class="label">Paper-only</div><div class="value">${counts.INFO}</div></div>
      <div class="tile"><div class="label">Checks run</div>
        <div class="value">${(audit.summary || {})['checks executed'] || audit.checks.length}</div></div>
    </div>

    <h3>Failing checks</h3>
    ${failures}

    <h3 style="margin-top:18px">Audit summary</h3>
    <div class="table-scroll">
      <table class="data"><tbody>${summaryRows}</tbody></table>
    </div>

    <h3 style="margin-top:18px">All checks
      <button class="table-toggle" id="toggle-checks" style="margin-left:8px">Show</button>
    </h3>
    <div id="all-checks" hidden></div>
  `;

  const toggle = host.querySelector('#toggle-checks');
  const list = host.querySelector('#all-checks');
  toggle.addEventListener('click', () => {
    list.hidden = !list.hidden;
    toggle.textContent = list.hidden ? 'Show' : 'Hide';
    if (!list.hidden && !list.dataset.filled) {
      list.innerHTML = renderChecksTable(audit.checks);
      list.dataset.filled = '1';
    }
  });
}

function renderChecksTable(checks) {
  const rows = checks
    .map(
      (c) => `<tr>
        <td><span class="status-pill status-${c.status}">${STATUS_GLYPH[c.status]} ${c.status}</span></td>
        <td><code>${c.label}</code></td>
        <td style="text-align:left">${c.text}
          ${c.details.length ? `<div class="sub">${c.details.join('<br>')}</div>` : ''}</td>
        <td style="text-align:left">${c.section}</td>
      </tr>`
    )
    .join('');
  return `<div class="table-scroll">
      <table class="data">
        <thead><tr><th>Status</th><th>Label</th><th>Check</th><th>Section</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderFunctional(host, functional) {
  if (!functional.available) {
    host.innerHTML = `
      <header><div><h2>Functional verification</h2>
        <span class="sub">Behavioural checks over a finished run</span></div></header>
      <div class="banner" data-status="warning" style="margin:0">
        <span class="glyph" aria-hidden="true">⚠</span>
        <div><strong>Not generated</strong>
          <span class="detail">${functional.note}<br>
          <code>${functional.command}</code></span></div>
      </div>`;
    return;
  }

  const c = functional.counts;
  host.innerHTML = `
    <header><div><h2>Functional verification</h2>
      <span class="sub">Behavioural checks over a finished run</span></div></header>
    <div class="tiles">
      <div class="tile"><div class="label">Passing</div>
        <div class="value" style="color:var(--status-good)">${c.PASS}</div></div>
      <div class="tile"><div class="label">Failing</div>
        <div class="value" style="color:${c.FAIL ? 'var(--status-critical)' : 'inherit'}">${c.FAIL}</div></div>
      <div class="tile"><div class="label">Coverage gaps</div>
        <div class="value" style="color:var(--status-warning)">${c.WARN}</div></div>
    </div>
    <p class="sub" style="margin-top:10px">
      WARN means the artefact was not produced by this run, so the property could not
      be evaluated — a coverage gap, not a defect.
    </p>`;
}
