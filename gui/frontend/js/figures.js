/**
 * Thesis figures tab -- the committed PNGs under output/.
 *
 * These are the figures already produced by scripts/plot_*.py and referenced by
 * the thesis, shown alongside the interactive charts so the demo can move
 * between "here is the published figure" and "here is the same data live".
 */

import { api } from './api.js';

const GROUP_TITLES = {
  '.': 'Root',
  hf: 'Hidden Forwarding (attacks 5–8)',
  fade: 'eFADE baseline comparison',
  tap: 'TAP baseline comparison',
  lstm: 'Federated LSTM',
  'ablation/q1': 'Ablation Q1',
  'ablation/q4': 'Ablation Q4 (witness)',
  'ablation/q5': 'Ablation Q5',
};

export async function initFigures(root) {
  root.innerHTML = '<div class="card"><p class="empty">Loading figures…</p></div>';

  let data;
  try {
    data = await api.figures();
  } catch (error) {
    root.innerHTML = `<div class="card"><p class="empty">${error.message}</p></div>`;
    return;
  }

  if (!data.groups.length) {
    root.innerHTML =
      '<div class="card"><p class="empty">No figures found under output/.</p></div>';
    return;
  }

  root.innerHTML = data.groups
    .map(
      (group) => `
      <div class="card">
        <header>
          <div>
            <h2>${GROUP_TITLES[group.group] || group.group}</h2>
            <span class="sub">output/${group.group === '.' ? '' : group.group + '/'}</span>
          </div>
          <span class="sub">${group.figures.length} figure${
            group.figures.length === 1 ? '' : 's'
          }</span>
        </header>
        <div class="gallery">
          ${group.figures
            .map(
              (fig) => `
              <figure>
                <a href="${api.figureUrl(fig.path)}" target="_blank" rel="noopener">
                  <img src="${api.figureUrl(fig.path)}" alt="${fig.name}" loading="lazy">
                </a>
                <figcaption>${fig.name}</figcaption>
              </figure>`
            )
            .join('')}
        </div>
      </div>`
    )
    .join('');
}
