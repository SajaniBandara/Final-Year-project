/**
 * SVG chart primitives.
 *
 * Hand-rolled rather than pulled from a chart library, for three reasons that
 * matter for this project specifically: the demo must not depend on a CDN or a
 * vendored bundle, confidence-interval bands and error bars are first-class here
 * instead of a plugin, and the mark specs (2px strokes, >=8px markers, a 2px
 * surface ring where marks overlap, recessive grid) are enforced directly.
 *
 * Every chart ships:
 *   - a crosshair + tooltip (an SVG chart is interactive by default),
 *   - a legend when there are >= 2 series,
 *   - direct end-of-line labels for <= 4 series, and
 *   - a table view, which is also the relief the light-mode contrast warning
 *     requires for the aqua/yellow/magenta slots.
 */

import { formatTick, formatValue } from './format.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

const VIEW = { w: 860, h: 380 };
const PAD = { top: 18, right: 84, bottom: 48, left: 68 };

const PLOT = {
  x: PAD.left,
  y: PAD.top,
  w: VIEW.w - PAD.left - PAD.right,
  h: VIEW.h - PAD.top - PAD.bottom,
};

/** The eight validated categorical slots, read from CSS so themes swap freely. */
export const SERIES_VARS = Array.from({ length: 8 }, (_, i) => `var(--series-${i + 1})`);

/** Colour for the nth series, in the fixed slot order. Never cycled past 8. */
export function seriesColor(index) {
  if (index >= SERIES_VARS.length) {
    // A 9th hue would be indistinguishable under CVD. Callers must fold or facet.
    throw new RangeError('more than 8 categorical series: fold into "Other" or facet');
  }
  return SERIES_VARS[index];
}

function el(name, attrs = {}, parent = null) {
  const node = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs)) {
    if (value !== undefined && value !== null) node.setAttribute(key, String(value));
  }
  if (parent) parent.appendChild(node);
  return node;
}

/** "Nice" axis bounds: pad the data range and snap to a readable step. */
function niceScale(min, max, ticks = 5) {
  if (!Number.isFinite(min) || !Number.isFinite(max)) return { lo: 0, hi: 1, step: 0.25 };
  if (min === max) {
    const pad = Math.abs(min) > 1e-9 ? Math.abs(min) * 0.1 : 1;
    min -= pad;
    max += pad;
  }
  const raw = (max - min) / ticks;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const norm = raw / mag;
  const step = (norm >= 5 ? 10 : norm >= 2 ? 5 : norm >= 1 ? 2 : 1) * mag;
  return { lo: Math.floor(min / step) * step, hi: Math.ceil(max / step) * step, step };
}

/**
 * Render a multi-series line chart.
 *
 * @param {HTMLElement} container
 * @param {object} config
 * @param {Array} config.series  [{ key, name, color, points: [{x, y, lo, hi}] }]
 * @param {string} config.yLabel Axis title (include the unit).
 * @param {string} config.unit   Unit key for value formatting.
 * @param {string} config.xLabel
 * @param {boolean} config.categoricalX  Space x values evenly (attack-% sweeps).
 * @param {Array} config.vlines  [{ x, label }] annotation lines, e.g. attack start.
 * @param {boolean} config.band  Draw a shaded lo..hi confidence band.
 * @param {boolean} config.errorBars Draw lo..hi whiskers instead of a band.
 */
export function renderLineChart(container, config) {
  const {
    series = [],
    yLabel = '',
    xLabel = '',
    unit = 'count',
    categoricalX = false,
    vlines = [],
    band = false,
    errorBars = false,
  } = config;

  container.innerHTML = '';
  const drawable = series.filter((s) => s.points && s.points.length);
  if (!drawable.length) {
    container.innerHTML = '<p class="empty">No data for this selection.</p>';
    return;
  }

  const wrap = document.createElement('div');
  wrap.className = 'chart-wrap';
  container.appendChild(wrap);

  const svg = el('svg', {
    viewBox: `0 0 ${VIEW.w} ${VIEW.h}`,
    role: 'img',
    'aria-label': `${yLabel} against ${xLabel}`,
    preserveAspectRatio: 'xMidYMid meet',
  });
  wrap.appendChild(svg);

  // --- scales -------------------------------------------------------------
  const xsAll = [...new Set(drawable.flatMap((s) => s.points.map((p) => p.x)))].sort(
    (a, b) => a - b
  );
  const ysAll = drawable.flatMap((s) =>
    s.points.flatMap((p) => [p.y, p.lo, p.hi].filter((v) => Number.isFinite(v)))
  );

  const yScale = niceScale(Math.min(...ysAll), Math.max(...ysAll));
  const xMin = xsAll[0];
  const xMax = xsAll[xsAll.length - 1];

  const sx = (x) => {
    if (categoricalX) {
      const i = xsAll.indexOf(x);
      return xsAll.length === 1
        ? PLOT.x + PLOT.w / 2
        : PLOT.x + (i / (xsAll.length - 1)) * PLOT.w;
    }
    return xMax === xMin
      ? PLOT.x + PLOT.w / 2
      : PLOT.x + ((x - xMin) / (xMax - xMin)) * PLOT.w;
  };
  const sy = (y) =>
    PLOT.y + PLOT.h - ((y - yScale.lo) / (yScale.hi - yScale.lo)) * PLOT.h;

  // --- grid + axes (recessive) -------------------------------------------
  const gridGroup = el('g', {}, svg);
  for (let v = yScale.lo; v <= yScale.hi + yScale.step / 2; v += yScale.step) {
    const y = sy(v);
    el('line', {
      x1: PLOT.x, x2: PLOT.x + PLOT.w, y1: y, y2: y,
      stroke: 'var(--grid)', 'stroke-width': 1,
    }, gridGroup);
    el('text', {
      x: PLOT.x - 10, y: y + 4, 'text-anchor': 'end',
      fill: 'var(--text-muted)', 'font-size': 11,
    }, gridGroup).textContent = formatTick(v, unit);
  }

  // x ticks: every category, or a thinned subset for dense continuous axes.
  const xTickValues = categoricalX
    ? xsAll
    : xsAll.filter((_, i) => i % Math.max(1, Math.ceil(xsAll.length / 10)) === 0);
  for (const x of xTickValues) {
    el('text', {
      x: sx(x), y: PLOT.y + PLOT.h + 20, 'text-anchor': 'middle',
      fill: 'var(--text-muted)', 'font-size': 11,
    }, gridGroup).textContent = categoricalX ? `${x}%` : String(x);
  }

  el('line', {
    x1: PLOT.x, x2: PLOT.x + PLOT.w, y1: PLOT.y + PLOT.h, y2: PLOT.y + PLOT.h,
    stroke: 'var(--axis)', 'stroke-width': 1,
  }, svg);

  el('text', {
    x: PLOT.x + PLOT.w / 2, y: VIEW.h - 8, 'text-anchor': 'middle',
    fill: 'var(--text-secondary)', 'font-size': 12,
  }, svg).textContent = xLabel;

  el('text', {
    x: 16, y: PLOT.y + PLOT.h / 2, 'text-anchor': 'middle',
    fill: 'var(--text-secondary)', 'font-size': 12,
    transform: `rotate(-90 16 ${PLOT.y + PLOT.h / 2})`,
  }, svg).textContent = yLabel;

  // --- annotation lines (e.g. attack start) -------------------------------
  for (const marker of vlines) {
    if (marker.x < xMin || marker.x > xMax) continue;
    const x = sx(marker.x);
    el('line', {
      x1: x, x2: x, y1: PLOT.y, y2: PLOT.y + PLOT.h,
      stroke: 'var(--status-serious)', 'stroke-width': 1.5, 'stroke-dasharray': '4 4',
    }, svg);
    el('text', {
      x: x + 5, y: PLOT.y + 12, fill: 'var(--status-serious)', 'font-size': 11,
    }, svg).textContent = marker.label;
  }

  // --- confidence bands (drawn under the lines) ---------------------------
  if (band) {
    for (const s of drawable) {
      const withCi = s.points.filter((p) => Number.isFinite(p.lo) && Number.isFinite(p.hi));
      if (withCi.length < 2) continue;
      const top = withCi.map((p) => `${sx(p.x)},${sy(p.hi)}`).join(' L ');
      const bottom = withCi.slice().reverse().map((p) => `${sx(p.x)},${sy(p.lo)}`).join(' L ');
      el('path', {
        d: `M ${top} L ${bottom} Z`, fill: s.color, opacity: 0.14, stroke: 'none',
      }, svg);
    }
  }

  // --- series -------------------------------------------------------------
  for (const s of drawable) {
    const path = s.points.map((p, i) => `${i ? 'L' : 'M'} ${sx(p.x)} ${sy(p.y)}`).join(' ');
    el('path', {
      d: path, fill: 'none', stroke: s.color, 'stroke-width': 2,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round',
    }, svg);

    if (errorBars) {
      for (const p of s.points) {
        if (!Number.isFinite(p.lo) || !Number.isFinite(p.hi)) continue;
        const x = sx(p.x);
        el('line', {
          x1: x, x2: x, y1: sy(p.lo), y2: sy(p.hi),
          stroke: s.color, 'stroke-width': 1.5,
        }, svg);
        for (const bound of [p.lo, p.hi]) {
          el('line', {
            x1: x - 4, x2: x + 4, y1: sy(bound), y2: sy(bound),
            stroke: s.color, 'stroke-width': 1.5,
          }, svg);
        }
      }
    }

    // Markers only when the series is sparse enough for them to be readable;
    // a 30-cycle time series becomes a caterpillar otherwise.
    if (s.points.length <= 12) {
      for (const p of s.points) {
        el('circle', {
          cx: sx(p.x), cy: sy(p.y), r: 4.5, fill: s.color,
          // 2px surface ring so overlapping marks stay separable.
          stroke: 'var(--surface-1)', 'stroke-width': 2,
        }, svg);
      }
    }
  }

  // --- direct labels (<= 4 series) ----------------------------------------
  // Also the relief for the light-mode contrast warning: identity never rests
  // on colour alone.
  if (drawable.length <= 4) {
    const placed = [];
    for (const s of drawable) {
      const last = s.points[s.points.length - 1];
      let y = sy(last.y) + 4;
      while (placed.some((p) => Math.abs(p - y) < 13)) y += 13;
      placed.push(y);
      el('text', {
        x: sx(last.x) + 10, y, fill: s.color, 'font-size': 11.5, 'font-weight': 600,
      }, svg).textContent = s.name;
    }
  }

  // --- crosshair + tooltip -------------------------------------------------
  attachCrosshair({ wrap, svg, drawable, xsAll, sx, sy, unit, categoricalX });

  // --- legend (>= 2 series) ------------------------------------------------
  if (drawable.length >= 2) {
    const legend = document.createElement('div');
    legend.className = 'legend';
    for (const s of drawable) {
      const item = document.createElement('span');
      item.className = 'item';
      const swatch = document.createElement('span');
      swatch.className = 'swatch';
      swatch.style.background = s.color;
      item.append(swatch, document.createTextNode(s.name));
      legend.appendChild(item);
    }
    container.appendChild(legend);
  }
}

function attachCrosshair({ wrap, svg, drawable, xsAll, sx, sy, unit, categoricalX }) {
  const crosshair = el('line', {
    y1: PLOT.y, y2: PLOT.y + PLOT.h,
    stroke: 'var(--axis)', 'stroke-width': 1, 'stroke-dasharray': '3 3',
    opacity: 0,
  }, svg);

  const highlights = drawable.map((s) =>
    el('circle', {
      r: 5.5, fill: s.color, stroke: 'var(--surface-1)', 'stroke-width': 2, opacity: 0,
    }, svg)
  );

  const tooltip = document.createElement('div');
  tooltip.className = 'chart-tooltip';
  wrap.appendChild(tooltip);

  // Transparent capture layer: a hit target far larger than the marks.
  const capture = el('rect', {
    x: PLOT.x, y: PLOT.y, width: PLOT.w, height: PLOT.h,
    fill: 'transparent', style: 'cursor:crosshair',
  }, svg);

  const hide = () => {
    crosshair.setAttribute('opacity', 0);
    highlights.forEach((h) => h.setAttribute('opacity', 0));
    tooltip.removeAttribute('data-visible');
  };

  capture.addEventListener('pointerleave', hide);
  capture.addEventListener('pointermove', (event) => {
    const box = svg.getBoundingClientRect();
    // Map client pixels back into viewBox units.
    const vx = ((event.clientX - box.left) / box.width) * VIEW.w;

    let nearest = xsAll[0];
    let best = Infinity;
    for (const x of xsAll) {
      const distance = Math.abs(sx(x) - vx);
      if (distance < best) {
        best = distance;
        nearest = x;
      }
    }

    const cx = sx(nearest);
    crosshair.setAttribute('x1', cx);
    crosshair.setAttribute('x2', cx);
    crosshair.setAttribute('opacity', 1);

    const rows = [];
    drawable.forEach((s, i) => {
      const point = s.points.find((p) => p.x === nearest);
      const marker = highlights[i];
      if (!point) {
        marker.setAttribute('opacity', 0);
        return;
      }
      marker.setAttribute('cx', cx);
      marker.setAttribute('cy', sy(point.y));
      marker.setAttribute('opacity', 1);
      rows.push({ name: s.name, color: s.color, point });
    });

    const title = categoricalX ? `${nearest}% attackers` : `Cycle ${nearest}`;
    tooltip.innerHTML =
      `<div class="tt-title">${title}</div>` +
      rows
        .map((r) => {
          const ci =
            Number.isFinite(r.point.lo) && Number.isFinite(r.point.hi)
              ? ` <span style="color:var(--text-muted)">±${formatValue(
                  (r.point.hi - r.point.lo) / 2,
                  unit
                )}</span>`
              : r.point.n === 1
                ? ' <span style="color:var(--text-muted)">n=1</span>'
                : '';
          return (
            `<div class="tt-row"><span class="swatch" style="background:${r.color}"></span>` +
            `<span>${r.name}</span>` +
            `<span class="tt-val">${formatValue(r.point.y, unit)}${ci}</span></div>`
          );
        })
        .join('');

    tooltip.style.left = `${(cx / VIEW.w) * 100}%`;
    tooltip.style.top = `${(PLOT.y / VIEW.h) * 100}%`;
    tooltip.setAttribute('data-visible', 'true');
  });
}

/**
 * Render the table view of a chart's data.
 *
 * Always available, never optional: it is how a reader who cannot separate two
 * hues still gets the numbers.
 */
export function renderTable(container, { series, xHeader, unit }) {
  const xs = [...new Set(series.flatMap((s) => s.points.map((p) => p.x)))].sort((a, b) => a - b);

  const scroll = document.createElement('div');
  scroll.className = 'table-scroll';
  const table = document.createElement('table');
  table.className = 'data';

  const head = document.createElement('thead');
  head.innerHTML =
    `<tr><th>${xHeader}</th>` +
    series.map((s) => `<th>${s.name}</th>`).join('') +
    '</tr>';
  table.appendChild(head);

  const body = document.createElement('tbody');
  for (const x of xs) {
    const cells = series.map((s) => {
      const point = s.points.find((p) => p.x === x);
      if (!point) return '<td>—</td>';
      const ci =
        Number.isFinite(point.lo) && Number.isFinite(point.hi)
          ? ` ± ${formatValue((point.hi - point.lo) / 2, unit)}`
          : point.n === 1
            ? ' (n=1)'
            : '';
      return `<td>${formatValue(point.y, unit)}${ci}</td>`;
    });
    const row = document.createElement('tr');
    row.innerHTML = `<td>${x}</td>${cells.join('')}`;
    body.appendChild(row);
  }
  table.appendChild(body);
  scroll.appendChild(table);

  container.innerHTML = '';
  container.appendChild(scroll);
}
