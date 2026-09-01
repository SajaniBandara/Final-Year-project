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

// A quarter-panel cell (e.g. a 2x2 metrics grid beside a map) cannot show the
// full-size chart's viewBox at a readable physical text size -- SVG text
// scales with the whole drawing, so shrinking only the container leaves axis
// labels a few physical pixels tall. `compact: true` swaps in a smaller
// viewBox with its own (still legible at that size) font scale, rather than
// the same 12.5-13.5px text stretched over a quarter of the space.
// Sized close to this call's actual rendered width (a 2x2 grid cell in a
// 560px sidebar column, see .pem-grid in app.css) rather than an arbitrary
// round number -- an SVG's font-size is in viewBox units, so what ends up
// legible is the ratio of font-size to viewBox width once scaled down to
// the container, not the font-size number alone.
// Flatter than the default 860x380 ratio on purpose: this feeds a 2x2 grid
// that has to fit beside the map, in view together with it, not stack tall
// enough to push the bottom row off-screen.
const VIEW_COMPACT = { w: 250, h: 100 };
const PAD_COMPACT = { top: 6, right: 8, bottom: 16, left: 30 };
const FONT = { default: { tick: 12.5, axis: 13.5, label: 12.5 }, compact: { tick: 10, axis: 0, label: 0 } };

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
 * @param {Array} config.hlines  [{ y, label }] horizontal reference lines, e.g. a
 *   detector threshold. Drawn beneath the series so data stays on top.
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
    hlines = [],
    band = false,
    errorBars = false,
    // A quarter-panel cell: smaller viewBox, smaller (still legible at that
    // physical size) type, and the chrome a reader doesn't need at a glance
    // (axis titles, direct end labels) dropped rather than shrunk illegibly.
    compact = false,
  } = config;

  container.innerHTML = '';
  const drawable = series.filter((s) => s.points && s.points.length);
  if (!drawable.length) {
    container.innerHTML = '<p class="empty">No data for this selection.</p>';
    return;
  }

  const view = compact ? VIEW_COMPACT : VIEW;
  const pad = compact ? PAD_COMPACT : PAD;
  const plot = {
    x: pad.left, y: pad.top,
    w: view.w - pad.left - pad.right,
    h: view.h - pad.top - pad.bottom,
  };
  const font = compact ? FONT.compact : FONT.default;

  const wrap = document.createElement('div');
  wrap.className = 'chart-wrap';
  container.appendChild(wrap);

  const svg = el('svg', {
    viewBox: `0 0 ${view.w} ${view.h}`,
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

  const yScale = niceScale(Math.min(...ysAll), Math.max(...ysAll), compact ? 3 : 5);
  const xMin = xsAll[0];
  const xMax = xsAll[xsAll.length - 1];

  const sx = (x) => {
    if (categoricalX) {
      const i = xsAll.indexOf(x);
      return xsAll.length === 1
        ? plot.x + plot.w / 2
        : plot.x + (i / (xsAll.length - 1)) * plot.w;
    }
    return xMax === xMin
      ? plot.x + plot.w / 2
      : plot.x + ((x - xMin) / (xMax - xMin)) * plot.w;
  };
  const sy = (y) =>
    plot.y + plot.h - ((y - yScale.lo) / (yScale.hi - yScale.lo)) * plot.h;

  // --- grid + axes (recessive) -------------------------------------------
  const gridGroup = el('g', {}, svg);
  for (let v = yScale.lo; v <= yScale.hi + yScale.step / 2; v += yScale.step) {
    const y = sy(v);
    el('line', {
      x1: plot.x, x2: plot.x + plot.w, y1: y, y2: y,
      stroke: 'var(--grid)', 'stroke-width': 1,
    }, gridGroup);
    el('text', {
      x: plot.x - (compact ? 6 : 10), y: y + 4, 'text-anchor': 'end',
      fill: 'var(--text-muted)', 'font-size': font.tick,
    }, gridGroup).textContent = formatTick(v, unit);
  }

  // x ticks: every category, or a thinned subset for dense continuous axes.
  const xTickValues = categoricalX
    ? xsAll
    : xsAll.filter((_, i) => i % Math.max(1, Math.ceil(xsAll.length / (compact ? 4 : 10))) === 0);
  for (const x of xTickValues) {
    el('text', {
      x: sx(x), y: plot.y + plot.h + (compact ? 14 : 20), 'text-anchor': 'middle',
      fill: 'var(--text-muted)', 'font-size': font.tick,
    }, gridGroup).textContent = categoricalX ? `${x}%` : String(x);
  }

  el('line', {
    x1: plot.x, x2: plot.x + plot.w, y1: plot.y + plot.h, y2: plot.y + plot.h,
    stroke: 'var(--axis)', 'stroke-width': 1,
  }, svg);

  if (!compact) {
    el('text', {
      x: plot.x + plot.w / 2, y: view.h - 8, 'text-anchor': 'middle',
      fill: 'var(--text-secondary)', 'font-size': font.axis, 'font-weight': 600,
    }, svg).textContent = xLabel;

    el('text', {
      x: 16, y: plot.y + plot.h / 2, 'text-anchor': 'middle',
      fill: 'var(--text-secondary)', 'font-size': font.axis, 'font-weight': 600,
      transform: `rotate(-90 16 ${plot.y + plot.h / 2})`,
    }, svg).textContent = yLabel;
  }

  // --- annotation lines (e.g. attack start) -------------------------------
  for (const marker of vlines) {
    if (marker.x < xMin || marker.x > xMax) continue;
    const x = sx(marker.x);
    el('line', {
      x1: x, x2: x, y1: plot.y, y2: plot.y + plot.h,
      stroke: 'var(--status-serious)', 'stroke-width': compact ? 1 : 1.5, 'stroke-dasharray': '4 4',
    }, svg);
    if (!compact) {
      el('text', {
        x: x + 5, y: plot.y + 12, fill: 'var(--status-serious)', 'font-size': font.tick, 'font-weight': 600,
      }, svg).textContent = marker.label;
    }
  }

  // --- horizontal reference lines (e.g. a detector threshold) -------------
  for (const marker of hlines) {
    if (marker.y < yScale.lo || marker.y > yScale.hi) continue;
    const y = sy(marker.y);
    el('line', {
      x1: plot.x, x2: plot.x + plot.w, y1: y, y2: y,
      stroke: 'var(--status-critical)', 'stroke-width': compact ? 1 : 1.5, 'stroke-dasharray': '6 3',
    }, svg);
    if (!compact) {
      el('text', {
        x: plot.x + plot.w - 4, y: y - 5, 'text-anchor': 'end',
        fill: 'var(--status-critical)', 'font-size': font.tick, 'font-weight': 600,
      }, svg).textContent = marker.label;
    }
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
      d: path, fill: 'none', stroke: s.color, 'stroke-width': compact ? 1.5 : 2,
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
    // a 30-cycle time series becomes a caterpillar otherwise. Compact charts
    // skip them entirely -- at this size they'd touch.
    if (!compact && s.points.length <= 12) {
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
  // on colour alone. Skipped in compact mode -- the picker above the chart
  // already names the one series, and there is no room to set it in type.
  if (!compact && drawable.length <= 4) {
    const placed = [];
    for (const s of drawable) {
      const last = s.points[s.points.length - 1];
      let y = sy(last.y) + 4;
      while (placed.some((p) => Math.abs(p - y) < 13)) y += 13;
      placed.push(y);
      el('text', {
        x: sx(last.x) + 10, y, fill: s.color, 'font-size': font.tick, 'font-weight': 600,
      }, svg).textContent = s.name;
    }
  }

  // --- crosshair + tooltip -------------------------------------------------
  attachCrosshair({ wrap, svg, drawable, xsAll, sx, sy, unit, categoricalX, view, plot });

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

function attachCrosshair({ wrap, svg, drawable, xsAll, sx, sy, unit, categoricalX, view = VIEW, plot = PLOT }) {
  const crosshair = el('line', {
    y1: plot.y, y2: plot.y + plot.h,
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
    x: plot.x, y: plot.y, width: plot.w, height: plot.h,
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
    const vx = ((event.clientX - box.left) / box.width) * view.w;

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

    tooltip.style.left = `${(cx / view.w) * 100}%`;
    tooltip.style.top = `${(plot.y / view.h) * 100}%`;
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

/**
 * Sequential blue ramp (light -> dark), for magnitude encoding.
 *
 * Used by the heatmap. For an ordinal ramp on the light surface the step
 * nearest the surface must still clear 2:1, so discrete marks start at index 3
 * (step 250) rather than index 0.
 */
export const SEQUENTIAL_BLUE = [
  '#cde2fb', '#b7d3f6', '#9ec5f4', '#86b6ef', '#6da7ec', '#5598e7', '#3987e5',
  '#2a78d6', '#256abf', '#1c5cab', '#184f95', '#104281', '#0d366b',
];

/** Map a 0..1 magnitude onto the sequential ramp. */
export function sequentialColor(t) {
  if (!Number.isFinite(t)) return 'var(--grid)';
  const clamped = Math.max(0, Math.min(1, t));
  const index = Math.round(clamped * (SEQUENTIAL_BLUE.length - 1));
  return SEQUENTIAL_BLUE[index];
}

/**
 * Vertical bar chart for comparing magnitude across categories.
 *
 * One hue for every bar: the bar's *length* encodes magnitude, so colouring
 * bars differently would imply an identity distinction that is not there.
 *
 * @param {object} config
 * @param {Array} config.bars [{ label, value, note }] -- `note` marks a bar
 *   whose value is not comparable (e.g. an undefined MCC), drawn as a gap.
 */
export function renderBarChart(container, { bars = [], unit = 'count', yLabel = '' }) {
  container.innerHTML = '';
  const drawable = bars.filter((b) => b && Number.isFinite(b.value));
  if (!bars.length) {
    container.innerHTML = '<p class="empty">No data.</p>';
    return;
  }

  const wrap = document.createElement('div');
  wrap.className = 'chart-wrap';
  container.appendChild(wrap);

  const height = 320;
  const pad = { top: 18, right: 16, bottom: 86, left: 64 };
  const plotW = VIEW.w - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const svg = el('svg', {
    viewBox: `0 0 ${VIEW.w} ${height}`,
    role: 'img',
    'aria-label': yLabel,
    preserveAspectRatio: 'xMidYMid meet',
  });
  wrap.appendChild(svg);

  const maxValue = Math.max(0, ...drawable.map((b) => b.value));
  const scale = niceScale(0, maxValue || 1);
  const sy = (v) => pad.top + plotH - ((v - scale.lo) / (scale.hi - scale.lo)) * plotH;

  for (let v = scale.lo; v <= scale.hi + scale.step / 2; v += scale.step) {
    const y = sy(v);
    el('line', {
      x1: pad.left, x2: pad.left + plotW, y1: y, y2: y,
      stroke: 'var(--grid)', 'stroke-width': 1,
    }, svg);
    el('text', {
      x: pad.left - 10, y: y + 4, 'text-anchor': 'end',
      fill: 'var(--text-muted)', 'font-size': 11,
    }, svg).textContent = formatTick(v, unit);
  }

  const slot = plotW / bars.length;
  const barWidth = Math.min(46, slot * 0.62);

  bars.forEach((bar, index) => {
    const cx = pad.left + slot * (index + 0.5);

    if (Number.isFinite(bar.value)) {
      const y = sy(bar.value);
      el('rect', {
        x: cx - barWidth / 2, y, width: barWidth,
        height: Math.max(0, pad.top + plotH - y),
        // 4px rounded data-end, anchored to the baseline.
        rx: 4, ry: 4,
        fill: 'var(--series-1)',
      }, svg);
      el('text', {
        x: cx, y: y - 6, 'text-anchor': 'middle',
        fill: 'var(--text-secondary)', 'font-size': 11,
      }, svg).textContent = formatValue(bar.value, unit);
    } else {
      // Not a zero bar: an explicit gap, so an uncomputable value is never
      // read as "scored nothing".
      el('text', {
        x: cx, y: pad.top + plotH - 8, 'text-anchor': 'middle',
        fill: 'var(--text-muted)', 'font-size': 11, 'font-style': 'italic',
      }, svg).textContent = bar.note || 'n/a';
    }

    const label = el('text', {
      x: cx, y: pad.top + plotH + 16, 'text-anchor': 'end',
      fill: 'var(--text-muted)', 'font-size': 11,
      transform: `rotate(-40 ${cx} ${pad.top + plotH + 16})`,
    }, svg);
    label.textContent = bar.label;
  });

  el('line', {
    x1: pad.left, x2: pad.left + plotW, y1: pad.top + plotH, y2: pad.top + plotH,
    stroke: 'var(--axis)', 'stroke-width': 1,
  }, svg);
}

/**
 * Single horizontal part-to-whole bar.
 *
 * Only honest when the segments sum to the whole, which the backend test
 * enforces for the federated rejection breakdown.
 */
export function renderStackedBar(container, { segments = [], total, unit = 'count' }) {
  container.innerHTML = '';
  const sum = total || segments.reduce((acc, s) => acc + s.count, 0);
  if (!sum) {
    container.innerHTML = '<p class="empty">No data.</p>';
    return;
  }

  const track = document.createElement('div');
  track.className = 'stack-track';
  segments
    .filter((s) => s.count > 0)
    .forEach((segment) => {
      const cell = document.createElement('div');
      cell.className = 'stack-seg';
      cell.style.flexGrow = String(segment.count);
      cell.style.background = segment.color;
      cell.title = `${segment.label}: ${segment.count} of ${sum}`;
      cell.textContent = segment.count >= sum * 0.08 ? String(segment.count) : '';
      track.appendChild(cell);
    });
  container.appendChild(track);

  const legend = document.createElement('div');
  legend.className = 'legend';
  segments.forEach((segment) => {
    const item = document.createElement('span');
    item.className = 'item';
    const swatch = document.createElement('span');
    swatch.className = 'swatch';
    swatch.style.background = segment.color;
    swatch.style.height = '10px';
    item.append(
      swatch,
      document.createTextNode(`${segment.label} — ${formatValue(segment.count, unit)}`)
    );
    legend.appendChild(item);
  });
  container.appendChild(legend);
}
