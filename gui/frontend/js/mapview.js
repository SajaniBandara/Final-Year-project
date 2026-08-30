/**
 * The network map: a NetAnim-style view with the annotations NetAnim cannot do.
 *
 * NetAnim shows nodes and packets. What a viva panel needs to see is *why the
 * system reacted*, so this draws the same scene with the security state layered
 * on: who is accusing whom, via which signature, and how that spreads over time.
 *
 * Rendered on a canvas rather than as SVG. 200 vehicles plus 64 RSUs plus the
 * accusation edges is 300-odd moving elements at 10 fps; that is enough DOM
 * churn to drop frames on a laptop, and none of it needs to be individually
 * addressable in the DOM -- hit-testing is a distance check against the same
 * coordinates used to draw.
 *
 * Coordinates: simulation metres, y-up (0,0 at the south-west corner of the LA
 * map). Canvas is y-down, so every draw goes through `project()`, which flips
 * y as well as scaling. Getting that flip wrong mirrors the whole map top to
 * bottom, which looks plausible and is completely wrong -- the RSU grid is
 * symmetric enough to hide it.
 */


/* Signature -> design token. Token names, not var() strings, so canvas code
 * can resolve them the same way it resolves every other colour and CSS can use
 * them directly -- keeping one mapping instead of two that can drift. */
const SIGNAL_TOKENS = {
  S1: '--series-1', S2: '--series-2', S3: '--series-3', S4: '--series-4',
  S5: '--series-5', S6: '--series-6', S7: '--series-7', S8: '--series-8',
};

const SIGNAL_COLORS = Object.fromEntries(
  Object.entries(SIGNAL_TOKENS).map(([sig, tok]) => [sig, `var(${tok})`])
);

/** How long an accusation stays lit, in simulated seconds. */
const EVENT_FADE_S = 3.0;

/** Click tolerance, in *screen* pixels.
 *
 * Screen space, not simulation metres: the RSU grid is spaced 260 x 270 m, so a
 * tolerance generous enough to hit a vehicle at one zoom is either unusable or
 * ambiguous at another. Converting a fixed pixel radius through the current
 * scale keeps "click near the dot" meaning the same thing however the map is
 * sized. */
const HIT_RADIUS_PX = 16;

export class NetworkMap {
  /**
   * @param {HTMLCanvasElement} canvas
   * @param {object} opts
   * @param {(node: object|null) => void} opts.onSelect  node clicked
   * @param {(node: object) => void} opts.onGuess        node marked as a guess
   */
  constructor(canvas, opts = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.onSelect = opts.onSelect || (() => {});
    this.onGuess = opts.onGuess || (() => {});

    this.scene = null;
    this.frameIndex = 0;
    this.selected = null;
    this.guesses = new Set();
    this.revealed = null;      // ground-truth attacker set, after a reveal
    this.showCoverage = true;
    this.showControlPlane = true;
    this.showTrails = false;
    this.guessMode = false;
    this.filterSignal = null;  // show only this signature's accusations

    /** Recent accusations, kept across frames so they can fade rather than blink. */
    this._recent = [];
    /** Screen positions from the last paint, for hit-testing. */
    this._hits = [];
    /** Previous sim-space positions per vehicle, for heading computation. */
    this._prevPositions = new Map();
    /** Last known heading angle (radians, canvas space) per vehicle id. */
    this._vehicleAngles = new Map();

    this._resize = this._resize.bind(this);
    window.addEventListener('resize', this._resize);
    canvas.addEventListener('click', (e) => this._click(e));
    canvas.addEventListener('mousemove', (e) => this._hover(e));
    canvas.addEventListener('mouseleave', () => {
      this._hovered = null;
      this.draw();
    });
    this._resize();
  }

  destroy() {
    window.removeEventListener('resize', this._resize);
  }

  // -- data ----------------------------------------------------------------

  setScene(scene) {
    this.scene = scene;
    this.frameIndex = 0;
    this._recent = [];
    this.revealed = null;
    this.guesses.clear();
    this._prevPositions.clear();
    this._vehicleAngles.clear();
    this._resize();
  }

  setFrame(index) {
    if (!this.scene) return;
    const clamped = Math.max(0, Math.min(this.scene.frames.length - 1, index));
    // Rebuild the fade window from scratch when scrubbing backwards; appending
    // only works while time moves forward, and a scrub that leaves stale events
    // lit is the kind of thing a panel notices.
    if (clamped < this.frameIndex) this._recent = [];
    for (let i = this.frameIndex + 1; i <= clamped; i += 1) {
      this._appendEvents(i);
    }
    if (clamped === 0) this._appendEvents(0);
    this.frameIndex = clamped;
    this.draw();
  }

  _appendEvents(index) {
    const frame = this.scene?.frames[index];
    if (!frame) return;
    for (const event of frame.events) this._recent.push(event);
    const cutoff = frame.t - EVENT_FADE_S;
    this._recent = this._recent.filter((e) => e.t >= cutoff);
  }

  get frame() {
    return this.scene?.frames[this.frameIndex] ?? null;
  }

  get time() {
    return this.frame?.t ?? 0;
  }

  /** Accusations currently drawn, i.e. inside the fade window and any filter. */
  visibleEvents() {
    return this._recent.filter(
      (e) => !this.filterSignal || e.signal === this.filterSignal
    );
  }

  // -- geometry ------------------------------------------------------------

  _resize() {
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.max(1, Math.round(rect.width * dpr));
    this.canvas.height = Math.max(1, Math.round(rect.height * dpr));
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.viewW = rect.width;
    this.viewH = rect.height;

    const map = this.scene?.layout?.map ?? { width: 2061, height: 2137 };
    const pad = 18;
    this.scale = Math.min(
      (this.viewW - pad * 2) / map.width,
      (this.viewH - pad * 2) / map.height
    );
    this.offsetX = (this.viewW - map.width * this.scale) / 2;
    this.offsetY = (this.viewH - map.height * this.scale) / 2;
    this.mapH = map.height;
    this.draw();
  }

  /** Simulation metres -> canvas pixels, flipping y (sim is y-up). */
  project(x, y) {
    return [
      this.offsetX + x * this.scale,
      this.offsetY + (this.mapH - y) * this.scale,
    ];
  }

  /** Canvas pixels -> simulation metres. Inverse of project(). */
  unproject(px, py) {
    return [
      (px - this.offsetX) / this.scale,
      this.mapH - (py - this.offsetY) / this.scale,
    ];
  }

  // -- interaction ---------------------------------------------------------

  _pointer(event) {
    const rect = this.canvas.getBoundingClientRect();
    return this.unproject(event.clientX - rect.left, event.clientY - rect.top);
  }

  _nearest(mx, my) {
    let best = null;
    const toleranceM = HIT_RADIUS_PX / this.scale;
    let bestD = toleranceM * toleranceM;
    for (const hit of this._hits) {
      const dx = hit.x - mx;
      const dy = hit.y - my;
      const d = dx * dx + dy * dy;
      if (d < bestD) {
        bestD = d;
        best = hit;
      }
    }
    return best;
  }

  _click(event) {
    const [mx, my] = this._pointer(event);
    const hit = this._nearest(mx, my);
    if (!hit) {
      this.selected = null;
      this.onSelect(null);
      this.draw();
      return;
    }
    if (this.guessMode) {
      if (this.guesses.has(hit.id)) this.guesses.delete(hit.id);
      else this.guesses.add(hit.id);
      this.onGuess(hit);
      this.draw();
      return;
    }
    this.selected = hit.id;
    this.onSelect(hit);
    this.draw();
  }

  _hover(event) {
    const [mx, my] = this._pointer(event);
    const hit = this._nearest(mx, my);
    const id = hit ? hit.id : null;
    if (id !== this._hovered) {
      this._hovered = id;
      this.canvas.style.cursor = hit ? 'pointer' : 'default';
      this.draw();
    }
  }

  // -- painting ------------------------------------------------------------

  draw() {
    const ctx = this.ctx;
    const css = getComputedStyle(document.documentElement);
    const token = (name) => css.getPropertyValue(name).trim();

    ctx.clearRect(0, 0, this.viewW, this.viewH);
    if (!this.scene) {
      this._placeholder(ctx, token, 'Pick a run to draw its network.');
      return;
    }

    const layout = this.scene.layout;
    this._hits = [];

    this._drawGround(ctx, token, layout);
    if (this.showControlPlane) this._drawControlPlane(ctx, token, layout);
    if (this.showCoverage) this._drawCoverage(ctx, token, layout);
    this._drawAccusations(ctx, token, layout);
    this._drawRsus(ctx, token, layout);
    this._drawControllers(ctx, token, layout);
    this._drawVehicles(ctx, token);
    this._drawScaleBar(ctx, token);
  }

  _placeholder(ctx, token, message) {
    ctx.fillStyle = token('--text-muted');
    ctx.font = '13px var(--font, system-ui)';
    ctx.textAlign = 'center';
    ctx.fillText(message, this.viewW / 2, this.viewH / 2);
    ctx.textAlign = 'left';
  }

  _drawGround(ctx, token, layout) {
    const [x0, y0] = this.project(0, layout.map.height);
    ctx.fillStyle = token('--surface-1');
    ctx.fillRect(x0, y0, layout.map.width * this.scale, layout.map.height * this.scale);
    ctx.strokeStyle = token('--border');
    ctx.lineWidth = 1;
    ctx.strokeRect(x0, y0, layout.map.width * this.scale, layout.map.height * this.scale);
  }

  /** RSU-to-controller assignment, which is nearest-controller in the C++. */
  _drawControlPlane(ctx, token, layout) {
    ctx.save();
    ctx.globalAlpha = 0.16;
    ctx.lineWidth = 1;
    for (const rsu of layout.rsus) {
      const controller = layout.controllers[rsu.controller];
      if (!controller) continue;
      const [ax, ay] = this.project(rsu.x, rsu.y);
      const [bx, by] = this.project(controller.x, controller.y);
      ctx.strokeStyle = token(`--series-${(rsu.controller % 8) + 1}`);
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(bx, by);
      ctx.stroke();
    }
    ctx.restore();
  }

  _drawCoverage(ctx, token, layout) {
    const radius = layout.coverage_radius * this.scale;
    ctx.save();
    ctx.globalAlpha = 0.07;
    ctx.fillStyle = token('--series-1');
    for (const rsu of layout.rsus) {
      const [x, y] = this.project(rsu.x, rsu.y);
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  }

  /**
   * Accusation edges: RSU -> suspect, coloured by signature, fading with age.
   *
   * Drawn under the nodes so a dense burst never hides what it is about.
   */
  _drawAccusations(ctx, token, layout) {
    const now = this.time;
    const positions = this._vehiclePositions();
    ctx.save();
    ctx.lineWidth = 1.4;
    for (const event of this._recent) {
      if (this.filterSignal && event.signal !== this.filterSignal) continue;
      const from = this._nodePosition(event.rsu, layout, positions);
      const to = this._nodePosition(event.suspect, layout, positions);
      if (!from || !to) continue;
      const age = Math.max(0, Math.min(1, (now - event.t) / EVENT_FADE_S));
      ctx.globalAlpha = 0.75 * (1 - age);
      ctx.strokeStyle = SIGNAL_TOKENS[event.signal]
        ? token(SIGNAL_TOKENS[event.signal])
        : token('--status-critical');
      const [ax, ay] = this.project(from[0], from[1]);
      const [bx, by] = this.project(to[0], to[1]);
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(bx, by);
      ctx.stroke();
    }
    ctx.restore();
  }

  _vehiclePositions() {
    const map = new Map();
    for (const v of this.frame?.vehicles ?? []) map.set(v.id, [v.x, v.y]);
    return map;
  }

  _nodePosition(id, layout, vehiclePositions) {
    if (vehiclePositions.has(id)) return vehiclePositions.get(id);
    const rsuRange = layout.id_ranges.rsus;
    if (id >= rsuRange[0] && id <= rsuRange[1]) {
      const rsu = layout.rsus[id - rsuRange[0]];
      return rsu ? [rsu.x, rsu.y] : null;
    }
    const ctrlRange = layout.id_ranges.controllers;
    if (id >= ctrlRange[0] && id <= ctrlRange[1]) {
      const c = layout.controllers[id - ctrlRange[0]];
      return c ? [c.x, c.y] : null;
    }
    return null;
  }

  /** Accusations *currently* landing on each node, for highlighting. */
  _accusedNow() {
    const counts = new Map();
    for (const event of this._recent) {
      if (this.filterSignal && event.signal !== this.filterSignal) continue;
      counts.set(event.suspect, (counts.get(event.suspect) || 0) + 1);
    }
    return counts;
  }

  _drawRsus(ctx, token, layout) {
    const density = this.frame?.density ?? {};
    const accused = this._accusedNow();
    const accusing = new Set(
      this._recent
        .filter((e) => !this.filterSignal || e.signal === this.filterSignal)
        .map((e) => e.rsu)
    );

    for (const rsu of layout.rsus) {
      const [x, y] = this.project(rsu.x, rsu.y);
      const load = Number(density[rsu.id] ?? 0);
      // Antenna height grows with load so a busy RSU is visible at a glance.
      const h = 9 + Math.min(6, load * 0.5);

      let color = token('--axis');
      let signalColor = token('--text-muted');
      if (accusing.has(rsu.id)) {
        color = token('--series-1');
        signalColor = token('--series-1');
      }
      if (accused.has(rsu.id)) {
        color = token('--status-critical');
        signalColor = token('--status-critical');
      }

      this._drawRsuIcon(ctx, x, y, h, color, signalColor);
      this._decorate(ctx, token, rsu.id, x, y, h * 1.6);
      this._hits.push({ id: rsu.id, x: rsu.x, y: rsu.y, kind: 'rsu', label: `RSU ${rsu.id}` });
    }
  }

  _drawControllers(ctx, token, layout) {
    for (const controller of layout.controllers) {
      const [x, y] = this.project(controller.x, controller.y);
      const color = token('--series-7');
      const bg    = token('--surface-raised');
      this._drawControllerIcon(ctx, x, y, 13, color, bg);
      this._decorate(ctx, token, controller.id, x, y, 26);
      this._hits.push({
        id: controller.id, x: controller.x, y: controller.y,
        kind: 'controller', label: `Controller c${controller.index + 1}`,
      });
    }
  }

  /**
   * Cell-tower icon for an RSU.
   *
   * Three layers, top to bottom:
   *   1. Signal arcs  — two curved arcs radiating from the antenna tip.
   *   2. Pole         — a thin vertical mast.
   *   3. Base disc    — a small filled circle anchoring the tower.
   *
   * `h` is the half-height of the pole in screen pixels.
   */
  _drawRsuIcon(ctx, cx, cy, h, color, signalColor) {
    const poleW  = Math.max(1.5, h * 0.14);
    const tipY   = cy - h;          // top of the antenna
    const baseY  = cy + h * 0.35;   // bottom of the pole
    const baseR  = h * 0.35;        // radius of the base disc

    // --- signal arcs --------------------------------------------------------
    for (let i = 1; i <= 2; i++) {
      const r = h * 0.45 * i;
      ctx.beginPath();
      ctx.arc(cx, tipY, r, -Math.PI * 0.78, -Math.PI * 0.22);
      ctx.lineWidth = 1.3 - i * 0.3;
      ctx.strokeStyle = signalColor;
      ctx.globalAlpha = 0.85 - (i - 1) * 0.3;
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // --- pole ---------------------------------------------------------------
    ctx.fillStyle = color;
    ctx.fillRect(cx - poleW / 2, tipY, poleW, baseY - tipY);

    // --- base disc ----------------------------------------------------------
    ctx.beginPath();
    ctx.arc(cx, baseY, baseR, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = 'rgba(0,0,0,0.18)';
    ctx.stroke();
  }

  /**
   * Hexagonal server-hub icon for a controller.
   *
   * Three layers:
   *   1. Hexagon body — filled with the controller colour.
   *   2. Rack lines   — three horizontal rules suggesting server blades.
   *   3. Outline      — thin contrasting stroke.
   *
   * `r` is the circumradius of the hexagon in screen pixels.
   */
  _drawControllerIcon(ctx, cx, cy, r, color, bg) {
    // --- hexagon body -------------------------------------------------------
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const a = Math.PI / 6 + (i * Math.PI) / 3;   // flat-top orientation
      const px = cx + r * Math.cos(a);
      const py = cy + r * Math.sin(a);
      if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
    }
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = bg;
    ctx.stroke();

    // --- inner rack lines ---------------------------------------------------
    const lw = r * 0.7;     // line width
    const gap = r * 0.32;   // vertical spacing between lines
    ctx.strokeStyle = bg;
    ctx.lineWidth = 1.2;
    ctx.globalAlpha = 0.55;
    for (let row = -1; row <= 1; row++) {
      ctx.beginPath();
      ctx.moveTo(cx - lw / 2, cy + row * gap);
      ctx.lineTo(cx + lw / 2, cy + row * gap);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }

  _drawVehicles(ctx, token) {
    const accused = this._accusedNow();
    const vehicles = this.frame?.vehicles ?? [];

    for (const vehicle of vehicles) {
      const [x, y] = this.project(vehicle.x, vehicle.y);
      const hits = accused.get(vehicle.id) || 0;

      // Compute heading from previous position; keep the last known angle when
      // the vehicle is stationary so the car shape does not snap to 0°.
      const prev = this._prevPositions.get(vehicle.id);
      if (prev) {
        // Project both positions to screen space so the angle accounts for
        // the y-axis flip that project() applies (sim is y-up, canvas y-down).
        const [px, py] = this.project(prev.x, prev.y);
        const dx = x - px;
        const dy = y - py;
        if (Math.hypot(dx, dy) > 0.5) {   // ignore sub-pixel jitter
          this._vehicleAngles.set(vehicle.id, Math.atan2(dy, dx));
        }
      }
      this._prevPositions.set(vehicle.id, { x: vehicle.x, y: vehicle.y });

      const angle = this._vehicleAngles.get(vehicle.id) ?? 0;
      this._drawCar(ctx, token, x, y, angle, hits > 0);

      // Decorations (selection ring, guess ring, reveal marks) expect a size
      // in pixels; 14 px covers the car body comfortably.
      this._decorate(ctx, token, vehicle.id, x, y, 14);
      this._hits.push({
        id: vehicle.id, x: vehicle.x, y: vehicle.y,
        kind: 'vehicle', label: `Vehicle ${vehicle.id}`,
      });
    }
  }

  /**
   * Draw a top-down car silhouette centred on (cx, cy), rotated by `angle`
   * radians (canvas space: 0 = pointing right, positive = clockwise).
   *
   * The shape has three layers:
   *   1. Car body  — rounded rectangle, coloured by threat status.
   *   2. Cabin     — smaller rounded rect with a dark tint for the glass area.
   *   3. Headlights — two small bright rectangles at the front.
   *
   * Sizes are kept small (body ≈ 13×8 px) so 200 cars fit on the map without
   * occluding the RSU grid.
   */
  _drawCar(ctx, token, cx, cy, angle, isAccused) {
    const bodyColor = isAccused
      ? token('--status-critical')
      : token('--series-2');

    // Car body dimensions in screen pixels.
    const bw = 13;   // length (along the direction of travel)
    const bh = 8;    // width
    const r  = 2;    // corner radius

    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(angle);

    // --- body ---------------------------------------------------------------
    ctx.beginPath();
    this._roundedRect(ctx, -bw / 2, -bh / 2, bw, bh, r);
    ctx.fillStyle = bodyColor;
    ctx.fill();

    // Thin outline so the car is legible against both light and dark themes.
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = isAccused
      ? token('--status-critical')
      : token('--surface-raised');
    ctx.globalAlpha = 0.6;
    ctx.stroke();
    ctx.globalAlpha = 1;

    // --- cabin (windscreen + roof) ------------------------------------------
    const cw = bw * 0.42;
    const ch = bh - 2.5;
    const cx2 = -cw / 2 + 0.5;   // slightly forward of centre
    const cy2 = -ch / 2;
    ctx.beginPath();
    this._roundedRect(ctx, cx2, cy2, cw, ch, 1.2);
    ctx.fillStyle = 'rgba(0,0,0,0.30)';
    ctx.fill();

    // --- headlights ---------------------------------------------------------
    const hlX = bw / 2 - 1.5;
    const hlH = (bh - 2) / 2 - 0.5;
    ctx.fillStyle = 'rgba(255, 245, 160, 0.95)';
    ctx.fillRect(hlX, -bh / 2 + 1.2, 1.5, hlH);
    ctx.fillRect(hlX,  0.3,           1.5, hlH);

    ctx.restore();
  }

  /** Canvas rounded-rect path helper (pre-CanvasRenderingContext2D.roundRect). */
  _roundedRect(ctx, x, y, w, h, r) {
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.arcTo(x + w, y,     x + w, y + r,     r);
    ctx.lineTo(x + w, y + h - r);
    ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
    ctx.lineTo(x + r, y + h);
    ctx.arcTo(x,      y + h, x,       y + h - r, r);
    ctx.lineTo(x, y + r);
    ctx.arcTo(x,      y,     x + r,   y,          r);
    ctx.closePath();
  }

  /**
   * Selection, guess and reveal marks, shared by every node kind.
   *
   * Reveal uses shape as well as colour -- a ring for a true attacker, a cross
   * for a wrong guess -- because the reveal is the moment the demo turns on,
   * and it should not depend on the projector's colour rendition.
   */
  _decorate(ctx, token, id, x, y, size) {
    const half = size / 2;
    if (this.guesses.has(id)) {
      ctx.beginPath();
      ctx.arc(x, y, half + 5, 0, Math.PI * 2);
      ctx.lineWidth = 2;
      ctx.strokeStyle = token('--series-4');
      ctx.setLineDash([3, 2]);
      ctx.stroke();
      ctx.setLineDash([]);
    }
    if (this.revealed) {
      const truth = this.revealed.has(id);
      const guessed = this.guesses.has(id);
      if (truth) {
        ctx.beginPath();
        ctx.arc(x, y, half + 8, 0, Math.PI * 2);
        ctx.lineWidth = 2.4;
        ctx.strokeStyle = token(guessed ? '--status-good' : '--status-critical');
        ctx.stroke();
      } else if (guessed) {
        ctx.beginPath();
        ctx.moveTo(x - half - 4, y - half - 4);
        ctx.lineTo(x + half + 4, y + half + 4);
        ctx.moveTo(x + half + 4, y - half - 4);
        ctx.lineTo(x - half - 4, y + half + 4);
        ctx.lineWidth = 2;
        ctx.strokeStyle = token('--status-warning');
        ctx.stroke();
      }
    }
    if (this.selected === id || this._hovered === id) {
      ctx.beginPath();
      ctx.arc(x, y, half + 3, 0, Math.PI * 2);
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = token('--text-primary');
      ctx.stroke();
      if (this._hovered === id) {
        ctx.fillStyle = token('--text-primary');
        ctx.font = '11px var(--mono, monospace)';
        ctx.fillText(String(id), x + half + 6, y - half - 4);
      }
    }
  }

  _drawScaleBar(ctx, token) {
    const metres = 500;
    const px = metres * this.scale;
    const x = 14;
    const y = this.viewH - 14;
    ctx.strokeStyle = token('--text-muted');
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x + px, y);
    ctx.moveTo(x, y - 4);
    ctx.lineTo(x, y + 4);
    ctx.moveTo(x + px, y - 4);
    ctx.lineTo(x + px, y + 4);
    ctx.stroke();
    ctx.fillStyle = token('--text-muted');
    ctx.font = '10px var(--font, system-ui)';
    ctx.fillText(`${metres} m`, x + px + 6, y + 3);
  }
}

/** Signature legend markup, shared by the map's two hosts. */
export function signalLegend(active = null) {
  return Object.keys(SIGNAL_COLORS)
    .map(
      (sig) => `
      <button class="chip sig-chip${active === sig ? ' is-active' : ''}"
              data-signal="${sig}" type="button"
              title="Show only ${sig} accusations">
        <span class="swatch" style="background:${SIGNAL_COLORS[sig]}"></span>${sig}
      </button>`
    )
    .join('');
}

export { SIGNAL_COLORS, SIGNAL_TOKENS };
