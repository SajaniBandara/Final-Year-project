/**
 * Value formatting, driven by the unit the API reports for each column.
 *
 * Units are not uniform across the metrics CSV: MCC is a fraction in [-1, 1]
 * while DR/FPR are already percentages in [0, 100]. Formatting from the
 * server-supplied unit rather than guessing from the column name is what keeps
 * a fraction from being rendered as "0.47%".
 */

const DECIMALS = { fraction: 4, percent: 2, ms: 2, s: 6, bytes: 0, count: 3 };

/** Suffix appended after the number, by unit. */
const SUFFIX = { percent: '%', ms: ' ms', s: ' s', bytes: ' B' };

/** Format one value for display. Returns an em dash for null/undefined/NaN. */
export function formatValue(value, unit = 'count') {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  const decimals = DECIMALS[unit] ?? 3;
  const rounded = Number(value).toFixed(decimals);
  // Trim trailing zeros on counts so integers read as integers.
  const text =
    unit === 'count' || unit === 'bytes'
      ? String(Number(rounded))
      : rounded;
  return text + (SUFFIX[unit] ?? '');
}

/** Compact form for axis ticks, where space is tight. */
export function formatTick(value, unit = 'count') {
  if (value === null || value === undefined || Number.isNaN(value)) return '';
  const abs = Math.abs(value);
  if (abs !== 0 && (abs >= 100000 || abs < 0.001)) return Number(value).toExponential(1);
  if (unit === 'fraction') return Number(value.toFixed(2)).toString();
  if (abs >= 1000) return Number(value.toFixed(0)).toLocaleString();
  return Number(value.toFixed(abs < 10 ? 2 : 1)).toString();
}

/** Human-readable column name: `cur_lat_ms` -> `Latency (current)`. */
const PRETTY = {
  cur_PDR: 'PDR (current)', avg_PDR: 'PDR (average)',
  cur_lat_ms: 'End-to-end latency (current)', avg_lat_ms: 'End-to-end latency (average)',
  cur_MCC: 'MCC (current)', avg_MCC: 'MCC (average)',
  cur_DR: 'Detection rate (current)', avg_DR: 'Detection rate (average)',
  cur_FPR: 'False-positive rate (current)', avg_FPR: 'False-positive rate (average)',
  cur_mit_ms: 'Mitigation latency (current)', avg_mit_ms: 'Mitigation latency (average)',
  cur_TVR: 'Trust violation rate (current)', avg_TVR: 'Trust violation rate (average)',
  cur_UCR: 'Unauthorised copy rate (current)', avg_UCR: 'Unauthorised copy rate (average)',
  avg_trust_score: 'Average trust score',
  sig_valid_rate: 'Signature validity rate',
  flowmod_endorsement_rate: 'FlowMod endorsement rate',
  rsu_chain_len: 'RSU chain length', global_chain_len: 'Global chain length',
  max_tcam_util: 'TCAM utilisation (max)', avg_tcam_util: 'TCAM utilisation (average)',
  escalation_count: 'Escalations', d_obu_count: 'OBU detections', d_rsu_count: 'RSU detections',
  UFCR: 'Unauthorised flow-command rate',
};

export function prettyColumn(name) {
  if (PRETTY[name]) return PRETTY[name];
  return name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Label for an attack id; 0 is the benign baseline, not "attack zero". */
export function attackLabel(attackId) {
  return attackId === 0 ? 'Baseline (benign)' : `Attack ${attackId}`;
}

/** Short attack label for direct labels on a chart, where space is tight. */
export function attackShortLabel(attackId) {
  return attackId === 0 ? 'Base' : `A${attackId}`;
}

/**
 * Small formatters for prose and tables, where there is no column unit to key
 * off. `formatValue` above is the one to use whenever the API has told you the
 * unit; this is for counts, durations and percentages the UI itself computes.
 */
export const fmt = {
  /** Thousands-separated integer. */
  int: (value) =>
    value === null || value === undefined || Number.isNaN(value)
      ? '—'
      : Math.round(Number(value)).toLocaleString(),

  /** Fixed-decimal number, trailing zeros trimmed. */
  num: (value, decimals = 2) =>
    value === null || value === undefined || Number.isNaN(value)
      ? '—'
      : String(Number(Number(value).toFixed(decimals))),

  /** A value already expressed in percent, e.g. 47.2 -> "47.2%". */
  pct: (value, decimals = 1) =>
    value === null || value === undefined || Number.isNaN(value)
      ? '—'
      : `${Number(Number(value).toFixed(decimals))}%`,

  /**
   * Wall-clock duration. Seconds below a minute, m:ss above -- a demo operator
   * reading "412 s" has to do arithmetic to know whether to keep talking.
   */
  duration: (seconds) => {
    if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return '—';
    const total = Math.max(0, Math.round(Number(seconds)));
    if (total < 60) return `${total} s`;
    const minutes = Math.floor(total / 60);
    return `${minutes}m ${String(total % 60).padStart(2, '0')}s`;
  },
};
