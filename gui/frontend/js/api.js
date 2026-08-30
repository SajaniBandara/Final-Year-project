/**
 * Thin fetch wrapper over the GUI backend.
 *
 * Every call surfaces the server's `detail` message on failure rather than a
 * bare status code -- the API returns useful ones (unknown column, TCAM column
 * on a narrow-schema attack, stale results directory) and swallowing them would
 * make a demo failure impossible to diagnose in the room.
 */

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(path, options);
  } catch (cause) {
    throw new ApiError(`Cannot reach the backend at ${path}. Is uvicorn running?`, 0);
  }

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body && body.detail) detail = body.detail;
    } catch {
      /* non-JSON error body; keep the status line */
    }
    throw new ApiError(detail, response.status);
  }
  return response.json();
}

const post = (path, body) =>
  request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });

const query = (params) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, value);
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : '';
};

export const api = {
  health: () => request('/api/health'),
  refresh: () => request('/api/refresh', { method: 'POST' }),
  catalog: () => request('/api/catalog'),
  metrics: (attackId) => request(`/api/metrics/${attackId}`),

  series: (runId, cols, runIndex = -1) =>
    request(
      `/api/run/${encodeURIComponent(runId)}/series` +
        query({ cols: cols ? cols.join(',') : undefined, run_index: runIndex })
    ),

  summary: (runId, runIndex = -1) =>
    request(`/api/run/${encodeURIComponent(runId)}/summary` + query({ run_index: runIndex })),

  sweep: ({ attack, metric, seeds, delayMs, tag }) =>
    request(
      '/api/sweep' +
        query({
          attack,
          metric,
          seeds: seeds && seeds.length ? seeds.join(',') : undefined,
          delay_ms: delayMs,
          tag,
        })
    ),

  lstmPanel: () => request('/api/panels/lstm'),
  tcamPanel: (mode) => request('/api/panels/tcam' + query({ mode })),
  cryptoPanel: (runId) => request('/api/panels/crypto' + query({ run_id: runId })),
  verification: () => request('/api/verification'),
  rerunAudit: () => request('/api/verification/audit', { method: 'POST' }),

  figures: () => request('/api/figures'),
  figureUrl: (path) => `/api/figures/${path}`,

  // --- simulation control ---------------------------------------------------
  // The only calls that change anything on the host. Everything above is a
  // read over the filesystem.
  simEnvironment: () => request('/api/sim/environment'),
  simOptions: () => request('/api/sim/options'),
  simPlan: (values, defences) => post('/api/sim/plan', { values, defences }),
  simStart: (values, defences) => post('/api/sim/start', { values, defences }),
  simStop: (uid) => request(`/api/sim/${encodeURIComponent(uid)}/stop`, { method: 'POST' }),
  simRuns: () => request('/api/sim/runs'),
  simStatus: (uid) => request(`/api/sim/${encodeURIComponent(uid)}`),
  simLog: (uid, since = 0) =>
    request(`/api/sim/${encodeURIComponent(uid)}/log` + query({ since })),

  // --- map ------------------------------------------------------------------
  mapScene: (runId, { start, end, step } = {}) =>
    request(`/api/map/${encodeURIComponent(runId)}` + query({ start, end, step })),
  mapNode: (runId, nodeId) =>
    request(`/api/map/${encodeURIComponent(runId)}/node/${nodeId}`),
  mapGuess: (runId, guess) =>
    post(`/api/map/${encodeURIComponent(runId)}/guess`, { guess }),
};
