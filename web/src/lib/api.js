// Schlanke Hülle um die REST-API der ThreatIntel-Plattform.

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.error ?? `Anfrage fehlgeschlagen (${response.status})`)
  }
  return response.status === 204 ? null : response.json()
}

export function buildQuery(filters) {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value !== '' && value !== null && value !== undefined && value !== false) {
      params.set(key, String(value))
    }
  }
  const query = params.toString()
  return query ? `?${query}` : ''
}

export const api = {
  stats: () => request('/api/stats'),
  vulnerabilities: (filters) => request(`/api/vulnerabilities${buildQuery(filters)}`),
  watchlist: () => request('/api/watchlist'),
  addToWatchlist: (product) => request('/api/watchlist', { method: 'POST', body: JSON.stringify({ product }) }),
  removeFromWatchlist: (product) => request(`/api/watchlist/${encodeURIComponent(product)}`, { method: 'DELETE' })
}
