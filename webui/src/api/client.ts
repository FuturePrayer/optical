// Minimal fetch wrapper for the center admin REST API.
// The admin token is read from localStorage (set via the login screen) and
// sent as a Bearer header on every request.

import type { NodeCounts, NodeRecord, ForwarderConfig } from './types';

const TOKEN_KEY = 'optical_center_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(init?.headers || {}) },
  });
  if (res.status === 401) {
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  overview: () => apiFetch<NodeCounts>('/overview'),
  nodes: () => apiFetch<NodeRecord[]>('/nodes'),
  node: (id: string) => apiFetch<NodeRecord>(`/nodes/${encodeURIComponent(id)}`),
  pending: () => apiFetch<NodeRecord[]>('/pending'),
  whitelist: () => apiFetch<string[]>('/whitelist'),
  approve: (id: string, forwarders: ForwarderConfig[]) =>
    apiFetch<{ delivered: boolean }>(`/nodes/${encodeURIComponent(id)}/approve`, {
      method: 'POST',
      body: JSON.stringify(forwarders),
    }),
  reject: (id: string) =>
    apiFetch<{ ok: boolean }>(`/nodes/${encodeURIComponent(id)}/reject`, { method: 'POST' }),
  rename: (id: string, name: string | null) =>
    apiFetch<{ ok: boolean }>(`/nodes/${encodeURIComponent(id)}/rename`, {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),
  remove: (id: string) =>
    apiFetch<{ removed: boolean }>(`/nodes/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  pushConfig: (nodeId: string, forwarders: ForwarderConfig[]) =>
    apiFetch<{ delivered: boolean }>('/config/push', {
      method: 'POST',
      body: JSON.stringify({ node_id: nodeId, forwarders }),
    }),
};

// SSE subscription helper. Returns an EventSource the caller manages.
// Token goes in the query string because EventSource can't set headers.
export function openEventStream(onEvent: (data: string) => void): EventSource {
  const token = getToken() || '';
  const es = new EventSource(`/api/events?token=${encodeURIComponent(token)}`);
  es.onmessage = (e) => onEvent(e.data);
  es.onerror = () => { /* EventSource auto-reconnects */ };
  return es;
}
