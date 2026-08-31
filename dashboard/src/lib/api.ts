const BASE = '/api/v1'

export interface Peer {
  id: string
  wg_pub_key: string
  ip: string
  local_ip?: string
  public_ip?: string
  country?: string
  hostname: string
  os: string
  version: string
  dns_label: string
  groups: string[]
  connected: boolean
  last_seen: string
  created_at: string
  advertised_routes?: string[]
}

export interface Group {
  id: string
  account_id: string
  name: string
  created_at: string
  peer_count: number
}

export interface Rule {
  id: string
  account_id: string
  name: string
  src: string
  dst: string
  protocol: string
  port: number
  action: 'allow' | 'deny'
  enabled: boolean
  priority: number
  created_at: string
}

export interface RulePayload {
  name: string
  src: string
  dst: string
  protocol: string
  port?: number
  action: 'allow' | 'deny'
  enabled: boolean
  priority?: number
}

export interface SetupKey {
  id: string
  name: string
  key: string
  ephemeral: boolean
  used_count: number
  auto_groups: string[]
  expires_at: string
  created_at: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (res.status === 401) {
    if (typeof window !== 'undefined') window.location.href = '/login'
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status} ${body}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  peers: {
    list: () => request<{ peers: Peer[] }>('/peers'),
    update: (key: string, payload: { groups: string[] }) =>
      request<Peer>(`/peers/${encodeURIComponent(key)}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    delete: (key: string) =>
      request<void>(`/peers/${encodeURIComponent(key)}`, { method: 'DELETE' }),
    setRoutes: (key: string, routes: string[]) =>
      request<{ peer: Peer }>(`/peers/${encodeURIComponent(key)}/routes`, {
        method: 'PUT',
        body: JSON.stringify({ routes }),
      }),
  },
  groups: {
    list: () => request<{ groups: Group[] }>('/groups'),
    create: (payload: { name: string }) =>
      request<{ group: Group }>('/groups', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    delete: (id: string) =>
      request<void>(`/groups/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  },
  setupKeys: {
    list: () => request<{ setup_keys: SetupKey[] }>('/setup-keys'),
    create: (payload: { name: string; ephemeral?: boolean; expires_in_days?: number; auto_groups?: string[] }) =>
      request<{ setup_key: SetupKey }>('/setup-keys', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    delete: (id: string) =>
      request<void>(`/setup-keys/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  },
  rules: {
    list: () => request<{ rules: Rule[] }>('/rules'),
    create: (payload: RulePayload) =>
      request<{ rule: Rule }>('/rules', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    update: (id: string, payload: Partial<RulePayload>) =>
      request<{ rule: Rule }>(`/rules/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    delete: (id: string) =>
      request<void>(`/rules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  },
  health: () => fetch(`${BASE}/health`).then(r => r.json()),
}
