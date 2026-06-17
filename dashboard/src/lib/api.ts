const BASE = process.env.NEXT_PUBLIC_MGMT_API ?? 'http://localhost:8080'

export interface Peer {
  id: string
  wg_pub_key: string
  ip: string
  hostname: string
  os: string
  dns_label: string
  connected: boolean
  last_seen: string
  created_at: string
  advertised_routes?: string[]
}

export interface SetupKey {
  id: string
  name: string
  key: string
  ephemeral: boolean
  used_count: number
  expires_at: string
  created_at: string
}

async function request<T>(
  path: string,
  token: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${BASE}/api/v1${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...init?.headers,
    },
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status} ${body}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  peers: {
    list: (token: string) =>
      request<{ peers: Peer[] }>('/peers', token),
    delete: (token: string, key: string) =>
      request<void>(`/peers/${encodeURIComponent(key)}`, token, { method: 'DELETE' }),
    setRoutes: (token: string, key: string, routes: string[]) =>
      request<{ peer: Peer }>(`/peers/${encodeURIComponent(key)}/routes`, token, {
        method: 'PUT',
        body: JSON.stringify({ routes }),
      }),
  },
  setupKeys: {
    list: (token: string) =>
      request<{ setup_keys: SetupKey[] }>('/setup-keys', token),
    create: (
      token: string,
      payload: { name: string; ephemeral?: boolean; expires_in_days?: number },
    ) =>
      request<{ setup_key: SetupKey }>('/setup-keys', token, {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    delete: (token: string, id: string) =>
      request<void>(`/setup-keys/${encodeURIComponent(id)}`, token, {
        method: 'DELETE',
      }),
  },
  health: () => fetch(`${BASE}/api/v1/health`).then(r => r.json()),
}
