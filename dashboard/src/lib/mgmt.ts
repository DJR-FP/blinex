import { Agent, type Dispatcher } from 'undici'

// Base URL of the management API (server-side only).
export const MGMT_URL = process.env.MGMT_API_URL ?? 'https://localhost:8080'

// When MGMT_TLS_SKIP_VERIFY=true (self-signed control-plane certs) we skip TLS
// verification — but SCOPED to this management client via a dedicated undici
// dispatcher, NOT the process-wide NODE_TLS_REJECT_UNAUTHORIZED=0 that used to
// be set here (which disabled verification for every outbound TLS request the
// dashboard process makes).
const insecureDispatcher: Dispatcher | undefined =
  process.env.MGMT_TLS_SKIP_VERIFY === 'true'
    ? new Agent({ connect: { rejectUnauthorized: false } })
    : undefined

// mgmtFetch calls the management API, applying the scoped TLS policy. `path` may
// be an absolute URL or a path (prefixed with MGMT_URL).
export function mgmtFetch(path: string, init?: RequestInit): Promise<Response> {
  const url = path.startsWith('http') ? path : `${MGMT_URL}${path}`
  if (!insecureDispatcher) {
    return fetch(url, init)
  }
  // `dispatcher` is a valid undici fetch option but isn't in the DOM RequestInit type.
  return fetch(url, { ...init, dispatcher: insecureDispatcher } as RequestInit)
}
