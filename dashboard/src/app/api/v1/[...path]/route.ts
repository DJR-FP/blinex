import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'

// Only skip TLS verification when explicitly opted in (self-signed certs).
if (process.env.MGMT_TLS_SKIP_VERIFY === 'true') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
}

const MGMT_URL = process.env.MGMT_API_URL ?? 'https://localhost:8080'

async function proxy(req: NextRequest): Promise<NextResponse> {
  const cookieStore = cookies()
  const token = cookieStore.get('blinex_token')?.value
  if (!token) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  // Use the raw, still percent-encoded path. The catch-all params decode
  // %2F into a literal '/', which would split base64 WireGuard keys and
  // break the upstream route. nextUrl.pathname preserves the encoding.
  const path = req.nextUrl.pathname.replace(/^\/api\/v1\//, '')
  const url = `${MGMT_URL}/api/v1/${path}${req.nextUrl.search}`

  const body =
    req.method !== 'GET' && req.method !== 'HEAD' ? await req.text() : undefined

  let upstream: Response
  try {
    upstream = await fetch(url, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body,
    })
  } catch (err) {
    return NextResponse.json({ error: 'management server unreachable' }, { status: 502 })
  }

  if (upstream.status === 204) {
    return new NextResponse(null, { status: 204 })
  }

  const data = await upstream.json().catch(() => null)
  return NextResponse.json(data, { status: upstream.status })
}

export const GET = (req: NextRequest) => proxy(req)
export const POST = (req: NextRequest) => proxy(req)
export const PUT = (req: NextRequest) => proxy(req)
export const DELETE = (req: NextRequest) => proxy(req)
