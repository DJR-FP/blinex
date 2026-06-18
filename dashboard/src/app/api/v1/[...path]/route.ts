import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'

if (process.env.MGMT_TLS_VERIFY !== 'true') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
}

const MGMT_URL = process.env.MGMT_API_URL ?? 'https://localhost:8080'

async function proxy(req: NextRequest, segments: string[]): Promise<NextResponse> {
  const cookieStore = cookies()
  const token = cookieStore.get('meshnet_token')?.value
  if (!token) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  const path = segments.join('/')
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

type Ctx = { params: { path: string[] } }

export const GET = (req: NextRequest, ctx: Ctx) => proxy(req, ctx.params.path)
export const POST = (req: NextRequest, ctx: Ctx) => proxy(req, ctx.params.path)
export const PUT = (req: NextRequest, ctx: Ctx) => proxy(req, ctx.params.path)
export const DELETE = (req: NextRequest, ctx: Ctx) => proxy(req, ctx.params.path)
