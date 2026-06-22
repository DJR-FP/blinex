import { NextRequest, NextResponse } from 'next/server'

if (process.env.MGMT_TLS_SKIP_VERIFY === 'true') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
}

const MGMT_URL = process.env.MGMT_API_URL ?? 'https://localhost:8080'

export async function POST(req: NextRequest) {
  let username: string | undefined
  let password: string | undefined
  try {
    const body = await req.json()
    username = body?.username
    password = body?.password
  } catch {
    return NextResponse.json({ error: 'invalid request body' }, { status: 400 })
  }

  if (!username || !password) {
    return NextResponse.json({ error: 'username and password required' }, { status: 400 })
  }

  let token: string | undefined
  try {
    const upstream = await fetch(`${MGMT_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!upstream.ok) {
      const data = await upstream.json().catch(() => ({}))
      return NextResponse.json(
        { error: (data as { error?: string }).error ?? 'invalid credentials' },
        { status: upstream.status },
      )
    }
    const data = await upstream.json()
    token = data?.token
  } catch {
    return NextResponse.json({ error: 'cannot reach management server' }, { status: 502 })
  }

  if (!token) {
    return NextResponse.json({ error: 'no token returned' }, { status: 500 })
  }

  const response = NextResponse.json({ ok: true })
  response.cookies.set('blinex_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'lax',
    maxAge: 60 * 60 * 24,
    path: '/',
  })
  return response
}
