import { NextRequest, NextResponse } from 'next/server'

if (process.env.MGMT_TLS_SKIP_VERIFY === 'true') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
}

const MGMT_URL = process.env.MGMT_API_URL ?? 'https://localhost:8080'

export async function POST(req: NextRequest) {
  let token: string | undefined
  try {
    const body = await req.json()
    token = body?.token
  } catch {
    return NextResponse.json({ error: 'invalid request body' }, { status: 400 })
  }

  if (!token || typeof token !== 'string' || token.trim() === '') {
    return NextResponse.json({ error: 'missing token' }, { status: 400 })
  }

  // Validate the token against the management server before issuing a cookie.
  let valid = false
  try {
    const check = await fetch(`${MGMT_URL}/api/v1/peers`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    valid = check.ok
  } catch {
    return NextResponse.json({ error: 'cannot reach management server' }, { status: 502 })
  }

  if (!valid) {
    return NextResponse.json({ error: 'invalid token' }, { status: 401 })
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

export async function DELETE() {
  const response = NextResponse.json({ ok: true })
  response.cookies.delete('blinex_token')
  return response
}
