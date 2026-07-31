import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(req: NextRequest) {
  // Auth gate for the dashboard.
  const token = req.cookies.get('blinex_token')
  if (!token && req.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', req.url))
  }

  // Per-request CSP nonce. Next.js emits inline bootstrap/hydration scripts
  // (self.__next_f.push(...)); a static `script-src 'self'` blocks them, which
  // leaves the page blank after the SSR flash. A nonce lets exactly those
  // scripts run without opening the door to 'unsafe-inline'. Next.js reads the
  // nonce from the request's Content-Security-Policy header and stamps it onto
  // every script tag it renders.
  const nonce = btoa(crypto.randomUUID())
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join('; ')

  const requestHeaders = new Headers(req.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('content-security-policy', csp)

  const res = NextResponse.next({ request: { headers: requestHeaders } })
  res.headers.set('content-security-policy', csp)
  return res
}

export const config = {
  // Run on page routes so the CSP + nonce attaches to rendered HTML. Skip
  // static assets and API routes (no inline scripts to nonce there).
  matcher: [
    {
      source:
        '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|txt)$).*)',
    },
  ],
}
