/** @type {import('next').NextConfig} */

// Static security headers applied to every response. The Content-Security-Policy
// is intentionally NOT here: it needs a per-request nonce so Next.js can run its
// own inline hydration scripts (a static `script-src 'self'` blocks them and
// leaves the page blank). The CSP is set in middleware.ts instead.
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=()',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
];

const nextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  env: {
    NEXT_PUBLIC_MGMT_API: process.env.NEXT_PUBLIC_MGMT_API || 'http://localhost:8080',
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

module.exports = nextConfig;
