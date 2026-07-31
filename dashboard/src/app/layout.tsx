import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Bline-X',
  description: 'Zero-trust mesh networking',
}

// Render per-request so the middleware's per-request CSP nonce is stamped onto
// Next.js's inline hydration scripts. Static prerendering can't carry a nonce,
// which leaves those scripts blocked by the CSP → blank page. This is an admin
// dashboard, so per-request rendering has no meaningful cost.
export const dynamic = 'force-dynamic'

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
