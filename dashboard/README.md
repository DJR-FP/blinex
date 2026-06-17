# dashboard

Web UI for Meshnet. Built with Next.js 14 (App Router), TypeScript, and Tailwind CSS.

## Pages

| Route | Description |
|---|---|
| `/login` | Paste JWT token to authenticate |
| `/dashboard` | Device grid — live list of enrolled peers, 10s auto-refresh |
| `/dashboard/setup-keys` | Create, list, copy, and revoke setup keys |
| `/dashboard/acls` | Access rule editor (scaffold — coming soon) |
| `/dashboard/settings` | Network settings (CIDR, DNS suffix) |

## Authentication

The dashboard uses a JWT stored in `localStorage`. The token is obtained from the agent on first enrollment (printed to stdout, also returned in the `Login` gRPC response). Paste it into the login page.

There is no built-in login form for username/password — auth is token-based. OIDC is planned for Phase 3.

## Environment variables

| Var | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_MGMT_API` | `http://localhost:8080` | Base URL of the management REST API |

Set this at build time (docker build arg) or at runtime via `.env.local`.

## Development

```bash
npm install
npm run dev      # http://localhost:3000  (hot reload)
npm run build    # production build
npx tsc --noEmit # type check only
```

## Project layout

```
dashboard/
├── src/
│   ├── app/
│   │   ├── layout.tsx              Root layout (font, metadata)
│   │   ├── page.tsx                Redirects / → /login or /dashboard
│   │   ├── login/page.tsx          Token login page
│   │   └── dashboard/
│   │       ├── layout.tsx          Auth guard + sidebar
│   │       ├── page.tsx            Devices page
│   │       ├── setup-keys/page.tsx Setup keys CRUD
│   │       ├── acls/page.tsx       Access rules (scaffold)
│   │       └── settings/page.tsx   Network settings
│   ├── components/
│   │   ├── Sidebar.tsx            Navigation sidebar
│   │   └── PeerCard.tsx          Device card (name, IP, DNS label, status dot)
│   └── lib/
│       ├── api.ts                  REST client for peers + setup keys
│       └── auth.ts                 localStorage token management
├── public/
├── tailwind.config.ts
└── next.config.ts
```
