'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { clsx } from 'clsx'
import { logout } from '@/lib/auth'
import { useRouter } from 'next/navigation'

const nav = [
  { label: 'Devices', href: '/dashboard', icon: '⬡' },
  { label: 'Setup Keys', href: '/dashboard/setup-keys', icon: '🔑' },
  { label: 'Access Rules', href: '/dashboard/acls', icon: '🛡' },
  { label: 'Settings', href: '/dashboard/settings', icon: '⚙' },
]

export function Sidebar() {
  const path = usePathname()
  const router = useRouter()

  const signOut = async () => {
    await logout()
    router.push('/login')
  }

  return (
    <aside className="w-56 bg-gray-900 text-white flex flex-col h-screen sticky top-0">
      <div className="px-6 py-5 border-b border-gray-700">
        <span className="text-xl font-bold tracking-tight">Meshnet</span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(item => (
          <Link
            key={item.href}
            href={item.href}
            className={clsx(
              'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
              path === item.href
                ? 'bg-brand-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-800',
            )}
          >
            <span className="text-base">{item.icon}</span>
            {item.label}
          </Link>
        ))}
      </nav>

      <div className="px-3 py-4 border-t border-gray-700">
        <button
          onClick={signOut}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
        >
          <span>↩</span> Sign out
        </button>
      </div>
    </aside>
  )
}
