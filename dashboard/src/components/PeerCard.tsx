'use client'

import { useState } from 'react'
import type { Peer } from '@/lib/api'
import { clsx } from 'clsx'

interface Props {
  peer: Peer
  onDelete: (key: string) => void
  onRoutesChange: (key: string, routes: string[]) => Promise<void>
}

export function PeerCard({ peer, onDelete, onRoutesChange }: Props) {
  const [showRoutes, setShowRoutes] = useState(false)
  const [newCIDR, setNewCIDR] = useState('')
  const [saving, setSaving] = useState(false)
  const [cidrError, setCIDRError] = useState('')

  const routes = peer.advertised_routes ?? []
  const isExitNode = routes.includes('0.0.0.0/0')
  const subnets = routes.filter(r => r !== '0.0.0.0/0')

  const save = async (newRoutes: string[]) => {
    setSaving(true)
    try {
      await onRoutesChange(peer.wg_pub_key, newRoutes)
    } finally {
      setSaving(false)
    }
  }

  const toggleExitNode = () =>
    save(isExitNode ? routes.filter(r => r !== '0.0.0.0/0') : [...routes, '0.0.0.0/0'])

  const addSubnet = async () => {
    const cidr = newCIDR.trim()
    if (!cidr) return
    // Basic CIDR validation (browser-side).
    if (!/^[\d./]+$/.test(cidr) || !cidr.includes('/')) {
      setCIDRError('Enter a valid CIDR like 192.168.1.0/24')
      return
    }
    setCIDRError('')
    await save([...routes, cidr])
    setNewCIDR('')
  }

  const removeRoute = (cidr: string) => save(routes.filter(r => r !== cidr))

  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5 hover:shadow-md transition-shadow">
      <div className="flex items-start gap-4">
        <div className={clsx(
          'w-3 h-3 rounded-full mt-1.5 flex-shrink-0',
          peer.connected ? 'bg-green-400' : 'bg-gray-300',
        )} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-semibold text-gray-900 truncate">{peer.hostname || 'Unknown'}</p>
            <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">{peer.os}</span>
            {isExitNode && (
              <span className="text-xs bg-orange-100 text-orange-600 px-2 py-0.5 rounded-full font-medium">
                Exit node
              </span>
            )}
          </div>
          <p className="text-sm text-gray-500 mt-0.5 font-mono">{peer.ip}</p>
          <p className="text-xs text-brand-500 mt-1">{peer.dns_label}.mesh</p>
          {subnets.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {subnets.map(r => (
                <span key={r} className="text-xs bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full font-mono">
                  {r}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <button
            onClick={() => setShowRoutes(true)}
            className="text-xs text-gray-400 hover:text-brand-500 transition-colors px-1 py-0.5"
            title="Manage routes"
          >
            Routes
          </button>
          <button
            onClick={() => onDelete(peer.wg_pub_key)}
            className="text-gray-300 hover:text-red-400 transition-colors p-1"
            title="Remove device"
          >
            ✕
          </button>
        </div>
      </div>

      {showRoutes && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-1">
              Routes — {peer.hostname || 'Unknown'}
            </h2>
            <p className="text-sm text-gray-500 mb-5">
              Configure which subnets this device advertises to the mesh network.
            </p>

            {/* Exit node toggle */}
            <div className="flex items-center justify-between p-4 bg-orange-50 rounded-xl mb-5">
              <div>
                <p className="text-sm font-semibold text-gray-900">Exit node</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  Route all internet traffic through this device (0.0.0.0/0)
                </p>
              </div>
              <button
                onClick={toggleExitNode}
                disabled={saving}
                className={clsx(
                  'relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50',
                  isExitNode ? 'bg-orange-500' : 'bg-gray-200',
                )}
                aria-pressed={isExitNode}
              >
                <span className={clsx(
                  'inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform',
                  isExitNode ? 'translate-x-6' : 'translate-x-1',
                )} />
              </button>
            </div>

            {/* Subnet routes */}
            <p className="text-sm font-semibold text-gray-700 mb-2">Subnet routes</p>

            {subnets.length === 0 ? (
              <p className="text-xs text-gray-400 mb-3">No subnet routes configured.</p>
            ) : (
              <div className="space-y-2 mb-3">
                {subnets.map(r => (
                  <div key={r} className="flex items-center justify-between bg-gray-50 rounded-lg px-3 py-2">
                    <span className="font-mono text-sm text-gray-700">{r}</span>
                    <button
                      onClick={() => removeRoute(r)}
                      disabled={saving}
                      className="text-gray-400 hover:text-red-500 transition-colors text-xs disabled:opacity-50"
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="flex gap-2 mb-1">
              <input
                type="text"
                placeholder="192.168.1.0/24"
                value={newCIDR}
                onChange={e => { setNewCIDR(e.target.value); setCIDRError('') }}
                onKeyDown={e => e.key === 'Enter' && addSubnet()}
                className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
              <button
                onClick={addSubnet}
                disabled={saving || !newCIDR.trim()}
                className="bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium px-4 py-2 rounded-lg disabled:opacity-40 transition-colors flex-shrink-0"
              >
                Add
              </button>
            </div>
            {cidrError && <p className="text-xs text-red-500 mb-3">{cidrError}</p>}

            <button
              onClick={() => setShowRoutes(false)}
              className="w-full mt-4 border border-gray-200 text-gray-700 font-medium py-2 rounded-xl text-sm hover:bg-gray-50 transition-colors"
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
