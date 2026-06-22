'use client'

import { useEffect, useState, useCallback } from 'react'
import { api, type Peer } from '@/lib/api'
import { PeerCard } from '@/components/PeerCard'

export default function DevicesPage() {
  const [peers, setPeers] = useState<Peer[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showInstall, setShowInstall] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.peers.list()
      setPeers(data.peers ?? [])
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, 10_000)
    return () => clearInterval(interval)
  }, [load])

  const handleDelete = async (key: string) => {
    await api.peers.delete(key)
    setPeers(prev => prev.filter(p => p.wg_pub_key !== key))
  }

  const handleRoutesChange = async (key: string, routes: string[]) => {
    const resp = await api.peers.setRoutes(key, routes)
    setPeers(prev => prev.map(p => p.wg_pub_key === key ? { ...p, advertised_routes: routes, ...resp.peer } : p))
  }

  const handleTagsChange = async (key: string, tags: string[]) => {
    const updated = await api.peers.update(key, { tags })
    setPeers(prev => prev.map(p => p.wg_pub_key === key ? { ...p, tags: updated.tags } : p))
  }

  const connected = peers.filter(p => p.connected).length
  const installCmd = `curl -fsSL https://install.blinex.co.uk/agent | BLINEX_SETUP_KEY=<your-key> bash`

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Devices</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {connected} of {peers.length} connected
          </p>
        </div>
        <button
          className="bg-brand-500 hover:bg-brand-600 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
          onClick={() => setShowInstall(true)}
        >
          + Add device
        </button>
      </div>

      {showInstall && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-lg p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-1">Add a device</h2>
            <p className="text-sm text-gray-500 mb-4">
              Run this command on the device you want to enroll. Get a setup key from the
              <strong> Setup Keys</strong> page.
            </p>
            <pre className="bg-gray-900 text-green-400 rounded-xl p-4 text-xs font-mono whitespace-pre-wrap break-all select-all">
              {installCmd}
            </pre>
            <p className="text-xs text-gray-400 mt-3 mb-4">
              Replace <code className="bg-gray-100 px-1 rounded">&lt;your-key&gt;</code> with a key from the Setup Keys page.
            </p>
            <button
              onClick={() => setShowInstall(false)}
              className="w-full border border-gray-200 text-gray-700 font-medium py-2 rounded-xl text-sm hover:bg-gray-50 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {loading && <div className="text-gray-400 text-sm">Loading…</div>}
      {error && <div className="bg-red-50 text-red-600 rounded-xl p-4 text-sm">{error}</div>}

      {!loading && peers.length === 0 && (
        <div className="text-center py-20 text-gray-400">
          <p className="text-4xl mb-4">⬡</p>
          <p className="font-medium">No devices yet</p>
          <p className="text-sm mt-1">Click <strong>Add device</strong> to enroll your first device.</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {peers.map(p => (
          <PeerCard key={p.wg_pub_key} peer={p} onDelete={handleDelete} onRoutesChange={handleRoutesChange} onTagsChange={handleTagsChange} />
        ))}
      </div>
    </div>
  )
}
