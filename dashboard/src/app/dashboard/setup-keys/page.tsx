'use client'

import { useEffect, useState, useCallback } from 'react'
import { api, type SetupKey } from '@/lib/api'
import { getToken } from '@/lib/auth'

export default function SetupKeysPage() {
  const [keys, setKeys] = useState<SetupKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyEphemeral, setNewKeyEphemeral] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)

  const load = useCallback(async () => {
    const token = getToken()
    if (!token) return
    try {
      const data = await api.setupKeys.list(token)
      setKeys(data.setup_keys ?? [])
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const token = getToken()
    if (!token || !newKeyName) return
    setCreating(true)
    try {
      const data = await api.setupKeys.create(token, {
        name: newKeyName,
        ephemeral: newKeyEphemeral,
        expires_in_days: 365,
      })
      setKeys(prev => [data.setup_key, ...prev])
      setNewKeyName('')
      setShowCreate(false)
    } catch (e) {
      setError(String(e))
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (id: string) => {
    const token = getToken()
    if (!token) return
    try {
      await api.setupKeys.delete(token, id)
      setKeys(prev => prev.filter(k => k.id !== id))
    } catch (e) {
      setError(String(e))
    }
  }

  const handleCopy = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopied(key)
    setTimeout(() => setCopied(null), 2000)
  }

  const isExpired = (expiresAt: string) => new Date(expiresAt) < new Date()

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Setup Keys</h1>
          <p className="text-sm text-gray-500 mt-0.5">Enroll new devices to your network</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="bg-brand-500 hover:bg-brand-600 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
        >
          + Create key
        </button>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 rounded-xl p-4 text-sm mb-4">{error}</div>
      )}

      {showCreate && (
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 mb-6">
          <h2 className="font-semibold text-gray-900 mb-4">Create setup key</h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
              <input
                type="text"
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                placeholder="e.g. office-servers"
                className="w-full max-w-sm px-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                required
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="ephemeral"
                checked={newKeyEphemeral}
                onChange={e => setNewKeyEphemeral(e.target.checked)}
                className="rounded border-gray-300"
              />
              <label htmlFor="ephemeral" className="text-sm text-gray-700">
                Ephemeral (one-time use)
              </label>
            </div>
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={creating}
                className="bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
              >
                {creating ? 'Creating…' : 'Create'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="text-gray-600 hover:text-gray-800 font-medium px-4 py-2 rounded-lg text-sm border border-gray-200 transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {loading && <div className="text-gray-400 text-sm">Loading…</div>}

      {!loading && keys.length === 0 && (
        <div className="text-center py-16 text-gray-400">
          <p className="font-medium">No setup keys</p>
          <p className="text-sm mt-1">Create a key to start enrolling devices.</p>
        </div>
      )}

      <div className="space-y-3">
        {keys.map(k => (
          <div key={k.id} className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-semibold text-gray-900">{k.name}</span>
                  {k.ephemeral && (
                    <span className="text-xs bg-purple-50 text-purple-600 px-2 py-0.5 rounded-full">
                      Ephemeral
                    </span>
                  )}
                  {isExpired(k.expires_at) && (
                    <span className="text-xs bg-red-50 text-red-500 px-2 py-0.5 rounded-full">
                      Expired
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <code className="text-xs font-mono bg-gray-50 px-3 py-1.5 rounded-lg text-gray-700 truncate max-w-xs">
                    {k.key}
                  </code>
                  <button
                    onClick={() => handleCopy(k.key)}
                    className="text-xs text-brand-500 hover:text-brand-600 font-medium whitespace-nowrap"
                  >
                    {copied === k.key ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <p className="text-xs text-gray-400 mt-2">
                  Used {k.used_count}× · Expires {new Date(k.expires_at).toLocaleDateString()}
                </p>
              </div>
              <button
                onClick={() => handleDelete(k.id)}
                className="text-red-400 hover:text-red-600 text-sm font-medium shrink-0 transition-colors"
              >
                Revoke
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
