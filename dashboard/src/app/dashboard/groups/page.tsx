'use client'

import { useEffect, useState, useCallback } from 'react'
import { api, type Group } from '@/lib/api'

export default function GroupsPage() {
  const [groups, setGroups] = useState<Group[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [newGroupName, setNewGroupName] = useState('')
  const [showCreate, setShowCreate] = useState(false)

  const load = useCallback(async () => {
    try {
      const data = await api.groups.list()
      setGroups(data.groups ?? [])
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newGroupName.trim()) return
    setCreating(true)
    setError('')
    try {
      const data = await api.groups.create({ name: newGroupName.trim() })
      setGroups(prev => [...prev, data.group])
      setNewGroupName('')
      setShowCreate(false)
    } catch (e) {
      setError(String(e))
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (g: Group) => {
    if (!confirm(`Delete group "${g.name}"? Devices in it will just lose that membership — nothing else is affected.`)) return
    try {
      await api.groups.delete(g.id)
      setGroups(prev => prev.filter(x => x.id !== g.id))
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Groups</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Every device is always in <span className="font-medium text-gray-700">Default</span>. Setup keys can drop new devices
            straight into other groups too — use them in Access Rules to control who can reach what.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="bg-brand-500 hover:bg-brand-600 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
        >
          + Create group
        </button>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 rounded-xl p-4 text-sm mb-4">{error}</div>
      )}

      {showCreate && (
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 mb-6">
          <h2 className="font-semibold text-gray-900 mb-4">Create group</h2>
          <form onSubmit={handleCreate} className="flex items-end gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
              <input
                type="text"
                value={newGroupName}
                onChange={e => setNewGroupName(e.target.value)}
                placeholder="e.g. web, database, engineering"
                className="w-64 px-4 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                required
              />
            </div>
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
          </form>
        </div>
      )}

      {loading && <div className="text-gray-400 text-sm">Loading…</div>}

      {!loading && groups.length === 0 && (
        <div className="text-center py-16 text-gray-400">
          <p className="font-medium">No groups yet</p>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-100">
            <tr>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Name</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Devices</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">Created</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {groups.map(g => (
              <tr key={g.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1.5 font-medium text-gray-900">
                    {g.name}
                    {g.name === 'Default' && (
                      <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full font-normal">
                        every device
                      </span>
                    )}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-600">{g.peer_count}</td>
                <td className="px-4 py-3 text-gray-400">{new Date(g.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-3 text-right">
                  {g.name !== 'Default' && (
                    <button
                      onClick={() => handleDelete(g)}
                      className="text-red-400 hover:text-red-600 text-xs underline"
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
