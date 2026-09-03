'use client'

import { useState } from 'react'
import type { Peer } from '@/lib/api'
import { api } from '@/lib/api'
import { clsx } from 'clsx'

const DEFAULT_GROUP = 'Default'

interface Props {
  peer: Peer
  onDelete: (key: string) => void
  onRoutesChange: (key: string, routes: string[]) => Promise<void>
  onGroupsChange: (key: string, groups: string[]) => Promise<void>
  onRename: (key: string, hostname: string) => Promise<void>
}

export function PeerCard({ peer, onDelete, onRoutesChange, onGroupsChange, onRename }: Props) {
  const [showRoutes, setShowRoutes] = useState(false)
  const [showGroups, setShowGroups] = useState(false)
  const [newCIDR, setNewCIDR] = useState('')
  const [newGroup, setNewGroup] = useState('')
  const [saving, setSaving] = useState(false)
  const [cidrError, setCIDRError] = useState('')
  const [editingName, setEditingName] = useState(false)
  const [nameDraft, setNameDraft] = useState(peer.hostname)
  const [nameError, setNameError] = useState('')

  const startEditingName = () => {
    setNameDraft(peer.hostname)
    setNameError('')
    setEditingName(true)
  }

  const saveName = async () => {
    const trimmed = nameDraft.trim()
    if (trimmed === peer.hostname) {
      setEditingName(false)
      return
    }
    if (!trimmed) {
      setNameError('Name cannot be empty')
      return
    }
    if (trimmed.length > 63) {
      setNameError('Name must be 63 characters or fewer')
      return
    }
    setSaving(true)
    try {
      await onRename(peer.wg_pub_key, trimmed)
      setEditingName(false)
    } catch (e) {
      setNameError(String(e))
    } finally {
      setSaving(false)
    }
  }

  const routes = peer.advertised_routes ?? []
  const groups = peer.groups ?? []
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
    if (!/^[\d./]+$/.test(cidr) || !cidr.includes('/')) {
      setCIDRError('Enter a valid CIDR like 192.168.1.0/24')
      return
    }
    setCIDRError('')
    await save([...routes, cidr])
    setNewCIDR('')
  }

  const removeRoute = (cidr: string) => save(routes.filter(r => r !== cidr))

  const addGroup = async () => {
    const group = newGroup.trim().replace(/[^a-zA-Z0-9_-]/g, '')
    if (!group || groups.includes(group)) return
    setSaving(true)
    try {
      await onGroupsChange(peer.wg_pub_key, [...groups, group])
    } finally {
      setSaving(false)
    }
    setNewGroup('')
  }

  // Default can't be removed here — the server re-adds it if a request
  // omits it, so trying would just silently revert; the "Remove" control is
  // hidden for it instead (see the modal below).
  const removeGroup = async (group: string) => {
    setSaving(true)
    try {
      await onGroupsChange(peer.wg_pub_key, groups.filter(g => g !== group))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5 hover:shadow-md transition-shadow">
      <div className="flex items-start gap-4">
        <div className={clsx(
          'w-3 h-3 rounded-full mt-1.5 flex-shrink-0',
          peer.connected ? 'bg-green-400' : 'bg-gray-300',
        )} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {editingName ? (
              <div className="flex items-center gap-1">
                <input
                  type="text"
                  autoFocus
                  value={nameDraft}
                  onChange={e => { setNameDraft(e.target.value); setNameError('') }}
                  onKeyDown={e => {
                    if (e.key === 'Enter') saveName()
                    if (e.key === 'Escape') setEditingName(false)
                  }}
                  onBlur={saveName}
                  disabled={saving}
                  className="font-semibold text-gray-900 border border-brand-300 rounded px-1.5 py-0.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500 disabled:opacity-50"
                />
              </div>
            ) : (
              <button
                onClick={startEditingName}
                className="font-semibold text-gray-900 truncate hover:text-brand-600 transition-colors flex items-center gap-1 group"
                title="Rename device"
              >
                {peer.hostname || 'Unknown'}
                <span className="opacity-0 group-hover:opacity-100 text-gray-300 text-xs transition-opacity">✎</span>
              </button>
            )}
            <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">{peer.os}</span>
            {peer.version && (
              <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full font-mono">
                v{peer.version.replace(/^v/i, '')}
              </span>
            )}
            {isExitNode && (
              <span className="text-xs bg-orange-100 text-orange-600 px-2 py-0.5 rounded-full font-medium">
                Exit node
              </span>
            )}
          </div>
          {nameError && <p className="text-xs text-red-500 mt-0.5">{nameError}</p>}
          <p className="text-sm text-gray-500 mt-0.5 font-mono">{peer.ip} <span className="text-gray-300">(overlay)</span></p>
          {(peer.local_ip || peer.public_ip) && (
            <p className="text-xs text-gray-400 mt-0.5 font-mono">
              {peer.local_ip && <>local {peer.local_ip}</>}
              {peer.local_ip && peer.public_ip && ' · '}
              {peer.public_ip && <>public {peer.public_ip}</>}
              {peer.country && <> ({peer.country})</>}
            </p>
          )}
          <p className="text-xs text-brand-500 mt-1">{peer.dns_label}.blinex</p>
          {groups.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {groups.map(g => (
                <span key={g} className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full font-medium">
                  {g}
                </span>
              ))}
            </div>
          )}
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
            onClick={() => setShowGroups(true)}
            className="text-xs text-gray-400 hover:text-brand-500 transition-colors px-1 py-0.5"
            title="Manage groups"
          >
            Groups
          </button>
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

      {showGroups && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-1">
              Groups — {peer.hostname || 'Unknown'}
            </h2>
            <p className="text-sm text-gray-500 mb-5">
              Groups are used in access rules to control what can reach what (e.g. <code className="bg-gray-100 px-1 rounded text-xs">group:servers</code>).
              Every device is always in <span className="font-medium">{DEFAULT_GROUP}</span>.
            </p>

            <div className="flex flex-wrap gap-2 mb-3">
              {groups.map(g => (
                <span key={g} className="inline-flex items-center gap-1 bg-blue-100 text-blue-700 px-2.5 py-1 rounded-full text-sm font-medium">
                  {g}
                  {g !== DEFAULT_GROUP && (
                    <button
                      onClick={() => removeGroup(g)}
                      disabled={saving}
                      className="text-blue-400 hover:text-red-500 transition-colors disabled:opacity-50"
                    >
                      ✕
                    </button>
                  )}
                </span>
              ))}
            </div>

            <div className="flex gap-2 mb-1">
              <input
                type="text"
                placeholder="e.g. servers, database, web"
                value={newGroup}
                onChange={e => setNewGroup(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addGroup()}
                className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
              <button
                onClick={addGroup}
                disabled={saving || !newGroup.trim()}
                className="bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium px-4 py-2 rounded-lg disabled:opacity-40 transition-colors flex-shrink-0"
              >
                Add
              </button>
            </div>

            <button
              onClick={() => setShowGroups(false)}
              className="w-full mt-4 border border-gray-200 text-gray-700 font-medium py-2 rounded-xl text-sm hover:bg-gray-50 transition-colors"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {showRoutes && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6">
            <h2 className="text-lg font-bold text-gray-900 mb-1">
              Routes — {peer.hostname || 'Unknown'}
            </h2>
            <p className="text-sm text-gray-500 mb-5">
              Configure which subnets this device advertises to the mesh network.
            </p>

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
