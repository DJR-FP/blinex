'use client'

import { useState, useEffect, useCallback } from 'react'
import { api, Rule, RulePayload } from '@/lib/api'

const PROTOCOLS = ['all', 'tcp', 'udp', 'icmp']

const emptyForm = (): RulePayload => ({
  name: '',
  src: '*',
  dst: '*',
  protocol: 'all',
  port: 0,
  action: 'allow',
  enabled: true,
  priority: 100,
})

function TagOrIPInput({
  label,
  value,
  onChange,
  tags,
  placeholder,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  tags: string[]
  placeholder: string
}) {
  const mode = value === '*' ? 'any' : value.startsWith('tag:') ? 'tag' : 'ip'

  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <div className="flex gap-1 mb-1.5">
        {(['any', 'tag', 'ip'] as const).map(m => (
          <button
            key={m}
            type="button"
            onClick={() => {
              if (m === 'any') onChange('*')
              else if (m === 'tag') onChange(tags.length > 0 ? `tag:${tags[0]}` : 'tag:')
              else onChange('')
            }}
            className={`px-2 py-0.5 text-xs rounded font-medium transition-colors ${
              mode === m
                ? 'bg-brand-500 text-white'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {m === 'any' ? 'Any' : m === 'tag' ? 'Tag' : 'IP/CIDR'}
          </button>
        ))}
      </div>
      {mode === 'tag' ? (
        <select
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          value={value.replace('tag:', '')}
          onChange={e => onChange(`tag:${e.target.value}`)}
        >
          {tags.length === 0 && <option value="">No tags defined</option>}
          {tags.map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      ) : mode === 'ip' ? (
        <input
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          placeholder={placeholder}
          value={value}
          onChange={e => onChange(e.target.value)}
        />
      ) : null}
    </div>
  )
}

function RuleModal({
  initial,
  tags,
  onSave,
  onClose,
}: {
  initial?: Rule
  tags: string[]
  onSave: (p: RulePayload) => Promise<void>
  onClose: () => void
}) {
  const [form, setForm] = useState<RulePayload>(
    initial
      ? {
          name: initial.name,
          src: initial.src,
          dst: initial.dst,
          protocol: initial.protocol,
          port: initial.port,
          action: initial.action,
          enabled: initial.enabled,
          priority: initial.priority,
        }
      : emptyForm(),
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const set = <K extends keyof RulePayload>(k: K, v: RulePayload[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.name.trim()) { setError('Name is required'); return }
    setSaving(true)
    try {
      await onSave(form)
      onClose()
    } catch (err) {
      setError(String(err))
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg mx-4 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">
          {initial ? 'Edit rule' : 'New rule'}
        </h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
            <input
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="e.g. Allow web to database"
              value={form.name}
              onChange={e => set('name', e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <TagOrIPInput
              label="Source"
              value={form.src}
              onChange={v => set('src', v)}
              tags={tags}
              placeholder="100.64.0.1 or CIDR"
            />
            <TagOrIPInput
              label="Destination"
              value={form.dst}
              onChange={v => set('dst', v)}
              tags={tags}
              placeholder="100.64.0.2 or CIDR"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Protocol</label>
              <select
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                value={form.protocol}
                onChange={e => set('protocol', e.target.value)}
              >
                {PROTOCOLS.map(p => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Port <span className="text-gray-400 font-normal">(0 = any)</span>
              </label>
              <input
                type="number"
                min={0}
                max={65535}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                value={form.port ?? 0}
                onChange={e => set('port', parseInt(e.target.value) || 0)}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Action</label>
              <select
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                value={form.action}
                onChange={e => set('action', e.target.value as 'allow' | 'deny')}
              >
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Priority <span className="text-gray-400 font-normal">(lower = first)</span>
              </label>
              <input
                type="number"
                min={0}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                value={form.priority ?? 100}
                onChange={e => set('priority', parseInt(e.target.value) || 0)}
              />
            </div>
          </div>

          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              className="accent-brand-500 w-4 h-4"
              checked={form.enabled}
              onChange={e => set('enabled', e.target.checked)}
            />
            <span className="text-sm text-gray-700">Enabled</span>
          </label>

          {error && <p className="text-sm text-red-600">{error}</p>}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm font-medium text-white bg-brand-500 hover:bg-brand-600 rounded-lg disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function formatSrcDst(val: string) {
  if (val.startsWith('tag:')) {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 text-xs font-medium">
          {val}
        </span>
      </span>
    )
  }
  return <span className="font-mono text-gray-600">{val}</span>
}

export default function ACLsPage() {
  const [rules, setRules] = useState<Rule[]>([])
  const [tags, setTags] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [modal, setModal] = useState<{ open: boolean; editing?: Rule }>({ open: false })

  const fetchData = useCallback(async () => {
    try {
      const [rulesData, tagsData] = await Promise.all([
        api.rules.list(),
        api.tags.list(),
      ])
      setRules(rulesData.rules ?? [])
      setTags(tagsData.tags ?? [])
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchData() }, [fetchData])

  const handleSave = async (payload: RulePayload) => {
    if (modal.editing) {
      await api.rules.update(modal.editing.id, payload)
    } else {
      await api.rules.create(payload)
    }
    await fetchData()
  }

  const handleToggle = async (rule: Rule) => {
    try {
      await api.rules.update(rule.id, { enabled: !rule.enabled })
      await fetchData()
    } catch (err) {
      setError(String(err))
    }
  }

  const handleDelete = async (rule: Rule) => {
    if (!confirm(`Delete rule "${rule.name}"?`)) return
    try {
      await api.rules.delete(rule.id)
      await fetchData()
    } catch (err) {
      setError(String(err))
    }
  }

  const sortedRules = [...rules].sort((a, b) => a.priority - b.priority)

  return (
    <div>
      <div className="mb-8 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Access Rules</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Control which devices can communicate. Use tags (e.g. <code className="text-xs bg-gray-100 px-1 rounded">tag:servers</code>) or IPs. Rules evaluated in priority order.
          </p>
        </div>
        <button
          onClick={() => setModal({ open: true })}
          className="bg-brand-500 hover:bg-brand-600 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors"
        >
          + Add rule
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-center text-gray-400 py-12">Loading…</div>
      ) : sortedRules.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-8 text-center text-gray-400">
          <p className="font-medium text-gray-700">Default policy: allow all</p>
          <p className="text-sm mt-1">
            All enrolled devices can reach each other. Add rules with tags to restrict access.
          </p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide w-8">
                  #
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Name
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Source
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Destination
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Protocol
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Port
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Action
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Enabled
                </th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {sortedRules.map(rule => (
                <tr key={rule.id} className={`hover:bg-gray-50 transition-colors ${!rule.enabled ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3 text-gray-400">{rule.priority}</td>
                  <td className="px-4 py-3 font-medium text-gray-900">{rule.name}</td>
                  <td className="px-4 py-3">{formatSrcDst(rule.src)}</td>
                  <td className="px-4 py-3">{formatSrcDst(rule.dst)}</td>
                  <td className="px-4 py-3 text-gray-600">{rule.protocol}</td>
                  <td className="px-4 py-3 text-gray-600">{rule.port === 0 ? 'any' : rule.port}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${
                        rule.action === 'allow'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-red-100 text-red-700'
                      }`}
                    >
                      {rule.action}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggle(rule)}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                        rule.enabled ? 'bg-brand-500' : 'bg-gray-200'
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          rule.enabled ? 'translate-x-4' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 justify-end">
                      <button
                        onClick={() => setModal({ open: true, editing: rule })}
                        className="text-gray-400 hover:text-gray-600 text-xs underline"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(rule)}
                        className="text-red-400 hover:text-red-600 text-xs underline"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {modal.open && (
        <RuleModal
          initial={modal.editing}
          tags={tags}
          onSave={handleSave}
          onClose={() => setModal({ open: false })}
        />
      )}
    </div>
  )
}
