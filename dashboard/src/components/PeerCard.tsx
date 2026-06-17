import type { Peer } from '@/lib/api'
import { clsx } from 'clsx'

interface Props {
  peer: Peer
  onDelete: (key: string) => void
}

export function PeerCard({ peer, onDelete }: Props) {
  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5 flex items-start gap-4 hover:shadow-md transition-shadow">
      <div className={clsx(
        'w-3 h-3 rounded-full mt-1 flex-shrink-0',
        peer.connected ? 'bg-green-400' : 'bg-gray-300',
      )} />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="font-semibold text-gray-900 truncate">{peer.hostname || 'Unknown'}</p>
          <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">{peer.os}</span>
        </div>
        <p className="text-sm text-gray-500 mt-0.5 font-mono">{peer.ip}</p>
        <p className="text-xs text-brand-500 mt-1">{peer.dns_label}.mesh</p>
      </div>

      <button
        onClick={() => onDelete(peer.wg_pub_key)}
        className="text-gray-300 hover:text-red-400 transition-colors p-1 flex-shrink-0"
        title="Remove device"
      >
        ✕
      </button>
    </div>
  )
}
