export default function ACLsPage() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Access Rules</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Control which devices can communicate with each other.
        </p>
      </div>

      <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-8 text-center text-gray-400">
        <p className="text-4xl mb-4">🔒</p>
        <p className="font-medium text-gray-700">Default policy: allow all</p>
        <p className="text-sm mt-1">All enrolled devices can reach each other. Add rules below to restrict access.</p>
        <button className="mt-6 bg-brand-500 hover:bg-brand-600 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors">
          + Add rule
        </button>
      </div>
    </div>
  )
}
