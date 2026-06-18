export default function SettingsPage() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
      </div>

      <div className="space-y-6 max-w-2xl">
        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-6">
          <h2 className="font-semibold text-gray-900 mb-4">Network</h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">CIDR block</span>
              <span className="font-mono text-gray-900">100.64.0.0/10</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Magic DNS suffix</span>
              <span className="font-mono text-gray-900">.mesh</span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-6">
          <h2 className="font-semibold text-gray-900 mb-4">Setup Keys</h2>
          <p className="text-sm text-gray-500">
            Setup keys are used to enroll new devices. Manage and rotate keys from the{' '}
            <a href="/dashboard/keys" className="text-brand-500 underline">Setup Keys</a> page.
            The active key is printed to the server log on first startup — never share it publicly.
          </p>
        </div>
      </div>
    </div>
  )
}
