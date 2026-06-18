// POST the token to our API route which validates it and sets an HttpOnly cookie.
export async function login(token: string): Promise<void> {
  const res = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error((data as { error?: string }).error ?? 'Login failed')
  }
}

// Clear the HttpOnly cookie via the API route.
export async function logout(): Promise<void> {
  await fetch('/api/auth', { method: 'DELETE' })
}
