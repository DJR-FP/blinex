import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'

export default async function Home() {
  const token = (await cookies()).get('blinex_token')
  redirect(token ? '/dashboard' : '/login')
}
