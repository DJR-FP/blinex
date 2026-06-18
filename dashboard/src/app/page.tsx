import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'

export default function Home() {
  const token = cookies().get('meshnet_token')
  redirect(token ? '/dashboard' : '/login')
}
