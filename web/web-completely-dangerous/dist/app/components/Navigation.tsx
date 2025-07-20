'use client'

import Link from 'next/link'
import { useAuth } from '@/contexts/AuthContext'
import { useRouter } from 'next/navigation'

export default function Navigation() {
  const { user, logout, loading } = useAuth()
  const router = useRouter()

  const handleLogout = async () => {
    await logout()
    router.push('/')
  }

  if (loading) {
    return (
      <nav className="navigation">
        <div className="nav-links">
          <span>Loading...</span>
        </div>
      </nav>
    )
  }

  return (
    <nav className="navigation">
      <div className="nav-links">
        <Link href="/">Home</Link>
        
        {user ? (
          <>
            <Link href="/dashboard">Dashboard</Link>
            <Link href="/settings">Settings</Link>
            <span className="user-info">Welcome, {user.username}!</span>
            <button onClick={handleLogout} className="logout-btn">
              Logout
            </button>
          </>
        ) : (
          <>
            <Link href="/login">Login</Link>
            <Link href="/register">Register</Link>
          </>
        )}
      </div>
    </nav>
  )
}
