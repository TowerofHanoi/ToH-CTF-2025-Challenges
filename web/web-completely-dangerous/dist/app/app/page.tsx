'use client'

import Navigation from '@/components/Navigation'
import { useAuth } from '@/contexts/AuthContext'

export default function Home() {
  const { user, loading } = useAuth()

  return (
    <div className="container">
      <Navigation />
      
      <div className="welcome">
        <h1>Demo</h1>
        <p>A Next.js app demonstrating authentication and user settings</p>
      </div>
      
      <div className="card">
        <div style={{ textAlign: 'center', padding: '2rem 0' }}>
          {loading ? (
            <p>Loading...</p>
          ) : user ? (
            <>
              <h2>Welcome!</h2>
              <p>You are logged in. Use the navigation above to access your dashboard and settings.</p>
            </>
          ) : (
            <>
              <h2>Welcome!</h2>
              <p>Please log in or register to access protected features.</p>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
