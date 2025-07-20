'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Navigation from '@/components/Navigation'
import { useAuth } from '@/contexts/AuthContext'

import type { UserSettings } from '@/lib/database'

export default function Dashboard() {
  const [userSettings, setUserSettings] = useState<UserSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()
  const { user } = useAuth()

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }

    const loadUserSettings = async () => {
      try {
        const settingsResponse = await fetch('/api/settings', {
          credentials: 'include'
        })
        if (settingsResponse.ok) {
          const settingsData = await settingsResponse.json()
          setUserSettings(settingsData.settings)
        }
      } catch (error) {
        console.error('Failed to load user settings:', error)
      } finally {
        setLoading(false)
      }
    }

    loadUserSettings()
  }, [user, router])

  if (loading || !user) {
    return (
      <div className="container">
        <Navigation />
        <div className="card">
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            Loading{user ? ' user settings...' : '...'}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="container">
      <Navigation />
      
      <div className="welcome">
        <h1>Dashboard</h1>
      </div>
      
      <div className="card">
        <div className="dashboard">
          <div className="user-info">
            <div className="user-details">
              <div className="user-avatar">
                <h2>Welcome, {userSettings?.displayName?.children || user.username}!</h2>
                <p>User ID: {user.id}</p>
                <p>Username: {user.username}</p>
                {userSettings?.displayName && (
                  <p>Display Name: <span {...userSettings.displayName}></span></p>
                )}
              </div>
            </div>
            <p style={{ marginTop: '1rem' }}>You are successfully logged in with a persistent session.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
