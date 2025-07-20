'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Navigation from '@/components/Navigation'
import { useAuth } from '@/contexts/AuthContext'
import type { UserSettings } from '@/lib/database'

export default function Settings() {
  const [settings, setSettings] = useState<UserSettings| null>(null);
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()
  const { user, refreshUser } = useAuth()

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }

    const loadSettings = async () => {
      try {
        const response = await fetch('/api/settings', {
          credentials: 'include'
        })
        
        if (response.ok) {
          const data = await response.json()
          if (data.settings) {
            setSettings({ ...settings, ...data.settings })
          }
        } else if (response.status === 401) {
          router.push('/login')
        }
      } catch (error) {
        console.error('Error loading settings:', error)
      }
    }

    loadSettings()
  }, [user, router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setMessage('')
    setError('')

    try {
      const response = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(settings),
        credentials: 'include'
      })

      const data = await response.json()
      
      if (response.ok) {
        setMessage('Settings saved successfully!')
        // Refresh user data in context to reflect display name changes
        await refreshUser()
      } else if (response.status === 401) {
        router.push('/login')
      } else {
        setError(data.error || 'Failed to save settings')
      }
    } catch (err) {
      setError('Network error occurred')
    } finally {
      setLoading(false)
    }
  }

  const handleInputChange = (field: keyof UserSettings, value: UserSettings[keyof UserSettings]) => {
    setSettings(prev => ({
      ...prev,
      [field]: value
    }))
  }

  return (
    <div className="container">
      <Navigation />
      <div className="welcome">
        <h1>User Settings</h1>
      </div>
      
      <div className="card">

        {message && <div className="success">{message}</div>}
        {error && <div className="error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="displayName">Display Name:</label>
            <input
              type="text"
              id="displayName"
              name="displayName"
              value={settings?.displayName ? settings.displayName.children : ''}
              onChange={(e) => handleInputChange('displayName', { children: e.target.value, style: settings?.displayName?.style || { color: '' } })}
              placeholder="Enter your display name..."
            />
          </div>

          <div className="form-group">
            <label htmlFor="displayColor">Display Color:</label>
            <input
              type="color"
              id="displayColor"
              name="displayColor"
              value={settings?.displayName?.style ? settings.displayName.style.color : ''}
              onChange={(e) => handleInputChange('displayName', { children: settings?.displayName?.children || '', style: { color: e.target.value } })}
            />
          </div>

          <button type="submit" className="btn" disabled={loading}>
            {loading ? 'Saving...' : 'Save Settings'}
          </button>
        </form>
      </div>
    </div>
  )
}


// TODO: fix the login button not working on first trial. 
// fix other ui issues (settings accessible only after login, etc.)
// test better the app
// test better the x.py