import './globals.css'
import { Inter } from 'next/font/google'
import { initDatabase } from '@/lib/database'
import { AuthProvider } from '@/contexts/AuthContext'

const inter = Inter({ subsets: ['latin'] })

// Initialize database at app startup
initDatabase()

export const metadata = {
  title: 'Completely Dangerous Web App',
  description: 'A web application with a cool and dangerous feature',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  )
}