import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { verifyToken } from './lib/auth'

// Define protected routes
const protectedRoutes = ['/dashboard', '/settings']

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Check if the current route is protected
  if (protectedRoutes.some(route => pathname.startsWith(route))) {
    const token = request.cookies.get('auth-token')?.value
    console.log(`Accessing protected route: ${pathname} with token: ${token}`)

    if (!token) {
      // Redirect to login if no token
      console.log(`No token found for protected route: ${pathname}`)
      return NextResponse.redirect(new URL('/login', request.url))
    }

    // Verify the token
    const user = await verifyToken(token)
    console.log(`Token verification result for ${pathname}:`, user)
    if (!user) {
      // Redirect to login if token is invalid
      const response = NextResponse.redirect(new URL('/login', request.url))
      response.cookies.delete('auth-token')
      return response
    }
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*', '/settings/:path*']
}
