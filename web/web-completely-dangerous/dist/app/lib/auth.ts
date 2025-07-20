import { SignJWT, jwtVerify } from 'jose';
import { serialize, parse } from 'cookie';
import { NextRequest, NextResponse } from 'next/server';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const secret = new TextEncoder().encode(JWT_SECRET);

export interface User {
  id: number;
  username: string;
}

export async function generateToken(user: User): Promise<string> {
  return await new SignJWT({ id: user.id, username: user.username })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secret);
}

export async function verifyToken(token: string): Promise<User | null> {
  try {
    const { payload } = await jwtVerify(token, secret);
    return { id: payload.id as number, username: payload.username as string };
  } catch (error) {
    console.error('Token verification failed:', error);
    return null;
  }
}

export async function setAuthCookie(response: NextResponse, user: User): Promise<NextResponse> {
  const token = await generateToken(user);
  const cookie = serialize('auth-token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 60 * 60 * 24 * 7, // 7 days
    path: '/',
  });
  console.log('Setting auth cookie:', cookie);
  response.headers.set('Set-Cookie', cookie);
  return response;
}

export function clearAuthCookie(response: NextResponse): NextResponse {
  const cookie = serialize('auth-token', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 0,
    path: '/',
  });

  response.headers.set('Set-Cookie', cookie);
  return response;
}

export function getAuthToken(request: NextRequest): string | null {
  const cookies = parse(request.headers.get('cookie') || '');
  let auth_token: string | null = null;
  if (cookies['auth-token']) {
    auth_token = cookies['auth-token'];
  } else {
    // check for auth-token in query parameters
    const url = new URL(request.url);
    auth_token = url.searchParams.get('auth-token');
    if (!auth_token) {
      return null;
    }
  }
  // Return the auth token from cookies
  return auth_token;
}

export async function getCurrentUser(request: NextRequest): Promise<User | null> {
  const token = getAuthToken(request);
  if (!token) return null;
  return await verifyToken(token);
}
