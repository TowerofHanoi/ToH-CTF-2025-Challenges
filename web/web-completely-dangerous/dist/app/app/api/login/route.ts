import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/database';
import { setAuthCookie } from '@/lib/auth';

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400 }
      );
    }
    const db = getDatabase();
    const user = await db.getUser(username, password);

    if (!user) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Get user settings to include profile picture and display name
    const userSettings = await db.getUserSettings(user.id);
    
    const userData = {
      id: user.id,
      username: user.username,
      displayName: userSettings?.displayName || ''
    };

    const response = NextResponse.json(
      { message: 'Login successful', user: userData },
      { status: 200 }
    );

    return await setAuthCookie(response, { id: user.id, username: user.username });
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
