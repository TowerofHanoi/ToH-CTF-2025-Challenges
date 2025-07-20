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
    const success = await db.createUser(username, password);

    if (!success) {
      return NextResponse.json(
        { error: 'Username already exists' },
        { status: 409 }
      );
    }

    // Auto-login after registration
    const user = await db.getUser(username, password);
    if (user) {
      // Get user settings (should be empty for new user)
      const userSettings = await db.getUserSettings(user.id);
      
      const userData = {
        id: user.id,
        username: user.username,
        displayName: userSettings?.displayName || ''
      };

      const response = NextResponse.json(
        { message: 'Registration successful', user: userData },
        { status: 201 }
      );
      return await setAuthCookie(response, { id: user.id, username: user.username });
    }

    return NextResponse.json(
      { message: 'Registration successful' },
      { status: 201 }
    );
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
