import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUser } from '@/lib/auth';
import { getDatabase } from '@/lib/database';

export async function GET(request: NextRequest) {
  const user = await getCurrentUser(request);

  if (!user) {
    return NextResponse.json(
      { error: 'Not authenticated' },
      { status: 401 }
    );
  }

  // Get user settings to include profile picture and display name
  const database = getDatabase();
  const userSettings = await database.getUserSettings(user.id);
  
  const userData = {
    id: user.id,
    username: user.username,
    displayName: userSettings?.displayName || ''
  };

  return NextResponse.json(userData, { status: 200 });
}
