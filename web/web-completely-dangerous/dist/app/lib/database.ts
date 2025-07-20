import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';

const DB_PATH = './users.db';

export interface User {
  id: number;
  username: string;
  password: string;
};
  
export interface UserSettings {
  displayName?: {
    children?: string;
    style?: { color: string };
  };
};

const EMPTY_USER_SETTINGS: UserSettings = {
  displayName: {
    children: '',
    style: {color: ''}
  }
};

interface UserSettingsDB {
  user_id: number;
  display_name?: string; // json stringified
}

class Database {
  private db: sqlite3.Database;

  constructor() {
    this.db = new sqlite3.Database(DB_PATH);
    this.init();
  }

  private run = (sql: string, params?: any[]) =>
    new Promise<any>((resolve, reject) => {
      return this.db.run(sql, params || [], function (err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });
  
  private get = (sql: string, params?: any[]) =>
    new Promise<any>((resolve, reject) => {
      return this.db.get(sql, params || [], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

  private async init() {    
    
    await this.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);

    // Create user_settings table if not exists
    await this.run(`
      CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY,
        display_name TEXT DEFAULT '',
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Insert default admin user if not exists
    const hashedPassword = await bcrypt.hash('testpaswd', 10);
    try {
      await this.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ['admin', hashedPassword]);
    } catch (error) {
      console.log('Admin user might already exist');
    }
    
  }

  async getUser(username: string, password: string) {
    const user = await this.get('SELECT * FROM users WHERE username = ?', [username]) as User | undefined;
    console.log('User fetched:', user);
    if (user && await bcrypt.compare(password, user.password)) {
      return user;
    }
    return null;
  }

  async createUser(username: string, password: string): Promise<boolean> {
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      await this.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
      return true;
    } catch (error) {
      return false; // Username already exists
    }
  }

  async getUserSettings(userId: number): Promise<UserSettings | null> {
    try {
      const settings = await this.get('SELECT * FROM user_settings WHERE user_id = ?', [userId]) as UserSettingsDB | undefined;
      
      if (!settings) {
        return null;
      }

      if (!settings.display_name) {
        return EMPTY_USER_SETTINGS;
      }

      return {
        displayName: JSON.parse(settings.display_name)
      };
    } catch (error) {
      console.error('Error getting user settings:', error);
      return null;
    }
  }

  async updateUserSettings(userId: number, settings?: UserSettings): Promise<boolean> {
    try {
      const finalSettings = settings || EMPTY_USER_SETTINGS;
      
      await this.run(`
        INSERT OR REPLACE INTO user_settings 
        (user_id, display_name)
        VALUES (?, ?)
      `, [
        userId,
        JSON.stringify(finalSettings.displayName || EMPTY_USER_SETTINGS.displayName)
      ]);
      return true;
    } catch (error) {
      console.error('Error updating user settings:', error);
      return false;
    }
  }

  close() {
    this.db.close();
  }
}

// Singleton instance
let dbInstance: Database | null = null;

export function initDatabase() {
  if (!dbInstance) {
    dbInstance = new Database();
  }
}

export function getDatabase(): Database {
  if (!dbInstance) {
    dbInstance = new Database();
  }
  return dbInstance;
}
