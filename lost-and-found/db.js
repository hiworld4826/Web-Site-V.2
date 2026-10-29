const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('lostfound.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK(type IN ('lost','found')),
  title TEXT NOT NULL,
  description TEXT,
  location TEXT,
  event_date TEXT,
  contact TEXT,
  image TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','returned')),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS item_tags (
  item_id INTEGER REFERENCES items(id) ON DELETE CASCADE,
  tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (item_id, tag_id)
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
`);

// สร้างแอดมินคนแรกถ้ายังไม่มี
const hasAdmin = db.prepare("SELECT id FROM users WHERE role = 'admin'").get();
if (!hasAdmin) {
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    .run('admin', bcrypt.hashSync('admin123', 10), 'admin');
  console.log('สร้างบัญชีแอดมินเริ่มต้น -> username: admin / password: admin123');
}

module.exports = db;