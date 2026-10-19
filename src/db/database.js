const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, '../../data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'ecommerce.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function initSchema(targetDb = db) {
  targetDb.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      role TEXT NOT NULL CHECK(role IN ('admin', 'seller', 'customer')),
      tier TEXT NOT NULL DEFAULT 'regular' CHECK(tier IN ('regular', 'vip')),
      is_verified INTEGER NOT NULL DEFAULT 1 CHECK(is_verified IN (0, 1)),
      google_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price INTEGER NOT NULL,
      seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      is_vip_exclusive INTEGER NOT NULL DEFAULT 0 CHECK(is_vip_exclusive IN (0, 1)),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refund_requested', 'refunded')),
      refund_reason TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

initSchema();

module.exports = {
  db,
  getDb: () => db,
  initSchema
};
