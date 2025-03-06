const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./database.sqlite", (err) => {
  if (err) {
    console.error("Error conectando a SQLite:", err);
  } else {
    console.log("Conexión a SQLite exitosa.");
    
    db.serialize(() => {
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE CHECK(length(email) <= 50),
          password TEXT NOT NULL CHECK(length(password) <= 100),
          role TEXT DEFAULT 'user',
          failed_login_attempts INTEGER DEFAULT 0,
          last_login_attempt DATETIME,
          csrf_token TEXT
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS accounts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          balance REAL DEFAULT 0,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT,
          description TEXT
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          level TEXT,
          message TEXT,
          details TEXT,
          timestamp TEXT
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT UNIQUE,
          user_id INTEGER,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS transfers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          amount REAL,
          from_account_id INTEGER,
          to_account_id INTEGER,
          FOREIGN KEY(from_account_id) REFERENCES accounts(id),
          FOREIGN KEY(to_account_id) REFERENCES accounts(id)
        )
      `);
      db.run(`
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          comment TEXT,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `);
      db.run(`
        CREATE TABLE IF NOT EXISTS expired_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT NOT NULL,
          expired_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        `);
    });
  }
});

module.exports = db;