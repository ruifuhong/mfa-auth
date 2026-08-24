const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const DEFAULT_DB_PATH = path.join(__dirname, "..", "data", "app.sqlite");
const SCHEMA_PATH = path.join(__dirname, "schema.sql");

function openDatabase(dbPath = process.env.DATABASE_PATH || DEFAULT_DB_PATH) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(fs.readFileSync(SCHEMA_PATH, "utf8"));
  return db;
}

module.exports = { openDatabase, DEFAULT_DB_PATH };
