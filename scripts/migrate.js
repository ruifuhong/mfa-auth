const { openDatabase, DEFAULT_DB_PATH } = require("../src/db");

const dbPath = process.env.DATABASE_PATH || DEFAULT_DB_PATH;
const db = openDatabase(dbPath);
const tables = db
  .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
  .all()
  .map((row) => row.name);

console.log(`Schema applied: ${dbPath}`);
console.log(`Tables: ${tables.join(", ")}`);
db.close();
