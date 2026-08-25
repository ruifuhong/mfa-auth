const { openDatabase } = require("../src/db");
const { createUser } = require("../src/users");

const DEMO_PASSWORD = "password12345";

const DEMO_USERS = [
  { email: "alice@example.com", password: DEMO_PASSWORD },
  { email: "bob@example.com", password: DEMO_PASSWORD },
  { email: "carol@example.com", password: DEMO_PASSWORD },
  ...Array.from({ length: 20 }, (_, i) => {
    const n = String(i + 1).padStart(2, "0");
    return { email: `test${n}@example.com`, password: DEMO_PASSWORD };
  }),
];

async function seedDemoUsers(db) {
  const results = [];
  for (const user of DEMO_USERS) {
    const existing = db.prepare("SELECT id, email FROM users WHERE email = ?").get(user.email);
    if (existing) {
      results.push({ email: user.email, status: "skipped" });
      continue;
    }
    const created = await createUser(db, user);
    results.push({ email: created.email, id: created.id, status: "created" });
  }
  return results;
}

async function main() {
  const db = openDatabase();
  const results = await seedDemoUsers(db);
  for (const row of results) {
    if (row.status === "skipped") {
      console.log(`skip (exists): ${row.email}`);
    } else {
      console.log(`created: ${row.email} (${row.id})`);
    }
  }
  db.close();
  console.log(`Done. ${DEMO_USERS.length} accounts. Passwords are all: ${DEMO_PASSWORD}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { DEMO_USERS, DEMO_PASSWORD, seedDemoUsers };
