const { openDatabase } = require("../src/db");
const { createUser } = require("../src/users");

const DEMO_USERS = [
  { email: "alice@example.com", password: "password12345" },
  { email: "bob@example.com", password: "password12345" },
  { email: "carol@example.com", password: "password12345" },
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
  console.log("Done. Passwords are all: password12345");
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { DEMO_USERS, seedDemoUsers };
