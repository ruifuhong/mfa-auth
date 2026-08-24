const crypto = require("node:crypto");
const argon2 = require("argon2");

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

function normalizeEmail(email) {
  return String(email ?? "")
    .trim()
    .toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function createUser(db, { email, password }) {
  const normalized = normalizeEmail(email);
  if (!isValidEmail(normalized) || typeof password !== "string" || password.length < 8) {
    const err = new Error("Invalid signup payload");
    err.status = 400;
    throw err;
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(normalized);
  if (existing) {
    const err = new Error("Email already registered");
    err.status = 409;
    throw err;
  }

  const id = crypto.randomUUID();
  const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);
  db.prepare(
    `INSERT INTO users (id, email, password_hash, mfa_enabled) VALUES (?, ?, ?, 0)`,
  ).run(id, normalized, passwordHash);

  return { id, email: normalized, mfa_enabled: false };
}

async function verifyPasswordLogin(db, { email, password }) {
  const normalized = normalizeEmail(email);
  const user = db
    .prepare("SELECT id, email, password_hash, mfa_enabled FROM users WHERE email = ?")
    .get(normalized);

  const dummyHash =
    "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const hash = user?.password_hash ?? dummyHash;
  const ok = await argon2.verify(hash, String(password ?? "")).catch(() => false);

  if (!user || !ok) {
    const err = new Error("Invalid credentials");
    err.status = 401;
    throw err;
  }

  return { id: user.id, email: user.email, mfa_enabled: Boolean(user.mfa_enabled) };
}

module.exports = { createUser, verifyPasswordLogin, normalizeEmail };
