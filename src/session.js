const crypto = require("node:crypto");

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COOKIE_NAME = "sid";

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.COOKIE_SECURE === "true",
    path: "/",
    maxAge: SESSION_TTL_MS,
  };
}

function createSession(db, { userId, ipAddress, userAgent }) {
  const token = createSessionToken();
  const now = new Date();
  db.prepare(
    `INSERT INTO sessions (id, user_id, created_at, expires_at, ip_address, user_agent)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    hashToken(token),
    userId,
    now.toISOString(),
    new Date(now.getTime() + SESSION_TTL_MS).toISOString(),
    ipAddress ?? null,
    userAgent ?? null,
  );
  return token;
}

function getActiveSession(db, token) {
  if (!token) {
    return null;
  }
  const row = db
    .prepare(
      `SELECT sessions.id, sessions.user_id, sessions.expires_at, sessions.revoked_at,
              users.email, users.mfa_enabled
       FROM sessions
       JOIN users ON users.id = sessions.user_id
       WHERE sessions.id = ?`,
    )
    .get(hashToken(token));
  if (!row || row.revoked_at) {
    return null;
  }
  if (Date.parse(row.expires_at) <= Date.now()) {
    return null;
  }
  return row;
}

function revokeSession(db, token) {
  if (!token) {
    return;
  }
  db.prepare(
    `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
  ).run(new Date().toISOString(), hashToken(token));
}

module.exports = {
  COOKIE_NAME,
  createSession,
  getActiveSession,
  revokeSession,
  sessionCookieOptions,
};
