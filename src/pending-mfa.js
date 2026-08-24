const crypto = require("node:crypto");

const DEFAULT_TTL_MS = 5 * 60 * 1000;

function createPendingMfaStore({ now = () => Date.now(), ttlMs = DEFAULT_TTL_MS } = {}) {
  const pending = new Map();

  function issue(userId) {
    const token = crypto.randomBytes(32).toString("base64url");
    pending.set(token, { userId, expiresAt: now() + ttlMs });
    return token;
  }

  function peek(token) {
    const row = pending.get(token);
    if (!row || row.expiresAt <= now()) {
      pending.delete(token);
      return null;
    }
    return row;
  }

  function consume(token) {
    const row = peek(token);
    if (!row) {
      return null;
    }
    pending.delete(token);
    return row;
  }

  return { issue, peek, consume };
}

module.exports = { createPendingMfaStore };
