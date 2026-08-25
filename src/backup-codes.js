const crypto = require("node:crypto");

const BACKUP_CODE_COUNT = 8;

function normalizeBackupCode(code) {
  return String(code ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("-", "");
}

function formatBackupCode(hex) {
  return hex.match(/.{4}/g).join("-");
}

function hashBackupCode(code) {
  return crypto.createHash("sha256").update(normalizeBackupCode(code)).digest("hex");
}

function generateBackupCodes(count = BACKUP_CODE_COUNT) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    codes.push(formatBackupCode(crypto.randomBytes(8).toString("hex")));
  }
  return codes;
}

function insertBackupCodes(db, userId, codes) {
  const stmt = db.prepare(
    `INSERT INTO backup_codes (id, user_id, code_hash, used_at) VALUES (?, ?, ?, NULL)`,
  );
  const tx = db.transaction((items) => {
    db.prepare("DELETE FROM backup_codes WHERE user_id = ?").run(userId);
    for (const code of items) {
      stmt.run(crypto.randomUUID(), userId, hashBackupCode(code));
    }
  });
  tx(codes);
}

function consumeBackupCode(db, userId, code, now) {
  const normalized = normalizeBackupCode(code);
  if (!normalized || normalized.length !== 16) {
    return false;
  }
  const hash = hashBackupCode(normalized);
  const row = db
    .prepare(
      `SELECT id FROM backup_codes
       WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
    )
    .get(userId, hash);
  if (!row) {
    return false;
  }
  const result = db
    .prepare(
      `UPDATE backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
    )
    .run(new Date(now).toISOString(), row.id);
  return result.changes === 1;
}

module.exports = {
  BACKUP_CODE_COUNT,
  generateBackupCodes,
  insertBackupCodes,
  consumeBackupCode,
};
