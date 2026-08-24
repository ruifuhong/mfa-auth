const crypto = require("node:crypto");

function writeAudit(db, { userId = null, event, ipAddress = null, userAgent = null }) {
  db.prepare(
    `INSERT INTO audit_logs (id, user_id, event, ip_address, user_agent, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    crypto.randomUUID(),
    userId,
    event,
    ipAddress,
    userAgent,
    new Date().toISOString(),
  );
}

module.exports = { writeAudit };
