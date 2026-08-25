const path = require("node:path");
const express = require("express");
const cookieParser = require("cookie-parser");
const QRCode = require("qrcode");
const { openDatabase } = require("./db");
const { createUser, verifyPasswordLogin, normalizeEmail } = require("./users");
const {
  COOKIE_NAME,
  createSession,
  getActiveSession,
  revokeSession,
  sessionCookieOptions,
} = require("./session");
const { writeAudit } = require("./audit");
const { createRateLimiter } = require("./rate-limit");
const { parseEncryptionKey, encryptSecret, decryptSecret } = require("./crypto-secret");
const { generateSecret, otpauthUri, verifyTotp } = require("./totp");
const { createPendingMfaStore } = require("./pending-mfa");
const { generateBackupCodes, insertBackupCodes, consumeBackupCode } = require("./backup-codes");

function clientMeta(req) {
  return {
    ipAddress: req.ip,
    userAgent: req.get("user-agent") ?? null,
  };
}

function requireSession(req, res, next) {
  const session = getActiveSession(req.app.locals.db, req.cookies[COOKIE_NAME]);
  if (!session) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.session = session;
  next();
}

function requireMfaEnabled(req, res, next) {
  if (!req.session.mfa_enabled) {
    return res.status(403).json({
      error: "MFA enrollment required",
      status: "MFA_ENROLLMENT_REQUIRED",
    });
  }
  next();
}

async function enrollTotpForUser(db, { userId, email, makeSecret, key }) {
  const secret = makeSecret();
  const encrypted = encryptSecret(secret, key);
  db.prepare(
    `INSERT INTO mfa_totp (user_id, encrypted_secret, confirmed_at)
     VALUES (?, ?, NULL)
     ON CONFLICT(user_id) DO UPDATE SET
       encrypted_secret = excluded.encrypted_secret,
       confirmed_at = NULL`,
  ).run(userId, encrypted);
  const otpauth = otpauthUri(secret, email);
  const qrDataUrl = await QRCode.toDataURL(otpauth);
  return { otpauth_uri: otpauth, qr_data_url: qrDataUrl };
}

function issueSession(res, db, user, meta) {
  const token = createSession(db, { userId: user.id, ...meta });
  res.cookie(COOKIE_NAME, token, sessionCookieOptions());
  return token;
}

function createApp({ dbPath, security, encryptionKey, totp } = {}) {
  const db = openDatabase(dbPath);
  const limiter = createRateLimiter(security);
  const now = totp?.now ?? (() => Date.now());
  const makeSecret = totp?.generateSecret ?? generateSecret;
  const key = parseEncryptionKey(
    encryptionKey ?? process.env.MFA_ENCRYPTION_KEY ?? "0".repeat(64),
  );
  const pendingMfa = createPendingMfaStore({ now });
  const lastTotpStep = new Map();

  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(cookieParser());
  app.locals.db = db;
  app.locals.limiter = limiter;

  app.post("/signup", async (req, res, next) => {
    try {
      const user = await createUser(db, {
        email: req.body?.email,
        password: req.body?.password,
      });
      res.status(201).json({ id: user.id, email: user.email });
    } catch (err) {
      next(err);
    }
  });

  app.post("/login", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    const meta = clientMeta(req);
    try {
      if (limiter.isBlocked(email, meta.ipAddress)) {
        return res.status(429).json({ error: "Too many attempts" });
      }

      const user = await verifyPasswordLogin(db, {
        email: req.body?.email,
        password: req.body?.password,
      });
      limiter.recordSuccess(email);

      if (user.mfa_enabled) {
        const mfaToken = pendingMfa.issue(user.id);
        return res.status(200).json({ status: "MFA_REQUIRED", mfa_token: mfaToken });
      }

      issueSession(res, db, user, meta);
      const enrollment = await enrollTotpForUser(db, {
        userId: user.id,
        email: user.email,
        makeSecret,
        key,
      });
      writeAudit(db, {
        userId: user.id,
        event: "login_success",
        ...meta,
      });
      res.status(200).json({
        status: "MFA_ENROLLMENT_REQUIRED",
        id: user.id,
        email: user.email,
        mfa_enabled: false,
        otpauth_uri: enrollment.otpauth_uri,
        qr_data_url: enrollment.qr_data_url,
      });
    } catch (err) {
      if (err.status === 401) {
        limiter.recordFailure(email, meta.ipAddress);
        const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
        writeAudit(db, {
          userId: existing?.id ?? null,
          event: "login_failed",
          ...meta,
        });
      }
      next(err);
    }
  });

  app.get("/me", requireSession, requireMfaEnabled, (req, res) => {
    res.json({
      id: req.session.user_id,
      email: req.session.email,
      mfa_enabled: Boolean(req.session.mfa_enabled),
    });
  });

  app.post("/logout", (req, res) => {
    const session = getActiveSession(db, req.cookies[COOKIE_NAME]);
    revokeSession(db, req.cookies[COOKIE_NAME]);
    if (session) {
      writeAudit(db, {
        userId: session.user_id,
        event: "logout",
        ...clientMeta(req),
      });
    }
    res.clearCookie(COOKIE_NAME, { ...sessionCookieOptions(), maxAge: 0 });
    res.status(204).end();
  });

  app.post("/mfa/enroll", requireSession, async (req, res, next) => {
    try {
      if (req.session.mfa_enabled) {
        return res.status(409).json({ error: "MFA already enabled" });
      }
      const enrollment = await enrollTotpForUser(db, {
        userId: req.session.user_id,
        email: req.session.email,
        makeSecret,
        key,
      });
      res.json(enrollment);
    } catch (err) {
      next(err);
    }
  });

  app.post("/mfa/confirm", requireSession, (req, res, next) => {
    try {
      const row = db
        .prepare("SELECT encrypted_secret, confirmed_at FROM mfa_totp WHERE user_id = ?")
        .get(req.session.user_id);
      if (!row || row.confirmed_at) {
        return res.status(400).json({ error: "MFA is not enrolled" });
      }
      const secret = decryptSecret(row.encrypted_secret, key);
      const result = verifyTotp(secret, req.session.email, req.body?.code, now());
      if (!result) {
        writeAudit(db, {
          userId: req.session.user_id,
          event: "mfa_challenge_failed",
          ...clientMeta(req),
        });
        return res.status(401).json({ error: "Invalid code" });
      }
      db.prepare("UPDATE mfa_totp SET confirmed_at = ? WHERE user_id = ?").run(
        new Date(now()).toISOString(),
        req.session.user_id,
      );
      db.prepare("UPDATE users SET mfa_enabled = 1 WHERE id = ?").run(req.session.user_id);
      const backupCodes = generateBackupCodes();
      insertBackupCodes(db, req.session.user_id, backupCodes);
      writeAudit(db, {
        userId: req.session.user_id,
        event: "mfa_enrolled",
        ...clientMeta(req),
      });
      res.json({ mfa_enabled: true, backup_codes: backupCodes });
    } catch (err) {
      next(err);
    }
  });

  app.post("/mfa/verify", (req, res, next) => {
    try {
      const pending = pendingMfa.peek(req.body?.mfa_token);
      if (!pending) {
        return res.status(401).json({ error: "Invalid or expired MFA token" });
      }
      const user = db
        .prepare(
          `SELECT users.id, users.email, users.mfa_enabled, mfa_totp.encrypted_secret
           FROM users
           JOIN mfa_totp ON mfa_totp.user_id = users.id
           WHERE users.id = ? AND users.mfa_enabled = 1 AND mfa_totp.confirmed_at IS NOT NULL`,
        )
        .get(pending.userId);
      if (!user) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      const secret = decryptSecret(user.encrypted_secret, key);
      const result = verifyTotp(secret, user.email, req.body?.code, now());
      const lastStep = lastTotpStep.get(user.id);
      const totpOk = result && result.step !== lastStep;
      const backupOk = !totpOk && consumeBackupCode(db, user.id, req.body?.code, now());
      if (!totpOk && !backupOk) {
        writeAudit(db, {
          userId: user.id,
          event: "mfa_challenge_failed",
          ...clientMeta(req),
        });
        return res.status(401).json({ error: "Invalid code" });
      }
      pendingMfa.consume(req.body.mfa_token);
      if (totpOk) {
        lastTotpStep.set(user.id, result.step);
      }
      const meta = clientMeta(req);
      issueSession(res, db, user, meta);
      if (backupOk) {
        writeAudit(db, {
          userId: user.id,
          event: "backup_code_used",
          ...meta,
        });
      }
      writeAudit(db, {
        userId: user.id,
        event: "login_success",
        ...meta,
      });
      res.status(200).json({ id: user.id, email: user.email, mfa_enabled: true });
    } catch (err) {
      next(err);
    }
  });

  app.use(express.static(path.join(__dirname, "..", "public")));

  app.use((err, _req, res, _next) => {
    const status = err.status || 500;
    if (status >= 500) {
      console.error(err);
    }
    res.status(status).json({ error: err.status ? err.message : "Internal server error" });
  });

  return app;
}

module.exports = { createApp };
