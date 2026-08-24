const express = require("express");
const cookieParser = require("cookie-parser");
const { openDatabase } = require("./db");
const { createUser, verifyPasswordLogin } = require("./users");
const {
  COOKIE_NAME,
  createSession,
  getActiveSession,
  revokeSession,
  sessionCookieOptions,
} = require("./session");

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

function createApp({ dbPath } = {}) {
  const db = openDatabase(dbPath);
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(cookieParser());
  app.locals.db = db;

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
    try {
      const user = await verifyPasswordLogin(db, {
        email: req.body?.email,
        password: req.body?.password,
      });
      const token = createSession(db, {
        userId: user.id,
        ...clientMeta(req),
      });
      res.cookie(COOKIE_NAME, token, sessionCookieOptions());
      res.status(200).json({ id: user.id, email: user.email, mfa_enabled: user.mfa_enabled });
    } catch (err) {
      next(err);
    }
  });

  app.get("/me", requireSession, (req, res) => {
    res.json({
      id: req.session.user_id,
      email: req.session.email,
      mfa_enabled: Boolean(req.session.mfa_enabled),
    });
  });

  app.post("/logout", (req, res) => {
    revokeSession(db, req.cookies[COOKIE_NAME]);
    res.clearCookie(COOKIE_NAME, { ...sessionCookieOptions(), maxAge: 0 });
    res.status(204).end();
  });

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
