import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");

const EMAIL = "a@example.com";
const PASSWORD = "correct-horse-battery-staple";

function cookieHeader(res) {
  const setCookie = res.headers["set-cookie"];
  if (!setCookie) {
    return "";
  }
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  return list.map((c) => c.split(";")[0]).join("; ");
}

function tempDbPath() {
  return path.join(
    os.tmpdir(),
    `mfa-auth-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.sqlite`,
  );
}

function closeApp(app, dbPath) {
  if (app?.locals?.db) {
    app.locals.db.close();
  }
  if (!dbPath) {
    return;
  }
  for (const suffix of ["", "-wal", "-shm"]) {
    const file = `${dbPath}${suffix}`;
    if (fs.existsSync(file)) {
      fs.unlinkSync(file);
    }
  }
}

describe("abuse audit", () => {
  let app;
  let dbPath;
  let clock;

  beforeEach(async () => {
    clock = Date.now();
    dbPath = tempDbPath();
    app = createApp({
      dbPath,
      security: {
        maxEmailFails: 3,
        maxIpFails: 20,
        windowMs: 60_000,
        lockMs: 60_000,
        now: () => clock,
      },
    });
    await request(app).post("/signup").send({ email: EMAIL, password: PASSWORD });
  });

  afterEach(() => {
    closeApp(app, dbPath);
  });

  it("writes login_success and logout audit events", async () => {
    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    expect(login.status).toBe(200);

    const logout = await request(app).post("/logout").set("Cookie", cookieHeader(login));
    expect(logout.status).toBe(204);

    const events = app.locals.db
      .prepare("SELECT event FROM audit_logs ORDER BY created_at")
      .all()
      .map((row) => row.event);

    expect(events).toEqual(["login_success", "logout"]);

    const success = app.locals.db
      .prepare("SELECT user_id FROM audit_logs WHERE event = 'login_success'")
      .get();
    expect(success.user_id).toBeTruthy();
  });

  it("writes login_failed on a wrong password", async () => {
    const res = await request(app).post("/login").send({
      email: EMAIL,
      password: "not-the-password",
    });
    expect(res.status).toBe(401);

    const row = app.locals.db
      .prepare("SELECT event, user_id FROM audit_logs WHERE event = 'login_failed'")
      .get();
    expect(row).toBeTruthy();
    expect(row.user_id).toBeTruthy();
  });

  it("locks the account after N failed logins and returns 429 even with the right password", async () => {
    for (let i = 0; i < 3; i += 1) {
      const fail = await request(app).post("/login").send({
        email: EMAIL,
        password: "not-the-password",
      });
      expect(fail.status).toBe(401);
    }

    const lockedWrong = await request(app).post("/login").send({
      email: EMAIL,
      password: "not-the-password",
    });
    expect(lockedWrong.status).toBe(429);

    const lockedRight = await request(app).post("/login").send({
      email: EMAIL,
      password: PASSWORD,
    });
    expect(lockedRight.status).toBe(429);
    expect(lockedRight.body.error).toBe("Too many attempts");
  });

  it("allows login again after the lockout window", async () => {
    for (let i = 0; i < 3; i += 1) {
      await request(app).post("/login").send({
        email: EMAIL,
        password: "not-the-password",
      });
    }

    clock += 60_000 + 1;

    const res = await request(app).post("/login").send({
      email: EMAIL,
      password: PASSWORD,
    });
    expect(res.status).toBe(200);
  });
});

describe("abuse audit IP limit", () => {
  let app;
  let dbPath;
  let clock;

  beforeEach(async () => {
    clock = Date.now();
    dbPath = tempDbPath();
    app = createApp({
      dbPath,
      security: {
        maxEmailFails: 10,
        maxIpFails: 2,
        windowMs: 60_000,
        lockMs: 60_000,
        now: () => clock,
      },
    });
    await request(app).post("/signup").send({ email: "a@example.com", password: PASSWORD });
    await request(app).post("/signup").send({ email: "b@example.com", password: PASSWORD });
  });

  afterEach(() => {
    closeApp(app, dbPath);
  });

  it("rate-limits failed attempts per IP across accounts", async () => {
    expect(
      (
        await request(app).post("/login").send({
          email: "a@example.com",
          password: "wrong",
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await request(app).post("/login").send({
          email: "b@example.com",
          password: "wrong",
        })
      ).status,
    ).toBe(401);

    const blocked = await request(app).post("/login").send({
      email: "a@example.com",
      password: PASSWORD,
    });
    expect(blocked.status).toBe(429);
  });
});
