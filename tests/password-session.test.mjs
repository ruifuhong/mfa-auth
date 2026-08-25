import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");
const argon2 = require("argon2");

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

function sessionSetCookie(res) {
  const setCookie = res.headers["set-cookie"];
  if (!setCookie) {
    return undefined;
  }
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  return list.find((c) => c.startsWith("sid="));
}

describe("password session", () => {
  let app;
  let dbPath;

  beforeEach(() => {
    dbPath = path.join(
      os.tmpdir(),
      `mfa-auth-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.sqlite`,
    );
    app = createApp({ dbPath });
  });

  afterEach(() => {
    if (app?.locals?.db) {
      app.locals.db.close();
    }
    for (const suffix of ["", "-wal", "-shm"]) {
      const file = `${dbPath}${suffix}`;
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    }
  });

  it("creates a user on POST /signup without returning the password hash", async () => {
    const res = await request(app).post("/signup").send({
      email: EMAIL,
      password: PASSWORD,
    });

    expect(res.status).toBe(201);
    expect(res.body.email).toBe(EMAIL);
    expect(res.body.id).toBeTruthy();
    expect(res.body.password).toBeUndefined();
    expect(res.body.password_hash).toBeUndefined();
  });

  it("stores the password as Argon2id and rejects duplicate emails", async () => {
    await request(app).post("/signup").send({ email: EMAIL, password: PASSWORD });

    const row = app.locals.db
      .prepare("SELECT password_hash FROM users WHERE email = ?")
      .get(EMAIL);

    expect(row.password_hash).not.toBe(PASSWORD);
    expect(row.password_hash.startsWith("$argon2id$")).toBe(true);
    await expect(argon2.verify(row.password_hash, PASSWORD)).resolves.toBe(true);

    const dup = await request(app).post("/signup").send({
      email: "A@example.com",
      password: PASSWORD,
    });
    expect(dup.status).toBe(409);
  });

  it("rejects wrong passwords with a generic error and does not set a session", async () => {
    await request(app).post("/signup").send({ email: EMAIL, password: PASSWORD });

    const res = await request(app).post("/login").send({
      email: EMAIL,
      password: "not-the-password",
    });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid credentials");
    expect(sessionSetCookie(res)).toBeUndefined();
  });

  it("logs in with an HttpOnly SameSite session cookie and requires MFA before /me", async () => {
    await request(app).post("/signup").send({ email: EMAIL, password: PASSWORD });

    const unauth = await request(app).get("/me");
    expect(unauth.status).toBe(401);

    const login = await request(app).post("/login").send({
      email: EMAIL,
      password: PASSWORD,
    });

    expect(login.status).toBe(200);
    expect(login.body.status).toBe("MFA_ENROLLMENT_REQUIRED");
    expect(login.body.qr_data_url).toMatch(/^data:image\/png;base64,/);
    const cookie = sessionSetCookie(login);
    expect(cookie).toBeTruthy();
    expect(cookie.toLowerCase()).toContain("httponly");
    expect(cookie.toLowerCase()).toMatch(/samesite=lax/);

    const token = cookie.split(";")[0].slice("sid=".length);
    const hashed = app.locals.db.prepare("SELECT id, revoked_at FROM sessions").all();
    expect(hashed).toHaveLength(1);
    expect(hashed[0].id).not.toBe(token);
    expect(hashed[0].revoked_at).toBeNull();

    const me = await request(app).get("/me").set("Cookie", cookieHeader(login));
    expect(me.status).toBe(403);
    expect(me.body.status).toBe("MFA_ENROLLMENT_REQUIRED");
  });

  it("revokes the session on POST /logout so GET /me fails", async () => {
    await request(app).post("/signup").send({ email: EMAIL, password: PASSWORD });
    const login = await request(app).post("/login").send({
      email: EMAIL,
      password: PASSWORD,
    });
    const cookie = cookieHeader(login);

    const logout = await request(app).post("/logout").set("Cookie", cookie);
    expect(logout.status).toBe(204);

    const session = app.locals.db.prepare("SELECT revoked_at FROM sessions").get();
    expect(session.revoked_at).toBeTruthy();

    const me = await request(app).get("/me").set("Cookie", cookie);
    expect(me.status).toBe(401);
  });
});
