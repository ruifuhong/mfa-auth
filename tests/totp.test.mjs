import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import * as OTPAuth from "otpauth";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");

const EMAIL = "a@example.com";
const PASSWORD = "correct-horse-battery-staple";
const KNOWN_SECRET = "JBSWY3DPEHPK3PXP";
const ENCRYPTION_KEY = "a".repeat(64);

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

function totpCode(secret, timestamp) {
  const totp = new OTPAuth.TOTP({
    issuer: "mfa-auth",
    label: EMAIL,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
  return totp.generate({ timestamp });
}

function tempDbPath() {
  return path.join(
    os.tmpdir(),
    `mfa-auth-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.sqlite`,
  );
}

describe("totp mfa", () => {
  let app;
  let dbPath;
  let clock;

  beforeEach(async () => {
    clock = Date.now();
    dbPath = tempDbPath();
    app = createApp({
      dbPath,
      encryptionKey: ENCRYPTION_KEY,
      totp: {
        now: () => clock,
        generateSecret: () => KNOWN_SECRET,
      },
    });
    await request(app).post("/signup").send({ email: EMAIL, password: PASSWORD });
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

  async function loginSession() {
    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    expect(login.status).toBe(200);
    return cookieHeader(login);
  }

  it("requires a session to enroll and returns otpauth URI plus QR data URL", async () => {
    const unauth = await request(app).post("/mfa/enroll");
    expect(unauth.status).toBe(401);

    const enroll = await request(app).post("/mfa/enroll").set("Cookie", await loginSession());
    expect(enroll.status).toBe(200);
    expect(enroll.body.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    expect(enroll.body.otpauth_uri).toMatch(/a(%40|@)example\.com/);
    expect(enroll.body.qr_data_url).toMatch(/^data:image\/png;base64,/);
    expect(enroll.body.secret).toBeUndefined();

    const row = app.locals.db.prepare("SELECT encrypted_secret, confirmed_at FROM mfa_totp").get();
    expect(row.encrypted_secret).toBeTruthy();
    expect(row.encrypted_secret).not.toContain(KNOWN_SECRET);
    expect(row.confirmed_at).toBeNull();

    const user = app.locals.db.prepare("SELECT mfa_enabled FROM users WHERE email = ?").get(EMAIL);
    expect(user.mfa_enabled).toBe(0);
  });

  it("confirms enrollment with a valid TOTP code and enables MFA", async () => {
    const cookie = await loginSession();
    await request(app).post("/mfa/enroll").set("Cookie", cookie);

    const bad = await request(app)
      .post("/mfa/confirm")
      .set("Cookie", cookie)
      .send({ code: "000000" });
    expect(bad.status).toBe(401);

    const confirm = await request(app)
      .post("/mfa/confirm")
      .set("Cookie", cookie)
      .send({ code: totpCode(KNOWN_SECRET, clock) });
    expect(confirm.status).toBe(200);

    const user = app.locals.db.prepare("SELECT mfa_enabled FROM users WHERE email = ?").get(EMAIL);
    expect(user.mfa_enabled).toBe(1);
    const totp = app.locals.db.prepare("SELECT confirmed_at FROM mfa_totp").get();
    expect(totp.confirmed_at).toBeTruthy();
  });

  it("does not issue a session cookie when MFA is enabled until TOTP verify", async () => {
    const cookie = await loginSession();
    await request(app).post("/mfa/enroll").set("Cookie", cookie);
    await request(app)
      .post("/mfa/confirm")
      .set("Cookie", cookie)
      .send({ code: totpCode(KNOWN_SECRET, clock) });

    await request(app).post("/logout").set("Cookie", cookie);

    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    expect(login.status).toBe(200);
    expect(login.body.status).toBe("MFA_REQUIRED");
    expect(login.body.mfa_token).toBeTruthy();
    expect(sessionSetCookie(login)).toBeUndefined();

    const me = await request(app).get("/me").set("Cookie", `mfa_pending=${login.body.mfa_token}`);
    expect(me.status).toBe(401);

    const wrong = await request(app).post("/mfa/verify").send({
      mfa_token: login.body.mfa_token,
      code: "000000",
    });
    expect(wrong.status).toBe(401);

    const verify = await request(app).post("/mfa/verify").send({
      mfa_token: login.body.mfa_token,
      code: totpCode(KNOWN_SECRET, clock),
    });
    expect(verify.status).toBe(200);
    const sid = sessionSetCookie(verify);
    expect(sid).toBeTruthy();
    expect(sid.toLowerCase()).toContain("httponly");

    const meOk = await request(app).get("/me").set("Cookie", cookieHeader(verify));
    expect(meOk.status).toBe(200);
    expect(meOk.body.mfa_enabled).toBe(true);
  });

  it("rejects a reused TOTP code in the same time step", async () => {
    const cookie = await loginSession();
    await request(app).post("/mfa/enroll").set("Cookie", cookie);
    const code = totpCode(KNOWN_SECRET, clock);
    await request(app).post("/mfa/confirm").set("Cookie", cookie).send({ code });
    await request(app).post("/logout").set("Cookie", cookie);

    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    const first = await request(app).post("/mfa/verify").send({
      mfa_token: login.body.mfa_token,
      code,
    });
    expect(first.status).toBe(200);

    const login2 = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    const replay = await request(app).post("/mfa/verify").send({
      mfa_token: login2.body.mfa_token,
      code,
    });
    expect(replay.status).toBe(401);
  });
});
