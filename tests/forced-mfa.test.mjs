import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import * as OTPAuth from "otpauth";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");

const EMAIL = "force@example.com";
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

describe("forced MFA enrollment", () => {
  let app;
  let dbPath;
  let clock;

  beforeEach(async () => {
    clock = Date.now();
    dbPath = path.join(
      os.tmpdir(),
      `mfa-auth-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.sqlite`,
    );
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

  it("auto-enrolls on first login and returns QR without a separate enroll call", async () => {
    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });

    expect(login.status).toBe(200);
    expect(login.body.status).toBe("MFA_ENROLLMENT_REQUIRED");
    expect(login.body.mfa_enabled).toBe(false);
    expect(login.body.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    expect(login.body.qr_data_url).toMatch(/^data:image\/png;base64,/);
    expect(login.body.secret).toBeUndefined();
    expect(sessionSetCookie(login)).toBeTruthy();

    const row = app.locals.db.prepare("SELECT encrypted_secret, confirmed_at FROM mfa_totp").get();
    expect(row.encrypted_secret).toBeTruthy();
    expect(row.encrypted_secret).not.toContain(KNOWN_SECRET);
    expect(row.confirmed_at).toBeNull();
  });

  it("blocks GET /me until MFA is confirmed", async () => {
    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    const cookie = cookieHeader(login);

    const blocked = await request(app).get("/me").set("Cookie", cookie);
    expect(blocked.status).toBe(403);
    expect(blocked.body.status).toBe("MFA_ENROLLMENT_REQUIRED");

    const confirm = await request(app)
      .post("/mfa/confirm")
      .set("Cookie", cookie)
      .send({ code: totpCode(KNOWN_SECRET, clock) });
    expect(confirm.status).toBe(200);
    expect(confirm.body.mfa_enabled).toBe(true);
    expect(confirm.body.backup_codes).toHaveLength(8);

    const me = await request(app).get("/me").set("Cookie", cookie);
    expect(me.status).toBe(200);
    expect(me.body.mfa_enabled).toBe(true);
  });

  it("requires MFA challenge on later logins after enrollment is confirmed", async () => {
    const first = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    await request(app)
      .post("/mfa/confirm")
      .set("Cookie", cookieHeader(first))
      .send({ code: totpCode(KNOWN_SECRET, clock) });
    await request(app).post("/logout").set("Cookie", cookieHeader(first));

    const second = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    expect(second.body.status).toBe("MFA_REQUIRED");
    expect(second.body.mfa_token).toBeTruthy();
    expect(sessionSetCookie(second)).toBeUndefined();
  });
});
