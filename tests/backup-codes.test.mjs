import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import * as OTPAuth from "otpauth";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");
const crypto = require("node:crypto");

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

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

describe("backup codes", () => {
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

  async function confirmMfa() {
    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    const cookie = cookieHeader(login);
    await request(app).post("/mfa/enroll").set("Cookie", cookie);
    const confirm = await request(app)
      .post("/mfa/confirm")
      .set("Cookie", cookie)
      .send({ code: totpCode(KNOWN_SECRET, clock) });
    return { cookie, confirm };
  }

  it("returns 8 backup codes once on confirm and stores only hashes", async () => {
    const { confirm } = await confirmMfa();
    expect(confirm.status).toBe(200);
    expect(confirm.body.backup_codes).toHaveLength(8);
    expect(new Set(confirm.body.backup_codes).size).toBe(8);

    for (const code of confirm.body.backup_codes) {
      expect(code).toMatch(/^[a-f0-9]{4}(-[a-f0-9]{4}){3}$/);
    }

    const rows = app.locals.db.prepare("SELECT code_hash, used_at FROM backup_codes").all();
    expect(rows).toHaveLength(8);
    expect(rows.every((row) => row.used_at === null)).toBe(true);

    const plaintext = new Set(confirm.body.backup_codes);
    for (const row of rows) {
      expect(plaintext.has(row.code_hash)).toBe(false);
      const match = [...plaintext].some((code) => sha256(code.replaceAll("-", "")) === row.code_hash);
      expect(match).toBe(true);
    }
  });

  it("accepts a backup code on MFA verify once, then rejects reuse", async () => {
    const { cookie, confirm } = await confirmMfa();
    const backupCode = confirm.body.backup_codes[0];
    await request(app).post("/logout").set("Cookie", cookie);

    const login = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    expect(login.body.status).toBe("MFA_REQUIRED");

    const verify = await request(app).post("/mfa/verify").send({
      mfa_token: login.body.mfa_token,
      code: backupCode,
    });
    expect(verify.status).toBe(200);
    expect(sessionSetCookie(verify)).toBeTruthy();

    const used = app.locals.db.prepare("SELECT used_at FROM backup_codes WHERE used_at IS NOT NULL").all();
    expect(used).toHaveLength(1);
    expect(used[0].used_at).toBeTruthy();

    const audit = app.locals.db
      .prepare("SELECT event FROM audit_logs WHERE event = 'backup_code_used'")
      .get();
    expect(audit).toBeTruthy();

    await request(app).post("/logout").set("Cookie", cookieHeader(verify));
    const login2 = await request(app).post("/login").send({ email: EMAIL, password: PASSWORD });
    const replay = await request(app).post("/mfa/verify").send({
      mfa_token: login2.body.mfa_token,
      code: backupCode,
    });
    expect(replay.status).toBe(401);
  });
});
