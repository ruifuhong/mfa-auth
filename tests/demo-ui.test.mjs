import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");
const { DEMO_USERS, seedDemoUsers } = require("../scripts/seed.js");
const { verifyPasswordLogin } = require("../src/users.js");

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

describe("demo ui", () => {
  let app;
  let dbPath;

  beforeEach(() => {
    dbPath = tempDbPath();
    app = createApp({ dbPath, encryptionKey: "a".repeat(64) });
  });

  afterEach(() => {
    closeApp(app, dbPath);
  });

  it("serves the minimal HTML play page at GET /", async () => {
    const res = await request(app).get("/");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/html/);
    expect(res.text).toContain("mfa-auth");
    expect(res.text).toContain("alice@example.com");
    expect(res.text).toContain('id="login"');
    expect(res.text).toContain('id="logout"');
    expect(res.text).toContain('id="enroll"');
    expect(res.text).toContain('id="confirm"');
    expect(res.text).toContain('id="mfa"');
  });
});

describe("demo seed", () => {
  let app;
  let dbPath;

  beforeEach(() => {
    dbPath = tempDbPath();
    app = createApp({ dbPath, encryptionKey: "a".repeat(64) });
  });

  afterEach(() => {
    closeApp(app, dbPath);
  });

  it(
    "creates all demo users that can authenticate, and is idempotent",
    async () => {
      const first = await seedDemoUsers(app.locals.db);
      expect(first).toHaveLength(DEMO_USERS.length);
      expect(first.every((row) => row.status === "created")).toBe(true);

      const samples = [DEMO_USERS[0], DEMO_USERS[3], DEMO_USERS[DEMO_USERS.length - 1]];
      for (const demo of samples) {
        await expect(
          verifyPasswordLogin(app.locals.db, {
            email: demo.email,
            password: demo.password,
          }),
        ).resolves.toMatchObject({ email: demo.email, mfa_enabled: false });
      }

      const login = await request(app).post("/login").send({
        email: samples[2].email,
        password: samples[2].password,
      });
      expect(login.status).toBe(200);
      expect(login.body.status).toBe("MFA_ENROLLMENT_REQUIRED");
      expect(login.body.qr_data_url).toMatch(/^data:image\/png;base64,/);

      const second = await seedDemoUsers(app.locals.db);
      expect(second.every((row) => row.status === "skipped")).toBe(true);
      const count = app.locals.db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
      expect(count).toBe(DEMO_USERS.length);
    },
    60_000,
  );
});
