import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";

const require = createRequire(import.meta.url);
const { createApp } = require("../src/app.js");

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
      email: "a@example.com",
      password: "correct-horse-battery-staple",
    });

    expect(res.status).toBe(201);
    expect(res.body.email).toBe("a@example.com");
    expect(res.body.id).toBeTruthy();
    expect(res.body.password).toBeUndefined();
    expect(res.body.password_hash).toBeUndefined();
  });
});
