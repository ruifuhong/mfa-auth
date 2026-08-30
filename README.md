# mfa-auth

Localhost MVP for custom auth with:
- email/password
- mandatory TOTP MFA
- single-use backup codes
- server-side sessions

Stack: Express, SQLite (`better-sqlite3`), Vitest/Supertest.

---

## Quick Start

Requires Node.js 18+ (on Windows, `argon2` / `better-sqlite3` need a working C++ build toolchain).

```bash
npm install
npm run migrate
npm run seed          # demo accounts (idempotent; existing emails are skipped)
npm test              # should be green
npm start             # http://localhost:3000
```

- Browser demo: open [http://localhost:3000/](http://localhost:3000/) (minimal HTML, almost no CSS)
- Env example: [`.env.example`](.env.example) (the app does not auto-load `.env` for local MVP testing convenience; export vars in shell in production)

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | HTTP port | `3000` |
| `DATABASE_PATH` | SQLite path | `./data/app.sqlite` |
| `MFA_ENCRYPTION_KEY` | AES-256 key (64 hex chars = 32 bytes) | 64 zeros (local only) |
| `COOKIE_SECURE` | Set `true` to mark cookies Secure | unset (OK for localhost HTTP) |

Demo accounts (password for all: `password12345`):

- `alice@example.com`, `bob@example.com`, `carol@example.com`
- `test01@example.com` … `test20@example.com`
---

## User Flow

1. **Sign up** `POST /signup` → account exists; not logged in yet.
2. **First login** (MFA not enabled) → after a correct password, the server auto-enrolls TOTP, returns `MFA_ENROLLMENT_REQUIRED` + QR, and sets `sid`. `GET /me` is **403**.
3. **Confirm** `POST /mfa/confirm` → `mfa_enabled=true`; backup codes are shown **once**; then `/me` returns 200.
4. **Later logins** → correct password returns `MFA_REQUIRED` + `mfa_token` (**no** full session). `POST /mfa/verify` with TOTP or a backup code issues a new `sid`.
5. **Logout** → server sets `revoked_at`; cookie no longer works.

---

## 1. Filling gaps the prompt did not specify

The PRD only proposed desired features (signup, login, MFA, logout) without specifying details. Here are additional implementations that I consider necessary for a login/logout project:

### Added — And Why

| Addition | Why |
| --- | --- |
| **Pending MFA token** (no full `sid` on `MFA_REQUIRED`) | Password OK ≠ login complete; still need to finish MFA settings. |
| **Session tokens stored as SHA-256 only** | A DB leak should not yield usable cookies. |
| **TOTP seeds encrypted with AES-256-GCM** | Seeds are as sensitive as passwords; no plaintext in SQLite. |
| **Generic `Invalid credentials` on login failure** | Reduces account enumeration. |
| **Argon2 verify even when the user is missing** | Reduces obvious timing differences. |
| **Audit log** (success/fail/MFA/backup) | Forensics and future alerting. |

### Considered But Not Built — And Why

| Not built | Reason |
| --- | --- |
| Passkeys / WebAuthn | Better phishing resistance, but implementation exceed MVP time.|
| SMS / email OTP as primary MFA | SIM swap, inbox = reset channel, cost/deliverability. |
| Forgot-password / email verification | Easy to implement as an MFA bypass; better omit than ship a half-safe path. |
| Logout-all, device list, trusted devices | PRD asked for single-session revoke; multi-device needs more complex session settings. |
| Redis / KMS / multi-instance | Local single-process MVP; in-memory rate limit / pending tokens are acceptable here for MVP. |

---

## 2. Risk Assessment: What to Prioritize

Identity systems are attack targets. Limited time cannot cover everything; this is the priority order and rationale.

### Prioritized (Done)

| Risk | Why prioritize | How this project addresses it |
| --- | --- | --- |
| **Password dump / offline cracking** | Highest blast radius if DB leaks | Argon2id hasing so that passwords cannot be restored|
| **Stolen session that cannot be revoked** | Long-lived JWTs survive “logout” | Opaque cookie + `revoked_at`; token hashed at db |
| **Skipping the second factor** | MFA in name only | Forced enroll; no full session before `MFA_REQUIRED` verify; `/me` 403 until confirm |
| **Credential stuffing / brute force** | Most common remote abuse | Per-email and per-IP fail counts + temporary lock; skip Argon2 while locked |
| **TOTP seed leak** | Permanent second-factor compromise | AES-256-GCM at rest |
| **Backup codes as a second password file** | Plaintext codes are a backdoor | Shown once; SHA-256; single-use + audit |
| **Account enumeration** | Helps attackers build target lists | Generic error messages |

### Consciously Deferred (Or Only Partly Handled)

| Risk | Why not (fully) this round |
| --- | --- |
| **Phishing against TOTP** | Right fix is WebAuthn; traded for a finishable MFA story |
| **XSS stealing cookies** | HttpOnly blocks JS reads; full answer needs content security policy (CSP) |
| **Rate limit / pending MFA lost on process restart** | Single-node demo; production should use Redis (or similar) |
| **Key management / rotation** | Currently fixed in env key; production needs KMS for key rotation |
| **Account-recovery social engineering** (support MFA reset) | A naive “email reset” without process is more dangerous than omitting it |
| **Wipe all devices after theft** | No logout-all |
| **Advanced abuse** (OTP spam, residential proxies, slow spray) | Basic limiting only |

### Libraries vs What I Still Own

**No** full auth SaaS (Auth0, Firebase Auth, Cognito, Clerk, etc.).

| Dependency | What it covers | What I still own |
| --- | --- | --- |
| `argon2` | Memory-hard hashing algorithm | When to hash/verify, dummy hash, policy |
| `otpauth` | TOTP math and otpauth URI | Enrollment state machine, encrypted storage, replay, login wiring |
| `qrcode` | QR encoding | When to expose it; never return plaintext secret |
| `better-sqlite3` | Local persistence | Schema, semantics, backups, migrations |
| `express` + `cookie-parser` | HTTP / cookie parsing | Cookie flags, CSRF stance, auth middleware |

**Bottom line:** use libraries for crypto primitives; identity lifecycle, threat boundaries, and “can MFA be bypassed?” stay application responsibilities.

---

## 3. Trade-offs: Known Gaps And “Two More Days”

### Known Gaps / Unfinished

- Pending MFA and rate limits live **in memory** (lost on restart; not shared across instances)
- No **logout-all**, no session/device list
- No safe **forgot-password / lost-MFA** product flow (after backup codes are gone: recreate account or edit DB)
- Minimal UI is for demo only, not product UX

### If Given Two More Days

1. **Logout-all + list/revoke sessions** (actually recoverable after cookie theft)
2. **Move rate limit / pending MFA to SQLite or Redis** with tests (restart behavior becomes predictable)
3. **High-friction recovery sketch when backup codes are exhausted** (cooldown + audit + revoke all sessions; not “one email skips MFA”)

Not first: fancy UI or SMS — weak marginal return for risk and maintainability.

---

## Controls

| Control | Approach |
| --- | --- |
| Password | Argon2id |
| TOTP seed | AES-256-GCM |
| Backup codes | SHA-256, single-use, `used_at` |
| Session | Opaque `sid`, hashed in DB, revocable |
| Mandatory MFA | Auto-enroll; block `/me` until confirm |
| Rate limit | Per email/IP; skip Argon2 while locked |
| Audit | login / logout / MFA / backup events |

---

## Project Layout

```
src/app.js           routes + mandatory MFA state machine
src/users.js         signup / Argon2id
src/session.js       opaque sid
src/rate-limit.js    limiter (injectable clock)
src/audit.js         audit_logs
src/totp.js          otpauth / verify
src/crypto-secret.js AES-256-GCM
src/pending-mfa.js   MFA_REQUIRED tokens
src/backup-codes.js  backup codes
src/schema.sql       schema
public/index.html    minimal demo UI
scripts/migrate.js   apply schema
scripts/seed.js      demo accounts
tests/*.test.mjs     Vitest + Supertest
