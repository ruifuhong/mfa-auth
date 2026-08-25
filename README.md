# mfa-auth

Localhost MVP: custom email/password authentication with **server-side sessions**, **TOTP MFA**, and **single-use backup codes**. Built as a 12–16 hour security-first exercise (Express + SQLite + Vitest).

## Quick start

Requires Node.js 18+ (native `argon2` / `better-sqlite3` need a working C++ toolchain on Windows).

```bash
npm install
npm run migrate
npm test
npm start
```

The API listens on [http://localhost:3000](http://localhost:3000). Schema is applied automatically when the process opens SQLite (`data/app.sqlite`). `npm run migrate` does the same without starting HTTP.

Optional environment (see [`.env.example`](.env.example)):

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | HTTP port | `3000` |
| `DATABASE_PATH` | SQLite file | `./data/app.sqlite` |
| `MFA_ENCRYPTION_KEY` | 32-byte AES key as **64 hex chars** | 64 zeros (dev only) |
| `COOKIE_SECURE` | Set `true` behind HTTPS | unset (`Secure` cookie off for localhost HTTP) |

This repo does not load a `.env` file automatically. Export variables in the shell, or keep the built-in defaults for local demos.

```bash
npm test          # vitest run — must stay green before commits
npm run test:watch
```

On Windows PowerShell, use `curl.exe` (not the `curl` alias) for the examples below.

## API specification

Base URL: `http://localhost:3000`

Session cookie name: **`sid`** (`HttpOnly`, `SameSite=Lax`, `Path=/`). SQLite stores a **SHA-256 hash** of the token, not the raw cookie.

Password minimum length: **8**. Emails are trimmed and lowercased.

### `POST /signup`

Creates a user. Password is hashed with **Argon2id**. The hash is never returned.

```bash
curl.exe -sS -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
```

**201** `{ "id": "<uuid>", "email": "you@example.com" }`  
**400** invalid payload · **409** email already registered

### `POST /login`

Verifies the password. If MFA is **off**, sets `sid` and returns the user. If MFA is **on**, does **not** set `sid`; returns a short-lived pending token instead.

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -D - -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
```

Without MFA: **200** `{ "id", "email", "mfa_enabled": false }` plus `Set-Cookie: sid=...`  
With MFA: **200** `{ "status": "MFA_REQUIRED", "mfa_token": "<opaque>" }`  
**401** `{ "error": "Invalid credentials" }` (generic; no user enumeration)  
**429** `{ "error": "Too many attempts" }` after too many failures (per email and per IP)

### `POST /mfa/enroll`

Requires a live `sid`. Generates a TOTP seed, stores it **encrypted** (AES-256-GCM), returns an `otpauth://` URI and a PNG QR as a data URL. Does not enable MFA until confirm. **409** if MFA is already enabled.

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/enroll
```

**200** `{ "otpauth_uri": "otpauth://totp/...", "qr_data_url": "data:image/png;base64,..." }`  
**401** no/invalid session

Scan `otpauth_uri` with an authenticator app, or extract the `secret=` query param and generate a code (example with `oathtool`):

```bash
oathtool --totp -b "<BASE32_SECRET>"
```

### `POST /mfa/confirm`

Requires `sid`. Verifies the first 6-digit TOTP, sets `mfa_enabled` and `confirmed_at`, and returns **8 backup codes once**.

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/confirm \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"123456\"}"
```

**200** `{ "mfa_enabled": true, "backup_codes": ["abcd-ef01-...", ...] }`  
Save the backup codes; they are stored only as SHA-256 hashes.  
**401** invalid TOTP · **400** not enrolled / already confirmed

### `POST /mfa/verify`

Completes login after `MFA_REQUIRED`. Body: pending `mfa_token` plus either a 6-digit TOTP **or** a backup code. On success, issues a **new** `sid` (session fixation defense).

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/verify \
  -H "Content-Type: application/json" \
  -d "{\"mfa_token\":\"PASTE_TOKEN_FROM_LOGIN\",\"code\":\"123456\"}"
```

Backup code (example):

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/verify \
  -H "Content-Type: application/json" \
  -d "{\"mfa_token\":\"PASTE_TOKEN_FROM_LOGIN\",\"code\":\"abcd-ef01-2345-6789\"}"
```

**200** `{ "id", "email", "mfa_enabled": true }` plus `Set-Cookie: sid=...`  
**401** bad/expired pending token, wrong TOTP, reused TOTP step, or used/unknown backup code

A used backup code sets `used_at` and writes `backup_code_used` to `audit_logs`.

### `GET /me`

Requires a valid, unrevoked, unexpired `sid`. A pending MFA token is **not** a session.

```bash
curl.exe -sS -c cookies.txt -b cookies.txt http://localhost:3000/me
```

**200** `{ "id", "email", "mfa_enabled" }` · **401** `{ "error": "Unauthorized" }`

### `POST /logout`

Revokes **this** session (`revoked_at`) and clears `sid`. Idempotent if already logged out.

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/logout -D -
```

**204** empty body

### End-to-end (no MFA, then enroll)

```bash
# 1. Signup
curl.exe -sS -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"

# 2. Login (session cookie)
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"

# 3. Who am I
curl.exe -sS -c cookies.txt -b cookies.txt http://localhost:3000/me

# 4. Enroll TOTP, then confirm with a live authenticator code
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/enroll
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/confirm \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"REPLACE_WITH_TOTP\"}"

# 5. Logout, login again → MFA_REQUIRED, then verify
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/logout
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
# paste mfa_token from the previous JSON:
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/verify \
  -H "Content-Type: application/json" \
  -d "{\"mfa_token\":\"REPLACE\",\"code\":\"REPLACE_WITH_TOTP_OR_BACKUP\"}"

curl.exe -sS -c cookies.txt -b cookies.txt http://localhost:3000/me
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/logout
```

## Security architecture (for interviewers)

### Why opaque server-side sessions, not long-lived JWTs

Logout must take effect **immediately**. A JWT is valid until `exp` unless you add a denylist or version stamp—which is a session store by another name. Here the cookie is a high-entropy random token; the server looks up a hashed row and can set `revoked_at` on logout. Stolen cookies can be invalidated without waiting for TTL.

Access tokens that last hours and cannot be revoked are a poor fit for login/logout MFA. Short-lived JWTs plus rotating refresh tokens are reasonable for native/SPA multi-API setups; this MVP is a first-party browser API, so a **`sid` cookie + SQLite** is the boring, correct default.

Pending MFA uses a separate in-memory token: password success does not mint a full session, so `GET /me` stays 401 until TOTP or a backup code succeeds.

### What is implemented

| Control | How |
| --- | --- |
| Password hashing | **Argon2id** (`argon2` library). Dummy verify path so missing users still pay hash cost. |
| TOTP seed at rest | **AES-256-GCM**; key from `MFA_ENCRYPTION_KEY` (not stored next to the seed in plaintext). |
| Backup codes | 8 × 64-bit hex codes shown **once**; **SHA-256** of the normalized value in `backup_codes`. High-entropy secrets do not need Argon2. `used_at` enforces single use. |
| Session cookie | `HttpOnly`, `SameSite=Lax`. Raw token only in the cookie; DB holds SHA-256. |
| Session fixation | New session id after password login (no MFA) and after `POST /mfa/verify`. |
| Brute force | In-memory limiter: 10 failed logins per email and per IP / 15 minutes, then 15-minute lock. Locked accounts skip Argon2. |
| Audit | `login_success`, `login_failed`, `logout`, `mfa_enrolled`, `mfa_challenge_failed`, `backup_code_used`. |
| TOTP replay | Same time-step code cannot be reused for login verify. |
| Errors | Login failures are generic (`Invalid credentials`). |

Tests inject a clock and a known TOTP secret so crypto behavior is deterministic without weakening production defaults.

### Intentionally out of scope (12–16h MVP)

- **Passkeys / WebAuthn** — origin-bound phishing resistance is the right long-term second factor; it needs RP ID, attestation, and browser lab tests. TOTP is enough to prove MFA + encryption + challenge/response in this window.
- **SMS / email OTP** — SIM swap, inbox-equals-password-reset, and deliverability. TOTP is local and cheap.
- **Trusted devices / “remember this computer”** — extra long-lived tokens and revocation UX; easy to get wrong.
- **Logout-all / JWT refresh rotation** — PRD asked for single-session revoke only.
- **Styled UI** — API + curl/Postman; less surface, faster review.
- **Production KMS, Redis cluster, fraud scoring** — localhost SQLite and an in-memory limiter match the scale of a demo, not a 100k-user IdP.

Trade-off: in-memory rate limits and pending MFA tokens do not survive process restart. That is acceptable for a single-node MVP; a deploy would move them to Redis with the same keys and TTLs.

## Project layout

```
src/app.js           HTTP routes
src/users.js         signup / Argon2id verify
src/session.js       opaque sid create / lookup / revoke
src/rate-limit.js    email + IP lockout (clock-injectable)
src/audit.js         audit_logs writes
src/totp.js          otpauth URI + verify
src/crypto-secret.js AES-256-GCM
src/pending-mfa.js   MFA_REQUIRED tokens
src/backup-codes.js  generate / hash / consume
src/schema.sql       SQLite tables
tests/*.test.mjs     Vitest + Supertest
```
