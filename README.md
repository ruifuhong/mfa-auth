# mfa-auth

Localhost MVP for custom auth with:
- Email / password
- Mandatory TOTP MFA
- Single-use backup codes
- Server-side sessions

Stack: Express, SQLite (`better-sqlite3`), Vitest/Supertest

---

## Medium Articles

1. [大哉問：「幫我做一個登入登出功能」第一篇－超基礎功能 The Great Challenge: “Build a Login and Logout Feature for Me” — Part 1: The Absolute Basics](https://medium.com/@ralph-tech/%E4%B8%AD%E8%8B%B1%E9%9B%99%E8%AA%9E-zh-en-bilingual-%E5%A4%A7%E5%93%89%E5%95%8F-%E5%B9%AB%E6%88%91%E5%81%9A%E4%B8%80%E5%80%8B%E7%99%BB%E5%85%A5%E7%99%BB%E5%87%BA%E5%8A%9F%E8%83%BD-%E7%AC%AC%E4%B8%80%E7%AF%87-%E8%B6%85%E5%9F%BA%E7%A4%8E%E5%8A%9F%E8%83%BD-the-great-question-build-a-login-and-logout-1372dc69f27b)
1. [大哉問：「幫我做一個登入登出功能」第二篇－多重要素驗證 The Great Challenge: “Build a Login and Logout Feature for Me” — Part 2: Multi-Factor Authentication (MFA)](https://medium.com/@ralph-tech/%E4%B8%AD%E8%8B%B1%E9%9B%99%E8%AA%9E-zh-en-bilingual-%E5%A4%A7%E5%93%89%E5%95%8F-%E5%B9%AB%E6%88%91%E5%81%9A%E4%B8%80%E5%80%8B%E7%99%BB%E5%85%A5%E7%99%BB%E5%87%BA%E5%8A%9F%E8%83%BD-%E7%AC%AC%E4%BA%8C%E7%AF%87-%E5%A4%9A%E9%87%8D%E8%A6%81%E7%B4%A0%E9%A9%97%E8%AD%89-the-great-question-build-a-login-and-logout-630f091a9d96)
1. [大哉問：「幫我做一個登入登出功能」第三篇－使用者體驗流程說明 The Great Challenge: “Build a Login and Logout Feature for Me” — Part 3: User Experience Flow Description](https://medium.com/@ralph-tech/%E4%B8%AD%E8%8B%B1%E9%9B%99%E8%AA%9E-zh-en-bilingual-%E5%A4%A7%E5%93%89%E5%95%8F-%E5%B9%AB%E6%88%91%E5%81%9A%E4%B8%80%E5%80%8B%E7%99%BB%E5%85%A5%E7%99%BB%E5%87%BA%E5%8A%9F%E8%83%BD-%E7%AC%AC%E4%B8%89%E7%AF%87-%E4%BD%BF%E7%94%A8%E8%80%85%E9%AB%94%E9%A9%97%E6%B5%81%E7%A8%8B%E8%AA%AA%E6%98%8E-the-great-challenge-build-a-login-and-55504dc18496)

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

## User Flow

1. **Sign up** `POST /signup` → account exists; not logged in yet.
2. **First login** (MFA not enabled) → after a correct password, the server auto-enrolls TOTP, returns `MFA_ENROLLMENT_REQUIRED` + QR, and sets `sid`. `GET /me` is **403**.
3. **Confirm** `POST /mfa/confirm` → `mfa_enabled=true`; backup codes are shown **once**; then `/me` returns 200.
4. **Later logins** → correct password returns `MFA_REQUIRED` + `mfa_token` (**no** full session). `POST /mfa/verify` with TOTP or a backup code issues a new `sid`.
5. **Logout** → server sets `revoked_at`; cookie no longer works.

## Security Features

This project contains the following features:

- Signup
- Login
- MFA
- Logout

with the following security design:

### Already Applied

| Designs | Description |
| --- | --- |
| **Pending MFA token** (no full `sid` on `MFA_REQUIRED`) | Password OK ≠ login complete; still need to finish MFA settings. |
| **Session tokens stored as SHA-256 only** | A DB leak should not yield usable cookies. |
| **TOTP seeds encrypted with AES-256-GCM** | Seeds are as sensitive as passwords; no plaintext in SQLite. |
| **Generic `Invalid credentials` on login failure** | Reduces account enumeration. |
| **Argon2 verify even when the user is missing** | Reduces obvious timing differences. |
| **Audit log** | Forensics and future alerting. |

### Not Applied Yet

| Designs | Description |
| --- | --- |
| Passkeys / WebAuthn | Better phishing resistance, but implementation exceed MVP time.|
| SMS / email OTP as primary MFA | SIM swap, inbox = reset channel, cost / deliverability. |
| Forgot-password / email verification | Easy to implement as an MFA bypass; better omit than ship a half-safe path. |
| Logout-all, device list, trusted devices | Multi-device needs more complex session settings. |
| Redis / KMS / multi-instance | In-memory limits / tokens acceptable on one process for MVP, but will need Redis / DB for shared state and KMS for key rotation for production. |

## Libraries

**No** full auth SaaS (Auth0, Firebase Auth, Cognito, Clerk, etc.).

| Dependency | Description | Local Settings |
| --- | --- | --- |
| `argon2` | Memory-hard hashing algorithm | When to hash / verify, dummy hash, policy |
| `otpauth` | TOTP math and otpauth URI | Enrollment flow, encrypted TOTP seed storage, allowed window and code reuse prevention, login logic design |
| `qrcode` | QR encoding | Expose timing; never return plaintext secret |
| `better-sqlite3` | Local persistence | Schema, semantics, migrations |
| `express` + `cookie-parser` | HTTP / cookie parsing | Cookie flags (`HttpOnly: true`, `SameSite: lax`), auth middleware |

## Safety Controls

| Control | Approach |
| --- | --- |
| Password | Argon2id |
| TOTP seed | AES-256-GCM |
| Backup codes | SHA-256, single-use, `used_at` |
| Session | Opaque `sid`, hashed in DB, revocable |
| Mandatory MFA | Auto-enroll; block `/me` until confirm |
| Rate limit | Per email / IP; skip Argon2 while locked |
| Audit | Login / logout / MFA / backup events |
