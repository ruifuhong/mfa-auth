# mfa-auth

Localhost MVP for **custom** auth (not Auth0/Cognito): **email/password + mandatory TOTP MFA + single-use backup codes + server-side sessions**.  
Stack: Express, SQLite (`better-sqlite3`), Vitest/Supertest.

This README is both a handoff doc and the assignment write-up: someone else should be able to run the project and understand the trade-offs without asking you.

---

## Quick start

Requires Node.js 18+ (on Windows, `argon2` / `better-sqlite3` need a working C++ build toolchain).

```bash
npm install
npm run migrate
npm run seed          # demo accounts (idempotent; existing emails are skipped)
npm test              # should be green
npm start             # http://localhost:3000
```

- Browser demo: open [http://localhost:3000/](http://localhost:3000/) (minimal HTML, almost no CSS)
- API and curl: see **API** below
- Env example: [`.env.example`](.env.example) (**the app does not auto-load `.env`**; export vars in your shell or use defaults)

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | HTTP port | `3000` |
| `DATABASE_PATH` | SQLite path | `./data/app.sqlite` |
| `MFA_ENCRYPTION_KEY` | AES-256 key (64 hex chars = 32 bytes) | 64 zeros (local only) |
| `COOKIE_SECURE` | Set `true` to mark cookies Secure | unset (OK for localhost HTTP) |

Demo accounts (password for all: `password12345`):

- `alice@example.com`, `bob@example.com`, `carol@example.com`
- `test01@example.com` … `test20@example.com`

On PowerShell use `curl.exe`; in Git Bash plain `curl` is fine.

---

## User flow (mandatory MFA)

1. **Sign up** `POST /signup` → account exists; not logged in yet.  
2. **First login** (MFA not enabled) → after a correct password, the server **auto-enrolls** TOTP, returns `MFA_ENROLLMENT_REQUIRED` + QR, and sets `sid`. `GET /me` is **403**.  
3. **Confirm** `POST /mfa/confirm` → `mfa_enabled=true`; backup codes are shown **once**; then `/me` returns 200.  
4. **Later logins** → correct password returns `MFA_REQUIRED` + `mfa_token` (**no** full session). `POST /mfa/verify` with TOTP or a backup code issues a new `sid`.  
5. **Logout** → server sets `revoked_at`; cookie no longer works.

---

## 1. Filling gaps the prompt did not specify

The prompt/PRD mostly named features (signup, login, TOTP, backup, logout, rate limit). Shipping still needs a state machine, failure modes, testability, and handoff. Below is what I added by judgment.

### Added — and why

| Addition | Why |
| --- | --- |
| **Mandatory MFA** (auto QR when MFA is off; `/me` returns 403 until confirm) | Optional MFA leaves half the accounts single-factor. An identity system should default to a high bar. |
| **Pending MFA token** (no full `sid` on `MFA_REQUIRED`) | Password OK ≠ login complete; otherwise the second factor is theater. |
| **Session tokens stored as SHA-256 only** | A DB leak should not yield usable cookies. |
| **TOTP seeds encrypted with AES-256-GCM** | Seeds are as sensitive as passwords; no plaintext in SQLite. |
| **TOTP same-step replay rejection** | Shrinks replay / concurrent-verify window. |
| **Generic `Invalid credentials` on login failure** | Reduces account enumeration. |
| **Argon2 verify even when the user is missing** | Reduces obvious timing differences. |
| **Audit log** (success/fail/MFA/backup) | Forensics and future alerting. |
| **Injectable clock for rate limits + known TOTP secret in tests** | Security behavior must be testable, not “feels secure.” |
| **TDD slices + Conventional Commits** | Reviewers can see decision order instead of one opaque dump. |
| **Minimal HTML + `npm run seed`** | Curl is enough for the brief; UI lowers “cannot run / cannot try MFA” friction. |

### Considered but not built — and why

| Not built | Reason |
| --- | --- |
| Full IdP (Auth0 / Clerk / Cognito) | The exercise asks for a custom identity lifecycle. Outsourcing that is a blank submission. Crypto/DB libraries only; the state machine is ours. |
| Passkeys / WebAuthn | Better phishing resistance, but RP ID and browser lab work exceed MVP time. TOTP still proves challenge, encryption, and recovery codes. |
| SMS / email OTP as primary MFA | SIM swap, inbox = reset channel, cost/deliverability. |
| Forgot-password / email verification | Easy to implement as an MFA bypass; better omit than ship a half-safe path. |
| Logout-all, device list, trusted devices | PRD asked for single-session revoke; multi-device needs its own threat model. |
| Redis / KMS / multi-instance | Local single-process MVP; in-memory rate limit / pending tokens are acceptable here. |
| Polished frontend | Grows surface area and schedule; little gain for the auth core. |

---

## 2. Risk assessment: what to prioritize

Identity systems are attack targets. Limited time cannot cover everything; this is the priority order and rationale.

### Prioritized (done or “good enough”)

| Risk | Why prioritize | How this project addresses it |
| --- | --- | --- |
| **Password dump / offline cracking** | Highest blast radius if DB leaks | Argon2id; hashes never returned |
| **Stolen session that cannot be revoked** | Long-lived JWTs survive “logout” | Opaque cookie + `revoked_at`; token hashed at rest |
| **Skipping the second factor** | MFA in name only | Forced enroll; no full session before `MFA_REQUIRED` verify; `/me` 403 until confirm |
| **Credential stuffing / brute force** | Most common remote abuse | Per-email and per-IP fail counts + temporary lock; skip Argon2 while locked |
| **TOTP seed leak** | Permanent second-factor compromise | AES-256-GCM at rest |
| **Backup codes as a second password file** | Plaintext codes are a backdoor | Shown once; SHA-256; single-use + audit |
| **Session fixation** | Pre-login cookie bound to a new login | New session after MFA verify |
| **Account enumeration** | Helps attackers build target lists | Generic error messages |

### Consciously deferred (or only partly handled)

| Risk | Why not (fully) this round |
| --- | --- |
| **Phishing against TOTP** | Right fix is WebAuthn; traded for a finishable MFA story |
| **XSS stealing cookies** | HttpOnly blocks JS reads; full answer needs CSP/template hygiene — almost no server HTML templates here |
| **CSRF** | `SameSite=Lax` helps same-site forms; no double-submit/CSRF token (API + same-origin fetch demo) |
| **Rate limit / pending MFA lost on process restart** | Single-node demo; production should use Redis (or similar) |
| **Key management / rotation** | Fixed env key; production needs KMS |
| **Account-recovery social engineering** (support MFA reset) | A naive “email reset” without process is more dangerous than omitting it |
| **Wipe all devices after theft** | No logout-all |
| **Advanced abuse** (OTP spam, residential proxies, slow spray) | Basic limiting only |

### Libraries vs what I still own

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

## 3. Collaboration: commits and a runnable README

### Git

Feature-sliced commits with Conventional Commit messages so `git log` reconstructs decisions:

1. `chore: initialize project scaffold and database schema`
2. `feat(auth): implement signup, password login, session cookie, and logout`
3. `feat(security): implement rate limiting, lockout, and audit logs`
4. `feat(mfa): implement TOTP enrollment, confirmation, and login challenge`
5. `feat(recovery): implement single-use hashed backup codes`
6. `docs: complete README with setup guide, curl examples, and security architecture`
7. `chore: add demo seed accounts and minimal browser UI`
8. `feat(mfa): force TOTP enrollment on first login with auto QR`
9. `docs: document design tradeoffs, risk priorities, and forced-MFA flows`

Rule of thumb: **tests first, green before commit**; do not mix a half MFA story with sessions in one unreviewable commit.

### README / runnability

- Quick start above: `install → migrate → seed → test → start`
- Browser and curl paths both documented
- Remaining sections explain *why*, to cut verbal handoff

Product questions that change the threat model (e.g. block `/me` before confirm) should be asked before coding them in stone — asking more is fine; guessing wrong is expensive.

---

## 4. Trade-offs: known gaps and “two more days”

### Known gaps / unfinished

- Pending MFA and rate limits live **in memory** (lost on restart; not shared across instances)  
- No **logout-all**, no session/device list  
- No safe **forgot-password / lost-MFA** product flow (after backup codes are gone: recreate account or edit DB)  
- No Passkeys, email verification, or admin console  
- No auto `.env` loading, formal migration tool, or Playwright E2E  
- README/seed briefly lagged forced MFA — **this version is source of truth**  
- Minimal UI is for demo only, not product UX  

### If given two more days — order

1. **Logout-all + list/revoke sessions** (actually recoverable after cookie theft)  
2. **Move rate limit / pending MFA to SQLite or Redis** with tests (restart behavior becomes predictable)  
3. **High-friction recovery sketch when backup codes are exhausted** (cooldown + audit + revoke all sessions; not “one email skips MFA”)  
4. If time remains: **step-up** (re-check TOTP before password change / regenerating backup codes) or a **WebAuthn prototype**

Not first: fancy UI or SMS — weak marginal return for risk and maintainability.

---

## API (summary)

Base: `http://localhost:3000`  
Cookie: `sid` (`HttpOnly`, `SameSite=Lax`); DB stores SHA-256 of the token.

### `POST /signup`

```bash
curl.exe -sS -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
```

**201** `{ id, email }` · **409** email already registered

### `POST /login`

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
```

- MFA not enabled yet: **200** `status: MFA_ENROLLMENT_REQUIRED` + `otpauth_uri` + `qr_data_url` + `Set-Cookie: sid`  
- MFA enabled: **200** `status: MFA_REQUIRED` + `mfa_token` (no sid)  
- **401** Invalid credentials · **429** Too many attempts  

### `POST /mfa/confirm` (requires `sid`, not yet confirmed)

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/confirm \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"123456\"}"
```

**200** `{ mfa_enabled: true, backup_codes: [...] }`

### `POST /mfa/verify` (nth login)

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/verify \
  -H "Content-Type: application/json" \
  -d "{\"mfa_token\":\"PASTE\",\"code\":\"123456\"}"
```

### `GET /me` · `POST /logout`

```bash
curl.exe -sS -c cookies.txt -b cookies.txt http://localhost:3000/me
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/logout
```

- Before confirm, `/me` → **403** `MFA_ENROLLMENT_REQUIRED`  
- Missing/invalid session → **401**  
- Logout → **204**

### `POST /mfa/enroll`

Manually regenerate QR (requires `sid`, MFA not yet enabled). First login usually auto-enrolls.

---

## Controls (cheat sheet)

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

## Project layout

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
```
