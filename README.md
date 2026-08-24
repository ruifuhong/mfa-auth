# mfa-auth

Localhost MVP: custom email/password auth with server-side sessions and TOTP MFA.

## Setup

```bash
npm install
copy .env.example .env
npm run migrate
npm test
npm start
```

## Tests

Vitest + Supertest. Slice 1 starts with a failing `POST /signup` test (`tests/password-session.test.js`).
