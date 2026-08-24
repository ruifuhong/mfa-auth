const OTPAuth = require("otpauth");

const ISSUER = "mfa-auth";
const PERIOD_MS = 30_000;

function createTotp({ secret, label }) {
  return new OTPAuth.TOTP({
    issuer: ISSUER,
    label,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

function generateSecret() {
  return new OTPAuth.Secret({ size: 20 }).base32;
}

function otpauthUri(secret, label) {
  return createTotp({ secret, label }).toString();
}

function verifyTotp(secret, label, code, timestamp) {
  const delta = createTotp({ secret, label }).validate({
    token: String(code ?? ""),
    timestamp,
    window: 1,
  });
  if (delta === null) {
    return null;
  }
  const step = Math.floor(timestamp / PERIOD_MS) + delta;
  return { step };
}

module.exports = { ISSUER, generateSecret, otpauthUri, verifyTotp, PERIOD_MS };
