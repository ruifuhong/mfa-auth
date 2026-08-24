const crypto = require("node:crypto");

function parseEncryptionKey(hex) {
  const value = hex ?? process.env.MFA_ENCRYPTION_KEY;
  if (!value || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("MFA_ENCRYPTION_KEY must be 32 bytes as 64 hex characters");
  }
  return Buffer.from(value, "hex");
}

function encryptSecret(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

function decryptSecret(payload, key) {
  const [ivB64, tagB64, dataB64] = String(payload).split(".");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64url"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

module.exports = { parseEncryptionKey, encryptSecret, decryptSecret };
