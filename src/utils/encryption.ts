import crypto from "crypto";

const IV_LENGTH = 16;

const rawKey = process.env.H3_OAUTH_ENCRYPTION_KEY;

if (!rawKey || rawKey.length !== 64) {
  throw new Error(
    "[h3-oauth-kit] H3_OAUTH_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)."
  );
}

const ENCRYPTION_KEY = Buffer.from(rawKey, "hex");

export function encrypt(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

export function decrypt(encryptedText: string): string {
  const [ivHex, encryptedHex] = encryptedText.split(":");

  const iv = Buffer.from(ivHex, "hex");

  const encrypted = Buffer.from(encryptedHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString();
}
