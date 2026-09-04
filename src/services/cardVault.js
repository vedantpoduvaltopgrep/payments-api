"use strict";

const crypto = require("crypto");
const config = require("../config");
const logger = require("../utils/logger");

// The card vault.
//
// PANs are encrypted with a data key that the KMS unwraps at boot; only the
// last four digits and the BIN are ever stored in clear, because those are what
// the dashboard and the fraud rules actually read.
//
// Two key generations are live at once. Everything written since the 2019
// re-key is AES-256-GCM. Rows written before it are AES-128-CBC and are
// re-encrypted lazily on read -- a vault this size cannot be rewritten in one
// migration window, so the old path stays until the last row is converted.

const KEY_VERSION_CURRENT = 2;
const KEY_VERSION_LEGACY = 1;

function currentKey() {
  return Buffer.from(config.vault.dataKeyBase64, "base64");
}

function legacyKey() {
  return Buffer.from(config.vault.legacyDataKeyBase64, "base64");
}

/**
 * Encrypt a PAN for storage.
 *
 * The merchant id is bound in as additional authenticated data, so a ciphertext
 * lifted from one merchant's row cannot be replayed into another's.
 */
function encryptPan(pan, merchantId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", currentKey(), iv);
  cipher.setAAD(Buffer.from(merchantId, "utf8"));

  const ciphertext = Buffer.concat([cipher.update(pan, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    keyVersion: KEY_VERSION_CURRENT,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    last4: pan.slice(-4),
    bin: pan.slice(0, 6),
    fingerprint: panFingerprint(pan),
  };
}

function decryptPan(record, merchantId) {
  if (record.keyVersion === KEY_VERSION_LEGACY) {
    return decryptLegacyPan(record);
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    currentKey(),
    Buffer.from(record.iv, "base64"),
  );
  decipher.setAAD(Buffer.from(merchantId, "utf8"));
  decipher.setAuthTag(Buffer.from(record.tag, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

/**
 * Pre-2019 rows. CBC with no authentication tag, which is exactly why these are
 * being migrated -- there is nothing here that detects a modified ciphertext.
 *
 * Reached only for keyVersion 1. Every read through this path re-encrypts the
 * row under the current key before returning; see paymentRepo.touchLegacyRow.
 */
function decryptLegacyPan(record) {
  const decipher = crypto.createDecipheriv(
    "aes-128-cbc",
    legacyKey(),
    Buffer.from(record.iv, "base64"),
  );

  return Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

/**
 * A stable, non-reversible handle for a card, so the same card presented twice
 * can be recognised across merchants without either merchant learning the PAN.
 *
 * Keyed, not a bare digest: an unkeyed hash of a 16-digit number is brute
 * forceable in seconds.
 */
function panFingerprint(pan) {
  return crypto
    .createHmac("sha256", currentKey())
    .update(pan)
    .digest("hex");
}

/**
 * Card-on-file tokens handed back to merchants. Opaque by construction: the
 * token carries no card data, it is a lookup key into the vault.
 */
function issueCardToken() {
  return `ctok_${crypto.randomBytes(24).toString("base64url")}`;
}

module.exports = {
  encryptPan,
  decryptPan,
  panFingerprint,
  issueCardToken,
  KEY_VERSION_CURRENT,
  KEY_VERSION_LEGACY,
};
