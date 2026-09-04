"use strict";

const crypto = require("crypto");

const logger = require("../utils/logger");

// Merchant API keys.
//
// The key is shown once at creation. What we store is a digest, so a database
// dump does not hand anybody working credentials, and the prefix, so the
// dashboard can show which key is which without holding the key.

const LIVE_PREFIX = "ak_live";
const TEST_PREFIX = "ak_test";

function issueApiKey(merchantId, mode = "live") {
  const prefix = mode === "live" ? LIVE_PREFIX : TEST_PREFIX;
  const secret = crypto.randomBytes(32).toString("base64url");
  const key = `${prefix}_${secret}`;

  return {
    key,
    prefix: key.slice(0, 16),
    digest: digestApiKey(key),
    merchantId,
    createdAt: new Date(),
  };
}

/**
 * Keys are high-entropy random values, not passwords, so a plain SHA-256 is the
 * right primitive here -- there is nothing to brute force, and a slow KDF would
 * put bcrypt on the hot path of every API call.
 */
function digestApiKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

/**
 * Webhook endpoint secrets, for merchants who verify with an HMAC rather than
 * by pinning our certificate.
 */
function issueEndpointSecret() {
  return `whsec_${crypto.randomBytes(24).toString("base64url")}`;
}

function endpointSignature(secret, timestamp, body) {
  return crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
}

module.exports = {
  issueApiKey,
  digestApiKey,
  issueEndpointSecret,
  endpointSignature,
  LIVE_PREFIX,
  TEST_PREFIX,
};
