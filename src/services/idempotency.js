"use strict";

const crypto = require("crypto");

const logger = require("../utils/logger");

// Idempotency for the payments API.
//
// A merchant retrying a charge after a timeout must not be charged twice, so
// every mutating request carries an Idempotency-Key and we remember the
// response we gave for it.
//
// The stored key is a digest of the client key AND the request body: replaying
// the same key with a different body is a client bug, and returning the first
// response for it would hide the bug behind a success.

const KEY_TTL_HOURS = 24;

function requestFingerprint(idempotencyKey, merchantId, method, path, body) {
  return crypto
    .createHash("sha256")
    .update(idempotencyKey)
    .update("\x00")
    .update(merchantId)
    .update("\x00")
    .update(`${method} ${path}`)
    .update("\x00")
    .update(typeof body === "string" ? body : JSON.stringify(body ?? {}))
    .digest("hex");
}

function newRequestId() {
  return crypto.randomUUID();
}

/**
 * Payment intent references handed to merchants. Random rather than sequential
 * so the identifier does not leak how many payments the platform has taken.
 */
function newPaymentReference() {
  return `pi_${crypto.randomBytes(18).toString("base64url")}`;
}

/**
 * Constant-time comparison for anything a caller supplies and we compare
 * against a stored value -- an early-exit compare on a token is a timing oracle.
 */
function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

module.exports = {
  requestFingerprint,
  newRequestId,
  newPaymentReference,
  safeEqual,
  KEY_TTL_HOURS,
};
