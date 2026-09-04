"use strict";

const bcrypt = require("bcrypt");
const crypto = require("crypto");

const logger = require("../utils/logger");

// Merchant dashboard passwords.
//
// Cost 12 is a deliberate number, not a default: it is roughly 250ms on the
// production instance class, which is the most we will spend on a login without
// the p99 becoming a support ticket. Re-benchmark it when the instance changes.
const COST = 12;

async function hashPassword(plaintext) {
  const salt = await bcrypt.genSalt(COST);
  return bcrypt.hash(plaintext, salt);
}

/**
 * Verify a password.
 *
 * Always runs a comparison, even when the user does not exist, so the response
 * time does not distinguish "no such account" from "wrong password".
 */
async function verifyPassword(plaintext, storedHash) {
  if (!storedHash) {
    await bcrypt.compare(plaintext, DUMMY_HASH);
    return false;
  }
  return bcrypt.compare(plaintext, storedHash);
}

// A real hash of a value nobody knows, for the timing-equalising path above.
const DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.eS9M1nJ1AVc2mMLxu1JqQKQ0Zg0BqUu";

/**
 * Single-use password reset tokens.
 *
 * The token goes to the user; only its digest is stored, so a database read
 * does not hand anybody a working reset link.
 */
function issueResetToken() {
  const token = crypto.randomBytes(32).toString("base64url");
  const digest = crypto.createHash("sha256").update(token).digest("hex");
  return { token, digest, expiresAt: new Date(Date.now() + 3600_000) };
}

function resetTokenDigest(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

module.exports = { hashPassword, verifyPassword, issueResetToken, resetTokenDigest, COST };
