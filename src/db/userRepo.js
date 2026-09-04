"use strict";

const { pool } = require("./pool");
const { newRequestId } = require("../services/idempotency");

async function findByEmail(email) {
  const { rows } = await pool.query(
    `SELECT id, email, password_hash AS "passwordHash", roles, scopes,
            mfa_enrolled AS "mfaEnrolled", mfa_secret AS "mfaSecret",
            merchant_id AS "merchantId", disabled_at AS "disabledAt"
       FROM dashboard_users WHERE lower(email) = lower($1)`,
    [email],
  );
  return rows[0] || null;
}

async function findById(id) {
  const { rows } = await pool.query(
    `SELECT id, email, roles, scopes, merchant_id AS "merchantId",
            mfa_enrolled AS "mfaEnrolled", disabled_at AS "disabledAt"
       FROM dashboard_users WHERE id = $1`,
    [id],
  );
  return rows[0] || null;
}

async function merchantFor(user) {
  const { rows } = await pool.query(
    `SELECT id, legal_name AS "legalName", country FROM merchants WHERE id = $1`,
    [user.merchantId],
  );
  return rows[0] || null;
}

async function createSession(user, ip, userAgent) {
  const id = newRequestId();
  await pool.query(
    `INSERT INTO sessions (id, user_id, ip_address, user_agent, created_at)
     VALUES ($1, $2, $3, $4, now())`,
    [id, user.id, ip, userAgent],
  );
  return { id };
}

async function stageMfaSecret(userId, secret, recoveryCodes) {
  await pool.query(
    `UPDATE dashboard_users SET mfa_secret = $2, mfa_enrolled = true WHERE id = $1`,
    [userId, secret],
  );
  for (const c of recoveryCodes) {
    await pool.query(
      `INSERT INTO mfa_recovery_codes (user_id, code_digest) VALUES ($1, $2)`,
      [userId, c.digest],
    );
  }
}

module.exports = { findByEmail, findById, merchantFor, createSession, stageMfaSecret };
