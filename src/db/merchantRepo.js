"use strict";

const { pool } = require("./pool");

async function findById(id) {
  const { rows } = await pool.query(
    `SELECT id, slug, legal_name AS "legalName", country, status
       FROM merchants WHERE id = $1`,
    [id],
  );
  return rows[0] || null;
}

async function findApiKeyByDigest(digest) {
  const { rows } = await pool.query(
    `SELECT merchant_id AS "merchantId", key_digest AS digest, mode,
            revoked_at AS "revokedAt"
       FROM merchant_api_keys WHERE key_digest = $1`,
    [digest],
  );
  return rows[0] || null;
}

async function storeApiKey(issued) {
  await pool.query(
    `INSERT INTO merchant_api_keys (merchant_id, key_prefix, key_digest, mode, created_at)
     VALUES ($1, $2, $3, $4, now())`,
    [issued.merchantId, issued.prefix, issued.digest, issued.mode || "live"],
  );
}

async function revokeApiKey(merchantId, prefix) {
  await pool.query(
    `UPDATE merchant_api_keys SET revoked_at = now()
      WHERE merchant_id = $1 AND key_prefix = $2 AND revoked_at IS NULL`,
    [merchantId, prefix],
  );
}

async function createWebhookEndpoint({ merchantId, url, events, secret }) {
  const { rows } = await pool.query(
    `INSERT INTO webhook_endpoints (merchant_id, url, events, secret, created_at)
     VALUES ($1, $2, $3, $4, now()) RETURNING id, url`,
    [merchantId, url, events, secret],
  );
  return rows[0];
}

async function storePartnerKey(merchantId, publicKeyPem) {
  await pool.query(
    `INSERT INTO partner_keys (merchant_id, public_key, created_at)
     VALUES ($1, $2, now())`,
    [merchantId, publicKeyPem],
  );
}

module.exports = {
  findById, findApiKeyByDigest, storeApiKey, revokeApiKey,
  createWebhookEndpoint, storePartnerKey,
};
