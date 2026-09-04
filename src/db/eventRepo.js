"use strict";

const { pool } = require("./pool");

async function recordInbound(source, event) {
  await pool.query(
    `INSERT INTO inbound_events (source, payload, received_at)
     VALUES ($1, $2, now())`,
    [source, event],
  );
}

async function schemeCertificate(keyId) {
  const { rows } = await pool.query(
    `SELECT certificate_pem FROM scheme_certificates WHERE key_id = $1 AND retired_at IS NULL`,
    [keyId],
  );
  if (!rows[0]) throw Object.assign(new Error("unknown scheme key id"), { status: 401 });
  return rows[0].certificate_pem;
}

async function northgateMerchant(merchantRef) {
  const { rows } = await pool.query(
    `SELECT merchant_id AS "merchantId", shared_secret AS "sharedSecret",
            envelope_key AS "envelopeKey"
       FROM northgate_merchants WHERE merchant_ref = $1`,
    [merchantRef],
  );
  if (!rows[0]) throw Object.assign(new Error("unknown northgate merchant"), { status: 401 });
  return rows[0];
}

module.exports = { recordInbound, schemeCertificate, northgateMerchant };
