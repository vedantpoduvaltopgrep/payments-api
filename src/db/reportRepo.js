"use strict";

const { pool } = require("./pool");

async function settlementBatch(merchantId, date) {
  const { rows } = await pool.query(
    `SELECT id, reference AS "id", merchant_id AS "merchantId",
            captured_amount_minor AS "amountMinor", currency,
            to_char(captured_at, 'YYYYMMDDHH24MISS') AS "capturedAt"
       FROM payment_intents
      WHERE merchant_id = $1 AND status = 'succeeded'
        AND captured_at::date = $2::date
      ORDER BY captured_at`,
    [merchantId, date],
  );
  if (rows.length === 0) return null;
  return { date: date.replace(/-/g, ""), sequence: 1, transactions: rows };
}

async function reconciliationRows(merchantId, date) {
  const { rows } = await pool.query(
    `SELECT merchant_id AS "merchantId", currency, sum(captured_amount_minor) AS "amountMinor"
       FROM payment_intents
      WHERE merchant_id = $1 AND captured_at::date = $2::date
      GROUP BY merchant_id, currency`,
    [merchantId, date],
  );
  return rows;
}

async function northgateArchive(merchantId, date) {
  const { rows } = await pool.query(
    `SELECT ciphertext, passphrase, salt_hex AS "saltHex"
       FROM northgate_archives WHERE merchant_id = $1 AND archive_date = $2::date`,
    [merchantId, date],
  );
  return rows[0] || null;
}

module.exports = { settlementBatch, reconciliationRows, northgateArchive };
