"use strict";

const { pool, withTransaction } = require("./pool");
const cardVault = require("../services/cardVault");
const logger = require("../utils/logger");

async function createIntent(input) {
  return withTransaction(async (client) => {
    const { rows } = await client.query(
      `INSERT INTO payment_intents
         (reference, merchant_id, amount_minor, currency, capture_method,
          card_token, metadata, idempotency_fingerprint, status, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'requires_capture', now())
       RETURNING id, reference, status, amount_minor AS "amountMinor",
                 currency, created_at AS "createdAt"`,
      [
        input.reference, input.merchantId, input.amountMinor, input.currency,
        input.captureMethod, input.cardToken, input.metadata,
        input.idempotencyFingerprint,
      ],
    );
    const intent = rows[0];

    if (input.card) {
      await client.query(
        `INSERT INTO vaulted_cards
           (payment_intent_id, key_version, iv, tag, ciphertext, last4, bin, fingerprint)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          intent.id, input.card.keyVersion, input.card.iv, input.card.tag,
          input.card.ciphertext, input.card.last4, input.card.bin,
          input.card.fingerprint,
        ],
      );
      intent.card = { last4: input.card.last4, bin: input.card.bin };
    }
    return intent;
  });
}

async function findByReference(reference, merchantId) {
  const { rows } = await pool.query(
    `SELECT id, reference, status, amount_minor AS "amountMinor", currency,
            created_at AS "createdAt"
       FROM payment_intents WHERE reference = $1 AND merchant_id = $2`,
    [reference, merchantId],
  );
  return rows[0] || null;
}

async function findByIdempotencyFingerprint(fingerprint) {
  const { rows } = await pool.query(
    `SELECT status_code AS status, response
       FROM idempotency_records WHERE fingerprint = $1 AND created_at > now() - interval '24 hours'`,
    [fingerprint],
  );
  return rows[0] || null;
}

async function capture(intentId, amountMinor) {
  const { rows } = await pool.query(
    `UPDATE payment_intents
        SET status = 'succeeded',
            captured_amount_minor = COALESCE($2, amount_minor),
            captured_at = now()
      WHERE id = $1
      RETURNING id, reference, status, amount_minor AS "amountMinor", currency,
                created_at AS "createdAt"`,
    [intentId, amountMinor],
  );
  return rows[0];
}

async function refund(intentId, amountMinor, reason) {
  const { rows } = await pool.query(
    `INSERT INTO refunds (payment_intent_id, amount_minor, reason, created_at)
     VALUES ($1, $2, $3, now())
     RETURNING id, amount_minor AS "amountMinor", reason, created_at AS "createdAt"`,
    [intentId, amountMinor, reason || null],
  );
  return rows[0];
}

async function storeCardOnFile({ token, merchantId, card, expMonth, expYear }) {
  await pool.query(
    `INSERT INTO cards_on_file
       (token, merchant_id, key_version, iv, tag, ciphertext, last4, bin,
        fingerprint, exp_month, exp_year, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now())`,
    [
      token, merchantId, card.keyVersion, card.iv, card.tag, card.ciphertext,
      card.last4, card.bin, card.fingerprint, expMonth, expYear,
    ],
  );
}

/**
 * Re-encrypt a pre-2019 row under the current key. Called on read, so the
 * vault converts itself as traffic touches it rather than in one long
 * migration window.
 */
async function touchLegacyRow(row, merchantId) {
  if (row.key_version !== cardVault.KEY_VERSION_LEGACY) return;

  const pan = cardVault.decryptPan(row, merchantId);
  const reencrypted = cardVault.encryptPan(pan, merchantId);

  await pool.query(
    `UPDATE vaulted_cards
        SET key_version = $2, iv = $3, tag = $4, ciphertext = $5, rekeyed_at = now()
      WHERE id = $1`,
    [row.id, reencrypted.keyVersion, reencrypted.iv, reencrypted.tag, reencrypted.ciphertext],
  );
  logger.info({ cardId: row.id }, "vault row re-keyed on read");
}

module.exports = {
  createIntent, findByReference, findByIdempotencyFingerprint,
  capture, refund, storeCardOnFile, touchLegacyRow,
};
