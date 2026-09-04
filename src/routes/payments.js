"use strict";

const router = require("express").Router();
const { z } = require("zod");

const cardVault = require("../services/cardVault");
const idempotency = require("../services/idempotency");
const apiKeyService = require("../services/apiKeyService");
const { requireApiKey } = require("../middleware/auth");
const paymentRepo = require("../db/paymentRepo");
const merchantRepo = require("../db/merchantRepo");
const logger = require("../utils/logger");

router.use(requireApiKey((digest) => merchantRepo.findApiKeyByDigest(digest)));

const cardSchema = z.object({
  number: z.string().regex(/^[0-9]{12,19}$/),
  exp_month: z.number().int().min(1).max(12),
  exp_year: z.number().int().min(2024).max(2099),
  cvv: z.string().regex(/^[0-9]{3,4}$/),
});

const intentSchema = z.object({
  amount_minor: z.number().int().positive(),
  currency: z.string().length(3),
  capture_method: z.enum(["automatic", "manual"]).default("automatic"),
  card: cardSchema.optional(),
  card_token: z.string().startsWith("ctok_").optional(),
  metadata: z.record(z.string()).optional(),
});

router.post("/intents", async (req, res, next) => {
  try {
    const key = req.get("idempotency-key");
    if (!key) {
      return res.status(400).json({ error: "idempotency_key_required" });
    }

    const body = intentSchema.parse(req.body);
    const fingerprint = idempotency.requestFingerprint(
      key, req.merchant.id, req.method, req.path, req.body,
    );

    const replayed = await paymentRepo.findByIdempotencyFingerprint(fingerprint);
    if (replayed) {
      res.set("idempotent-replayed", "true");
      return res.status(replayed.status).json(replayed.response);
    }

    let vaulted = null;
    if (body.card) {
      // The PAN is encrypted before it touches the database and is never
      // logged. The CVV is not stored at all -- it is forwarded to the
      // acquirer for this authorisation and dropped.
      vaulted = cardVault.encryptPan(body.card.number, req.merchant.id);
    }

    const intent = await paymentRepo.createIntent({
      reference: idempotency.newPaymentReference(),
      merchantId: req.merchant.id,
      amountMinor: body.amount_minor,
      currency: body.currency.toUpperCase(),
      captureMethod: body.capture_method,
      card: vaulted,
      cardToken: body.card_token || null,
      metadata: body.metadata || {},
      idempotencyFingerprint: fingerprint,
    });

    return res.status(201).json(present(intent));
  } catch (err) {
    return next(err);
  }
});

router.post("/intents/:reference/capture", async (req, res, next) => {
  try {
    const intent = await paymentRepo.findByReference(req.params.reference, req.merchant.id);
    if (!intent) return res.status(404).json({ error: "not_found" });
    if (intent.status !== "requires_capture") {
      return res.status(409).json({ error: "invalid_state", state: intent.status });
    }

    const captured = await paymentRepo.capture(intent.id, req.body?.amount_minor);
    return res.json(present(captured));
  } catch (err) {
    return next(err);
  }
});

router.post("/intents/:reference/refund", async (req, res, next) => {
  try {
    const intent = await paymentRepo.findByReference(req.params.reference, req.merchant.id);
    if (!intent) return res.status(404).json({ error: "not_found" });

    const refund = await paymentRepo.refund(intent.id, req.body?.amount_minor, req.body?.reason);
    logger.info({ reference: intent.reference, refundId: refund.id }, "refund issued");
    return res.status(201).json(refund);
  } catch (err) {
    return next(err);
  }
});

router.post("/tokens", async (req, res, next) => {
  try {
    const card = cardSchema.parse(req.body?.card);
    const vaulted = cardVault.encryptPan(card.number, req.merchant.id);
    const token = cardVault.issueCardToken();

    await paymentRepo.storeCardOnFile({
      token,
      merchantId: req.merchant.id,
      card: vaulted,
      expMonth: card.exp_month,
      expYear: card.exp_year,
    });

    return res.status(201).json({
      card_token: token,
      last4: vaulted.last4,
      bin: vaulted.bin,
      fingerprint: vaulted.fingerprint,
    });
  } catch (err) {
    return next(err);
  }
});

function present(intent) {
  return {
    reference: intent.reference,
    status: intent.status,
    amount_minor: intent.amountMinor,
    currency: intent.currency,
    card: intent.card ? { last4: intent.card.last4, bin: intent.card.bin } : null,
    created_at: intent.createdAt,
  };
}

module.exports = router;
