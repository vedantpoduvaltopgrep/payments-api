"use strict";

const router = require("express").Router();

const webhookSigner = require("../services/webhookSigner");
const legacyPartner = require("../services/legacyPartner");
const eventRepo = require("../db/eventRepo");
const logger = require("../utils/logger");

// Inbound callbacks. The body arrives raw (see app.js) because every one of
// these is signature-checked over the exact bytes the sender signed.

router.post("/acquirer", async (req, res, next) => {
  try {
    const raw = req.body.toString("utf8");
    const result = webhookSigner.verifyPartnerCallback("acquirer", raw, req.headers);
    if (!result.ok) {
      logger.warn({ reason: result.reason, requestId: req.id }, "acquirer callback rejected");
      return res.status(401).json({ error: result.reason });
    }

    const event = JSON.parse(raw);
    await eventRepo.recordInbound("acquirer", event);
    return res.status(202).json({ received: true });
  } catch (err) {
    return next(err);
  }
});

router.post("/scheme/advice", async (req, res, next) => {
  try {
    const raw = req.body.toString("utf8");
    const certPem = await eventRepo.schemeCertificate(req.get("x-scheme-key-id"));

    // The scheme signs advices with SHA-1. Their interface, their timetable.
    const ok = webhookSigner.verifySchemeAdvice(raw, req.get("x-scheme-signature"), certPem);
    if (!ok) {
      return res.status(401).json({ error: "bad_signature" });
    }

    await eventRepo.recordInbound("scheme", JSON.parse(raw));
    return res.status(202).json({ received: true });
  } catch (err) {
    return next(err);
  }
});

/**
 * Northgate posts form-encoded, 3DES-wrapped envelopes with an MD5 request MAC.
 * Retiring this endpoint is tracked as PLAT-4471.
 */
router.post("/northgate", async (req, res, next) => {
  try {
    const raw = req.body.toString("utf8");
    const params = Object.fromEntries(new URLSearchParams(raw));
    const merchant = await eventRepo.northgateMerchant(params.merchant_ref);

    const expected = legacyPartner.requestMac(
      [params.merchant_ref, params.txn_ref, params.amount, params.status],
      merchant.sharedSecret,
    );
    if (expected !== params.mac) {
      return res.status(401).json({ error: "bad_mac" });
    }

    const envelope = legacyPartner.decryptEnvelope(params.envelope, merchant.envelopeKey);
    await eventRepo.recordInbound("northgate", envelope);

    return res.status(200).send("OK");
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
