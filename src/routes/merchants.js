"use strict";

const router = require("express").Router();
const { z } = require("zod");

const apiKeyService = require("../services/apiKeyService");
const partnerKeys = require("../services/partnerKeys");
const { requireBearer, requireScope } = require("../middleware/auth");
const merchantRepo = require("../db/merchantRepo");
const logger = require("../utils/logger");

router.use(requireBearer);

router.get("/me", async (req, res, next) => {
  try {
    const merchant = await merchantRepo.findById(req.user.merchantId);
    return res.json(merchant);
  } catch (err) {
    return next(err);
  }
});

router.post("/me/api-keys", requireScope("api_keys:write"), async (req, res, next) => {
  try {
    const mode = req.body?.mode === "test" ? "test" : "live";
    const issued = apiKeyService.issueApiKey(req.user.merchantId, mode);
    await merchantRepo.storeApiKey(issued);

    logger.info({ merchantId: req.user.merchantId, prefix: issued.prefix }, "api key issued");

    // The only time the key is ever returned. There is no endpoint that can
    // read it back, because we do not store it.
    return res.status(201).json({ key: issued.key, prefix: issued.prefix, mode });
  } catch (err) {
    return next(err);
  }
});

router.delete("/me/api-keys/:prefix", requireScope("api_keys:write"), async (req, res, next) => {
  try {
    await merchantRepo.revokeApiKey(req.user.merchantId, req.params.prefix);
    return res.status(204).end();
  } catch (err) {
    return next(err);
  }
});

const endpointSchema = z.object({
  url: z.string().url().startsWith("https://"),
  events: z.array(z.string()).min(1),
});

router.post("/me/webhook-endpoints", requireScope("webhooks:write"), async (req, res, next) => {
  try {
    const body = endpointSchema.parse(req.body);
    const secret = apiKeyService.issueEndpointSecret();

    const endpoint = await merchantRepo.createWebhookEndpoint({
      merchantId: req.user.merchantId,
      url: body.url,
      events: body.events,
      secret,
    });

    return res.status(201).json({ id: endpoint.id, url: endpoint.url, secret });
  } catch (err) {
    return next(err);
  }
});

router.post("/me/partner-keys", requireScope("partner:admin"), async (req, res, next) => {
  try {
    const merchant = await merchantRepo.findById(req.user.merchantId);
    const keypair = partnerKeys.generateFileSigningKeypair();
    const csr = partnerKeys.buildCsr(merchant, keypair.publicKey, keypair.privateKey);

    await merchantRepo.storePartnerKey(merchant.id, keypair.publicKey);

    return res.status(201).json({ csr, public_key: keypair.publicKey });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
