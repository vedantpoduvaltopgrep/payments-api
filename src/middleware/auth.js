"use strict";

const tokenService = require("../services/tokenService");
const apiKeyService = require("../services/apiKeyService");
const { safeEqual } = require("../services/idempotency");
const logger = require("../utils/logger");

// Two ways in, and they are deliberately not interchangeable.
//
// A bearer JWT is a dashboard user acting on behalf of a merchant. An API key
// is the merchant's server. They carry different scopes and the routes say
// which they accept.

function requireBearer(req, res, next) {
  const header = req.get("authorization") || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized", message: "Bearer token required." });
  }

  try {
    const claims = tokenService.verifyAccessToken(header.slice(7));
    req.user = {
      id: claims.sub,
      merchantId: claims.merchant_id,
      roles: claims.roles || [],
      scopes: (claims.scope || "").split(" ").filter(Boolean),
    };
    return next();
  } catch (err) {
    logger.warn({ err: err.message, requestId: req.id }, "token rejected");
    return res.status(401).json({ error: "unauthorized", message: "Invalid or expired token." });
  }
}

function requireApiKey(lookup) {
  return async function apiKeyMiddleware(req, res, next) {
    const presented = req.get("x-api-key");
    if (!presented) {
      return res.status(401).json({ error: "unauthorized", message: "API key required." });
    }

    const digest = apiKeyService.digestApiKey(presented);
    const record = await lookup(digest);

    // The lookup is by digest, so this compare is belt-and-braces -- but it is
    // constant time, and the cost of getting that wrong here is a key oracle.
    if (!record || !safeEqual(record.digest, digest)) {
      return res.status(401).json({ error: "unauthorized", message: "Unknown API key." });
    }
    if (record.revokedAt) {
      return res.status(401).json({ error: "unauthorized", message: "API key revoked." });
    }

    req.merchant = { id: record.merchantId, mode: record.mode };
    return next();
  };
}

function requireScope(...needed) {
  return function scopeMiddleware(req, res, next) {
    const held = new Set(req.user?.scopes || []);
    const missing = needed.filter((s) => !held.has(s));
    if (missing.length > 0) {
      return res.status(403).json({
        error: "forbidden",
        message: `Missing scope: ${missing.join(", ")}`,
      });
    }
    return next();
  };
}

module.exports = { requireBearer, requireApiKey, requireScope };
