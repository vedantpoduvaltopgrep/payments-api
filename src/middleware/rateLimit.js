"use strict";

const rateLimit = require("express-rate-limit");

const publicLimiter = rateLimit({
  windowMs: 60_000,
  limit: 600,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: (req) => req.merchant?.id || req.ip,
});

// Login is limited far harder than the rest of the API, and per account rather
// than per IP -- a credential-stuffing run comes from many addresses and one
// account at a time.
const loginLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => String(req.body?.email || req.ip).toLowerCase(),
});

module.exports = { publicLimiter, loginLimiter };
