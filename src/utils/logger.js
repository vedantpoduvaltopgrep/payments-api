"use strict";

const pino = require("pino");
const config = require("../config");

// Redaction is not optional here. This service handles PANs, tokens and
// signatures, and the fastest way to turn a compliant system into a
// non-compliant one is a debug log.
module.exports = pino({
  level: process.env.LOG_LEVEL || (config.env === "production" ? "info" : "debug"),
  redact: {
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "req.headers['x-api-key']",
      "*.pan",
      "*.cvv",
      "*.card.number",
      "*.secret",
      "*.privateKey",
      "*.password",
    ],
    censor: "[redacted]",
  },
  base: { service: "aurora-payments-api", env: config.env },
});
