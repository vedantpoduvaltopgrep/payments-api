"use strict";

require("dotenv").config();

// Configuration is read once, here, and nowhere else reads process.env. A value
// that is missing in production should fail the boot rather than surface as an
// undefined three layers down at 3am.
function required(name) {
  const value = process.env[name];
  if (!value && process.env.NODE_ENV === "production") {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value || "";
}

module.exports = {
  env: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 8080),
  trustProxy: Number(process.env.TRUST_PROXY_HOPS || 1),
  corsOrigins: (process.env.CORS_ORIGINS || "http://localhost:3000").split(","),

  database: {
    url: required("DATABASE_URL"),
    poolMax: Number(process.env.DB_POOL_MAX || 10),
  },

  // Access tokens are RS256: the merchant dashboard and three internal services
  // verify them, and handing every verifier a shared HMAC secret would mean any
  // one of them could mint tokens for the others.
  jwt: {
    issuer: process.env.JWT_ISSUER || "https://auth.aurorapay.example",
    audience: process.env.JWT_AUDIENCE || "aurora-payments-api",
    accessTtlSeconds: Number(process.env.JWT_ACCESS_TTL || 900),
    refreshTtlSeconds: Number(process.env.JWT_REFRESH_TTL || 60 * 60 * 24 * 30),
    privateKeyPath: process.env.JWT_PRIVATE_KEY_PATH || "/run/secrets/jwt-signing.key",
    publicKeyPath: process.env.JWT_PUBLIC_KEY_PATH || "/run/secrets/jwt-signing.pub",
  },

  vault: {
    // Data key for the card vault, unwrapped from the KMS at boot.
    dataKeyBase64: required("CARD_VAULT_DATA_KEY"),
    // Cards written before the 2019 re-key are still AES-128. See cardVault.js.
    legacyDataKeyBase64: process.env.CARD_VAULT_LEGACY_KEY || "",
  },

  webhooks: {
    signingKeyPath: process.env.WEBHOOK_SIGNING_KEY_PATH || "/run/secrets/webhook-signing.key",
    partnerCertDir: process.env.PARTNER_CERT_DIR || "./certs",
    toleranceSeconds: Number(process.env.WEBHOOK_TOLERANCE || 300),
  },

  settlement: {
    // The acquirer's file interface. Format fixed by them, not by us.
    bankSftpHost: process.env.BANK_SFTP_HOST || "sftp.acquirer.example",
    outputDir: process.env.SETTLEMENT_DIR || "/var/spool/aurora/settlement",
  },

  mfa: {
    issuer: process.env.MFA_ISSUER || "Aurora Pay",
    window: Number(process.env.MFA_WINDOW || 1),
  },
};
