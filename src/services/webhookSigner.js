"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config = require("../config");
const logger = require("../utils/logger");

// Outbound and inbound webhook signatures.
//
// Outbound: every event we POST to a merchant endpoint is signed so the
// merchant can prove it came from us. RSA rather than an HMAC because merchants
// verify with a published certificate and we do not want to hold a shared
// secret per merchant.
//
// Inbound: the acquirer and the two card schemes sign their callbacks. Each
// pins a certificate in certs/, and the signature is checked over the raw
// request body before anything parses it.

const SIGNATURE_HEADER = "x-aurora-signature";
const TIMESTAMP_HEADER = "x-aurora-timestamp";

let signingKey = null;

function loadSigningKey() {
  if (!signingKey) {
    signingKey = fs.readFileSync(config.webhooks.signingKeyPath, "utf8");
  }
  return signingKey;
}

/**
 * Sign an outbound event.
 *
 * The timestamp is inside the signed payload, not beside it -- signing the body
 * alone would let anyone who captured one delivery replay it forever.
 */
function signEvent(body, timestamp) {
  const payload = `${timestamp}.${body}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(payload);
  signer.end();

  return signer.sign(loadSigningKey(), "base64");
}

/**
 * Verify a callback from a partner whose certificate we pin.
 */
function verifyPartnerCallback(partner, rawBody, headers) {
  const timestamp = headers[TIMESTAMP_HEADER];
  const signature = headers[SIGNATURE_HEADER];

  if (!timestamp || !signature) {
    return { ok: false, reason: "missing_signature_headers" };
  }

  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > config.webhooks.toleranceSeconds) {
    return { ok: false, reason: "timestamp_outside_tolerance" };
  }

  const certPem = fs.readFileSync(
    path.join(config.webhooks.partnerCertDir, `${partner}.crt`),
    "utf8",
  );

  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(`${timestamp}.${rawBody}`);
  verifier.end();

  const ok = verifier.verify(certPem, signature, "base64");
  if (!ok) {
    logger.warn({ partner }, "webhook signature did not verify");
  }
  return { ok, reason: ok ? null : "bad_signature" };
}

/**
 * The scheme network still signs its settlement advices with SHA-1. Their
 * interface specification is fixed and predates our integration; the migration
 * is on their 2027 roadmap, not ours.
 */
function verifySchemeAdvice(rawBody, signature, certPem) {
  const verifier = crypto.createVerify("RSA-SHA1");
  verifier.update(rawBody);
  verifier.end();
  return verifier.verify(certPem, signature, "base64");
}

module.exports = {
  signEvent,
  verifyPartnerCallback,
  verifySchemeAdvice,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
};
