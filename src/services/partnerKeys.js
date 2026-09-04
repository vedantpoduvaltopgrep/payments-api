"use strict";

const crypto = require("crypto");
const forge = require("node-forge");

const logger = require("../utils/logger");

// Per-partner key material for the mutual-TLS API and for signed file exchange.
//
// Keys are generated here and the private half is written straight to the KMS;
// only the public half and a CSR ever come back out of this module.

/**
 * Generate the RSA keypair a partner uses to sign file drops.
 *
 * 3072 bits rather than 2048: these keys have a five-year rotation and the
 * files they sign are retained for seven, so they outlive the usual guidance.
 */
function generateFileSigningKeypair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

/**
 * Mutual-TLS client keys. EC, because the handshake cost matters here -- a busy
 * partner opens thousands of connections an hour.
 */
function generateMtlsKeypair() {
  return crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

/**
 * The onboarding portal generates a keypair in the background while the partner
 * fills in the rest of the form, so the callback form is used rather than the
 * sync one.
 */
function generateOnboardingKeypair(callback) {
  crypto.generateKeyPair(
    "rsa",
    {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    },
    callback,
  );
}

/**
 * Build the CSR the partner takes to their own CA.
 *
 * node-forge rather than the crypto module: Node has no CSR builder, and
 * shelling out to openssl from inside a request handler is not something we
 * are willing to do.
 */
function buildCsr(partner, publicKeyPem, privateKeyPem) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  csr.setSubject([
    { name: "commonName", value: `${partner.slug}.partners.aurorapay.example` },
    { name: "organizationName", value: partner.legalName },
    { name: "countryName", value: partner.country },
  ]);
  csr.sign(forge.pki.privateKeyFromPem(privateKeyPem), forge.md.sha256.create());

  return forge.pki.certificationRequestToPem(csr);
}

/**
 * The fingerprint we pin a partner certificate by, and the value the operations
 * runbook asks them to read back over the phone during a rotation.
 */
function certificateFingerprint(certPem) {
  const der = crypto.createPublicKey(certPem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex").match(/.{2}/g).join(":");
}

module.exports = {
  generateFileSigningKeypair,
  generateMtlsKeypair,
  generateOnboardingKeypair,
  buildCsr,
  certificateFingerprint,
};
