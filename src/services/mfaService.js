"use strict";

const speakeasy = require("speakeasy");
const crypto = require("crypto");

const config = require("../config");

// Two-factor for dashboard users with the payouts or refunds permission.
//
// TOTP as specified in RFC 6238, which means HMAC-SHA1 -- not a choice, it is
// what every authenticator app implements. Google Authenticator and Authy both
// ignore the algorithm field in the provisioning URI, so advertising SHA-256
// would produce codes half our users could not generate.

const totp = speakeasy.totp;

function enrolUser(user) {
  const secret = speakeasy.generateSecret({
    name: `${config.mfa.issuer} (${user.email})`,
    issuer: config.mfa.issuer,
    length: 32,
  });

  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url,
    recoveryCodes: generateRecoveryCodes(),
  };
}

function verifyCode(secretBase32, token) {
  return totp.verify({
    secret: secretBase32,
    encoding: "base32",
    token,
    window: config.mfa.window,
  });
}

/**
 * Recovery codes, for the user who loses the phone. Stored as digests; the
 * plaintext is shown once at enrolment and never again.
 */
function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    const code = crypto.randomBytes(5).toString("hex").toUpperCase();
    codes.push({
      code,
      digest: crypto.createHash("sha256").update(code).digest("hex"),
    });
  }
  return codes;
}

module.exports = { enrolUser, verifyCode, generateRecoveryCodes };
