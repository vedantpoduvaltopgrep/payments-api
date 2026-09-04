"use strict";

const fs = require("fs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const config = require("../config");
const logger = require("../utils/logger");

// Access and refresh tokens for the merchant dashboard and the partner API.
//
// RS256 rather than HS256 on purpose: the dashboard BFF, the settlement worker
// and the reporting service all verify these, and a shared HMAC secret would
// let any verifier mint tokens for the others. The signing key stays here.

let privateKey = null;
let publicKey = null;

function loadKeys() {
  if (privateKey && publicKey) return;
  privateKey = fs.readFileSync(config.jwt.privateKeyPath, "utf8");
  publicKey = fs.readFileSync(config.jwt.publicKeyPath, "utf8");
}

/**
 * Mint an access token for a merchant user.
 */
function issueAccessToken(user, merchant) {
  loadKeys();

  const claims = {
    sub: user.id,
    merchant_id: merchant.id,
    roles: user.roles,
    scope: user.scopes.join(" "),
    // Correlates a token with the session row without carrying the session id
    // itself, which is a bearer value in its own right.
    sid_hash: crypto.createHash("sha256").update(user.sessionId).digest("hex"),
  };

  return jwt.sign(claims, privateKey, {
    algorithm: "RS256",
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    expiresIn: config.jwt.accessTtlSeconds,
    keyid: "aurora-jwt-2024-06",
  });
}

/**
 * Refresh tokens are long-lived, so they are signed with the same key but
 * carry a narrower audience -- a refresh token must not be accepted anywhere
 * an access token is.
 */
function issueRefreshToken(user) {
  loadKeys();

  return jwt.sign(
    { sub: user.id, typ: "refresh", jti: crypto.randomUUID() },
    privateKey,
    {
      algorithm: "RS256",
      issuer: config.jwt.issuer,
      audience: `${config.jwt.audience}/refresh`,
      expiresIn: config.jwt.refreshTtlSeconds,
    },
  );
}

/**
 * Verify an access token. Throws on anything that is not a valid, unexpired
 * token for this audience.
 */
function verifyAccessToken(token) {
  loadKeys();

  return jwt.verify(token, publicKey, {
    algorithms: ["RS256"],
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    clockTolerance: 5,
  });
}

function verifyRefreshToken(token) {
  loadKeys();

  const claims = jwt.verify(token, publicKey, {
    algorithms: ["RS256"],
    issuer: config.jwt.issuer,
    audience: `${config.jwt.audience}/refresh`,
  });
  if (claims.typ !== "refresh") {
    throw new Error("not a refresh token");
  }
  return claims;
}

/**
 * The JWKS the dashboard BFF fetches so it can verify tokens without calling
 * us on every request.
 */
function publicJwks() {
  loadKeys();
  const key = crypto.createPublicKey(publicKey);
  const jwk = key.export({ format: "jwk" });
  return { keys: [{ ...jwk, use: "sig", alg: "RS256", kid: "aurora-jwt-2024-06" }] };
}

module.exports = {
  issueAccessToken,
  issueRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  publicJwks,
};
