"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

process.env.CARD_VAULT_DATA_KEY = crypto.randomBytes(32).toString("base64");
process.env.CARD_VAULT_LEGACY_KEY = crypto.randomBytes(16).toString("base64");
process.env.DATABASE_URL = "postgres://localhost/unused";

const cardVault = require("../src/services/cardVault");

test("a PAN round-trips through the current key generation", () => {
  const pan = "4242424242424242";
  const record = cardVault.encryptPan(pan, "mer_123");

  assert.equal(record.keyVersion, cardVault.KEY_VERSION_CURRENT);
  assert.equal(record.last4, "4242");
  assert.equal(record.bin, "424242");
  assert.notEqual(record.ciphertext, pan);
  assert.equal(cardVault.decryptPan(record, "mer_123"), pan);
});

test("a ciphertext cannot be replayed into another merchant", () => {
  const record = cardVault.encryptPan("4242424242424242", "mer_123");
  assert.throws(() => cardVault.decryptPan(record, "mer_999"));
});

test("the fingerprint is stable and does not reveal the PAN", () => {
  const a = cardVault.panFingerprint("4242424242424242");
  const b = cardVault.panFingerprint("4242424242424242");
  const c = cardVault.panFingerprint("4000000000000002");

  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.doesNotMatch(a, /4242/);
});
