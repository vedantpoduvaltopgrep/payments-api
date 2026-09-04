"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

process.env.DATABASE_URL = "postgres://localhost/unused";
process.env.CARD_VAULT_DATA_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const idempotency = require("../src/services/idempotency");

test("the same key with the same body is the same fingerprint", () => {
  const a = idempotency.requestFingerprint("k1", "mer_1", "POST", "/v1/payments/intents", { amount_minor: 100 });
  const b = idempotency.requestFingerprint("k1", "mer_1", "POST", "/v1/payments/intents", { amount_minor: 100 });
  assert.equal(a, b);
});

test("the same key with a different body is a different fingerprint", () => {
  const a = idempotency.requestFingerprint("k1", "mer_1", "POST", "/v1/payments/intents", { amount_minor: 100 });
  const b = idempotency.requestFingerprint("k1", "mer_1", "POST", "/v1/payments/intents", { amount_minor: 999 });
  assert.notEqual(a, b);
});

test("one merchant's key cannot collide with another's", () => {
  const a = idempotency.requestFingerprint("k1", "mer_1", "POST", "/p", {});
  const b = idempotency.requestFingerprint("k1", "mer_2", "POST", "/p", {});
  assert.notEqual(a, b);
});

test("safeEqual rejects different lengths without throwing", () => {
  assert.equal(idempotency.safeEqual("abc", "abcd"), false);
  assert.equal(idempotency.safeEqual("abc", "abc"), true);
});
