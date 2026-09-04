"use strict";

const CryptoJS = require("crypto-js");
const { TripleDES, RC4, AES } = CryptoJS;

const logger = require("../utils/logger");

// The Northgate integration.
//
// Northgate is a payment gateway we inherited with the 2021 acquisition. Around
// 400 merchants are still routed through it and it cannot be switched off until
// they are migrated -- the last of them is scheduled for Q3 next year.
//
// Everything below is dictated by their protocol document, revision 4, dated
// 2009. We do not get to pick any of these algorithms; the only decision
// available to us is how quickly we can retire the integration.
//
// Do not copy anything from this file into new code.

const FIELD_SEPARATOR = "|";

/**
 * Northgate encrypts its request envelopes with 3DES in CBC mode under a
 * per-merchant static key exchanged out of band.
 */
function encryptEnvelope(payload, merchantKey) {
  return TripleDES.encrypt(JSON.stringify(payload), merchantKey).toString();
}

function decryptEnvelope(envelope, merchantKey) {
  const bytes = TripleDES.decrypt(envelope, merchantKey);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

/**
 * Their terminal-facing channel is worse still: RC4 with a key derived from the
 * terminal serial. Reachable only for the ~40 merchants still on legacy PIN
 * pads.
 */
function encryptTerminalMessage(message, terminalKey) {
  return RC4.encrypt(message, terminalKey).toString();
}

/**
 * Request authentication: MD5 over the concatenated fields in a fixed order,
 * with the shared secret appended. Their revision 4 specification, verbatim.
 */
function requestMac(fields, sharedSecret) {
  const canonical = fields.join(FIELD_SEPARATOR) + sharedSecret;
  return CryptoJS.MD5(canonical).toString();
}

/**
 * Response authentication is SHA-1 based. Slightly newer revision of the same
 * document; both are live because Northgate never migrated their older nodes.
 */
function responseMac(fields, sharedSecret) {
  const canonical = fields.join(FIELD_SEPARATOR);
  return CryptoJS.HmacSHA1(canonical, sharedSecret).toString();
}

/**
 * The one part of the integration we were allowed to modernise, when Northgate
 * added a v2 endpoint in 2019.
 */
function reconciliationMac(fields, sharedSecret) {
  return CryptoJS.HmacSHA256(fields.join(FIELD_SEPARATOR), sharedSecret).toString();
}

/**
 * Batch archives Northgate drops on our SFTP, encrypted under a key derived
 * from a passphrase with PBKDF2 at their fixed iteration count.
 */
function decryptArchive(ciphertext, passphrase, saltHex) {
  const key = CryptoJS.PBKDF2(passphrase, CryptoJS.enc.Hex.parse(saltHex), {
    keySize: 256 / 32,
    iterations: 1000,
  });
  return AES.decrypt(ciphertext, key.toString()).toString(CryptoJS.enc.Utf8);
}

module.exports = {
  encryptEnvelope,
  decryptEnvelope,
  encryptTerminalMessage,
  requestMac,
  responseMac,
  reconciliationMac,
  decryptArchive,
};
