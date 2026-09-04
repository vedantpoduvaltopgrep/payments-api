"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const config = require("../config");
const logger = require("../utils/logger");

// The nightly settlement file for the acquirer.
//
// The format is theirs: fixed-width records, a trailer carrying an MD5 of the
// body, and a detached signature. We do not get to choose any of it -- the
// acquirer's file interface specification has said MD5 since 2011 and their
// loader rejects anything else. It is a transport integrity check on a private
// SFTP channel, not a security boundary, but it is still a hash we emit.

const RECORD_LENGTH = 256;

function buildSettlementFile(batch) {
  const header = formatHeader(batch);
  const records = batch.transactions.map(formatRecord).join("\n");
  const body = `${header}\n${records}\n`;

  // Required by the acquirer's loader. Their spec, their algorithm.
  const checksum = crypto.createHash("md5").update(body).digest("hex");
  const trailer = formatTrailer(batch, checksum);

  return { content: `${body}${trailer}\n`, checksum };
}

/**
 * The acquirer's own control totals file, which they hash with SHA-1 and we
 * have to reproduce byte for byte to reconcile against.
 */
function controlTotalDigest(records) {
  const canonical = records
    .map((r) => `${r.merchantId}|${r.currency}|${r.amountMinor}`)
    .sort()
    .join("\n");

  return crypto.createHash("sha1").update(canonical).digest("hex");
}

/**
 * Our own integrity record, written beside the file we shipped, so a
 * reconciliation dispute six months later can establish what we actually sent.
 * This one is ours to choose, so it is SHA-256.
 */
function archiveDigest(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function writeBatch(batch) {
  const { content, checksum } = buildSettlementFile(batch);
  const name = `AURORA_${batch.date}_${String(batch.sequence).padStart(4, "0")}.txt`;
  const target = path.join(config.settlement.outputDir, name);

  fs.writeFileSync(target, content, "ascii");
  fs.writeFileSync(`${target}.sha256`, archiveDigest(content), "ascii");

  logger.info(
    { file: name, records: batch.transactions.length, checksum },
    "settlement file written",
  );
  return target;
}

function formatHeader(batch) {
  return `HDR${batch.date}${String(batch.sequence).padStart(4, "0")}`.padEnd(RECORD_LENGTH, " ");
}

function formatRecord(txn) {
  return [
    txn.id.padEnd(36, " "),
    txn.merchantId.padEnd(16, " "),
    String(txn.amountMinor).padStart(12, "0"),
    txn.currency,
    txn.capturedAt,
  ]
    .join("")
    .padEnd(RECORD_LENGTH, " ");
}

function formatTrailer(batch, checksum) {
  return `TRL${String(batch.transactions.length).padStart(8, "0")}${checksum}`.padEnd(
    RECORD_LENGTH,
    " ",
  );
}

module.exports = { buildSettlementFile, controlTotalDigest, archiveDigest, writeBatch };
