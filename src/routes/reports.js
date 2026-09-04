"use strict";

const router = require("express").Router();

const settlementFile = require("../services/settlementFile");
const legacyPartner = require("../services/legacyPartner");
const { requireBearer, requireScope } = require("../middleware/auth");
const reportRepo = require("../db/reportRepo");

router.use(requireBearer);

router.get("/settlement/:date", requireScope("reports:read"), async (req, res, next) => {
  try {
    const batch = await reportRepo.settlementBatch(req.user.merchantId, req.params.date);
    if (!batch) return res.status(404).json({ error: "not_found" });

    const { content, checksum } = settlementFile.buildSettlementFile(batch);

    res.set("content-type", "text/plain; charset=us-ascii");
    res.set("x-aurora-checksum", checksum);
    res.set("x-aurora-archive-digest", settlementFile.archiveDigest(content));
    return res.send(content);
  } catch (err) {
    return next(err);
  }
});

router.get("/reconciliation/:date", requireScope("reports:read"), async (req, res, next) => {
  try {
    const rows = await reportRepo.reconciliationRows(req.user.merchantId, req.params.date);
    return res.json({
      date: req.params.date,
      rows,
      // The acquirer reconciles against their own SHA-1 control total, so we
      // publish ours alongside for a support engineer to compare by eye.
      control_total: settlementFile.controlTotalDigest(rows),
    });
  } catch (err) {
    return next(err);
  }
});

router.get("/northgate/:date", requireScope("reports:read"), async (req, res, next) => {
  try {
    const archive = await reportRepo.northgateArchive(req.user.merchantId, req.params.date);
    if (!archive) return res.status(404).json({ error: "not_found" });

    const plaintext = legacyPartner.decryptArchive(
      archive.ciphertext,
      archive.passphrase,
      archive.saltHex,
    );

    return res.json({ date: req.params.date, records: JSON.parse(plaintext) });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
