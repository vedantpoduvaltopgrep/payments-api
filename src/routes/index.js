"use strict";

const router = require("express").Router();

router.use("/auth", require("./auth"));
router.use("/payments", require("./payments"));
router.use("/merchants", require("./merchants"));
router.use("/webhooks", require("./webhooks"));
router.use("/reports", require("./reports"));

module.exports = router;
