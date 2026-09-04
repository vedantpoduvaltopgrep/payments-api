"use strict";

const { newRequestId } = require("../services/idempotency");

// Every request gets an id, and it is echoed back. Support cannot chase a
// payment through four services without one.
module.exports = function requestId(req, res, next) {
  req.id = req.get("x-request-id") || newRequestId();
  res.set("x-request-id", req.id);
  next();
};
