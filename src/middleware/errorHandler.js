"use strict";

const logger = require("../utils/logger");

// One error shape for the whole API. A merchant integrating against us should
// never have to parse two different failure formats.
// eslint-disable-next-line no-unused-vars
module.exports = function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;

  if (status >= 500) {
    logger.error({ err, requestId: req.id, path: req.path }, "unhandled error");
  } else {
    logger.warn({ err: err.message, requestId: req.id, path: req.path }, "request rejected");
  }

  res.status(status).json({
    error: err.code || (status >= 500 ? "internal_error" : "bad_request"),
    // Never the raw message on a 5xx: it is the one place a stack trace or a
    // connection string reaches a client.
    message: status >= 500 ? "An unexpected error occurred." : err.message,
    request_id: req.id,
  });
};
