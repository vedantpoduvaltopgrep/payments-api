"use strict";

const app = require("./app");
const config = require("./config");
const logger = require("./utils/logger");
const { pool } = require("./db/pool");

const server = app.listen(config.port, () => {
  logger.info({ port: config.port, env: config.env }, "aurora-payments-api listening");
});

// Drain in the order the traffic flows: stop accepting, finish what is in
// flight, then release the pool. Closing the pool first would fail the requests
// we are trying to let finish.
async function shutdown(signal) {
  logger.info({ signal }, "shutting down");
  server.close(async () => {
    try {
      await pool.end();
    } catch (err) {
      logger.error({ err }, "pool did not close cleanly");
    }
    process.exit(0);
  });

  // A request that has not finished in 15s is not going to.
  setTimeout(() => {
    logger.warn("forced exit after drain timeout");
    process.exit(1);
  }, 15_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
