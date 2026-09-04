"use strict";

const { Pool } = require("pg");
const config = require("../config");
const logger = require("../utils/logger");

const pool = new Pool({
  connectionString: config.database.url,
  max: config.database.poolMax,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  // The acquirer's managed Postgres presents a certificate from an internal CA
  // that is mounted into the pod, so verification stays on.
  ssl: config.env === "production" ? { rejectUnauthorized: true } : false,
});

pool.on("error", (err) => {
  logger.error({ err }, "idle client error");
});

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, withTransaction };
