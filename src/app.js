"use strict";

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const compression = require("compression");

const config = require("./config");
const requestId = require("./middleware/requestId");
const errorHandler = require("./middleware/errorHandler");
const { publicLimiter } = require("./middleware/rateLimit");
const routes = require("./routes");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", config.trustProxy);

app.use(requestId);
app.use(helmet());
app.use(cors({ origin: config.corsOrigins, credentials: true }));
app.use(compression());

// Raw body on the webhook route only. Signature verification has to run over
// the exact bytes the partner signed, and a JSON round-trip does not preserve
// them -- key order and whitespace both change.
app.use("/v1/webhooks", express.raw({ type: "*/*", limit: "1mb" }));
app.use(express.json({ limit: "256kb" }));

app.use(publicLimiter);
app.use("/v1", routes);

app.get("/healthz", (req, res) => res.json({ status: "ok" }));
app.get("/readyz", (req, res) => res.json({ status: "ready" }));

app.use((req, res) => {
  res.status(404).json({ error: "not_found", path: req.path });
});
app.use(errorHandler);

module.exports = app;
