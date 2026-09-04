"use strict";

const router = require("express").Router();
const { z } = require("zod");

const tokenService = require("../services/tokenService");
const passwordService = require("../services/passwordService");
const mfaService = require("../services/mfaService");
const { loginLimiter } = require("../middleware/rateLimit");
const { requireBearer } = require("../middleware/auth");
const userRepo = require("../db/userRepo");
const logger = require("../utils/logger");

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
  totp: z.string().regex(/^[0-9]{6}$/).optional(),
});

router.post("/login", loginLimiter, async (req, res, next) => {
  try {
    const body = loginSchema.parse(req.body);
    const user = await userRepo.findByEmail(body.email);

    // verifyPassword runs a comparison even when the user is absent, so the
    // response time does not distinguish the two cases.
    const ok = await passwordService.verifyPassword(body.password, user?.passwordHash);
    if (!ok || !user) {
      return res.status(401).json({ error: "invalid_credentials" });
    }

    if (user.mfaEnrolled) {
      if (!body.totp) {
        return res.status(401).json({ error: "mfa_required" });
      }
      if (!mfaService.verifyCode(user.mfaSecret, body.totp)) {
        return res.status(401).json({ error: "invalid_mfa_code" });
      }
    }

    const merchant = await userRepo.merchantFor(user);
    const session = await userRepo.createSession(user, req.ip, req.get("user-agent"));

    return res.json({
      access_token: tokenService.issueAccessToken({ ...user, sessionId: session.id }, merchant),
      refresh_token: tokenService.issueRefreshToken(user),
      token_type: "Bearer",
      expires_in: 900,
    });
  } catch (err) {
    return next(err);
  }
});

router.post("/refresh", async (req, res, next) => {
  try {
    const claims = tokenService.verifyRefreshToken(String(req.body?.refresh_token || ""));
    const user = await userRepo.findById(claims.sub);
    if (!user || user.disabledAt) {
      return res.status(401).json({ error: "invalid_grant" });
    }

    const merchant = await userRepo.merchantFor(user);
    const session = await userRepo.createSession(user, req.ip, req.get("user-agent"));

    return res.json({
      access_token: tokenService.issueAccessToken({ ...user, sessionId: session.id }, merchant),
      token_type: "Bearer",
      expires_in: 900,
    });
  } catch (err) {
    logger.warn({ err: err.message, requestId: req.id }, "refresh rejected");
    return res.status(401).json({ error: "invalid_grant" });
  }
});

router.post("/mfa/enrol", requireBearer, async (req, res, next) => {
  try {
    const user = await userRepo.findById(req.user.id);
    const enrolment = mfaService.enrolUser(user);
    await userRepo.stageMfaSecret(user.id, enrolment.secret, enrolment.recoveryCodes);

    return res.status(201).json({
      otpauth_url: enrolment.otpauthUrl,
      recovery_codes: enrolment.recoveryCodes.map((c) => c.code),
    });
  } catch (err) {
    return next(err);
  }
});

router.get("/.well-known/jwks.json", (req, res) => {
  res.set("cache-control", "public, max-age=300");
  res.json(tokenService.publicJwks());
});

module.exports = router;
