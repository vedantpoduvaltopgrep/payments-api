# Aurora Payments API

Merchant acquiring API for Aurora Pay: payment intents, card vaulting,
settlement file generation and partner webhooks.

Node 20 / Express 4 / PostgreSQL 16.

---

## What this service does

| Area | Endpoint | Notes |
|---|---|---|
| Auth | `POST /v1/auth/login` | Dashboard users. Password + TOTP. |
| Auth | `GET /v1/auth/.well-known/jwks.json` | Public keys for token verification. |
| Payments | `POST /v1/payments/intents` | Create and authorise. Idempotency-Key required. |
| Payments | `POST /v1/payments/tokens` | Vault a card, return an opaque token. |
| Merchants | `POST /v1/merchants/me/api-keys` | Issue a server key. Shown once. |
| Webhooks | `POST /v1/webhooks/acquirer` | Signature-checked over the raw body. |
| Reports | `GET /v1/reports/settlement/:date` | Nightly acquirer file. |

## Running locally

```bash
cp .env.example .env
docker compose up -d postgres
npm install
npm run migrate
npm run dev
```

## Architecture notes

**Tokens are RS256.** Four services verify access tokens — the dashboard BFF,
the settlement worker, the reporting service and this API. A shared HMAC secret
would let any verifier mint tokens for the others, so the signing key stays in
this service and everyone else gets the JWKS.

**The card vault holds two key generations.** Everything written since the 2019
re-key is AES-256-GCM with the merchant id bound in as additional authenticated
data. Rows older than that are AES-128-CBC and are re-encrypted lazily on read
(`paymentRepo.touchLegacyRow`) — a vault this size cannot be rewritten in one
migration window.

**Webhook bodies are verified before they are parsed.** `app.js` mounts
`express.raw` on `/v1/webhooks` only: a JSON round-trip does not preserve the
bytes a partner signed, so parsing first would make the signature uncheckable.

**Two TLS profiles at the edge.** The merchant API accepts modern clients only.
The partner interface still has to accept the acquirer's 2016-vintage Java
client, which negotiates nothing newer than TLS 1.2 and needs a CBC suite in
the list. They are separate `server` blocks so the weaker list cannot be
reached from the merchant hostname.

## Known legacy

Tracked, funded, and not yet done:

- **PLAT-4471 — Northgate integration.** Inherited with the 2021 acquisition.
  3DES envelopes, RC4 on the terminal channel, MD5 request MACs — all dictated
  by their 2009 protocol document. ~400 merchants still route through it; the
  last is scheduled for Q3 next year. `src/services/legacyPartner.js`.
- **PLAT-4390 — partner TLS profile.** `AES128-SHA` and `DES-CBC3-SHA` remain
  in the partner cipher list for one acquirer client. Comes out when they
  finish their 2027 upgrade.
- **Acquirer settlement checksums.** Their file interface has specified MD5
  since 2011 and their loader rejects anything else. It is a transport
  integrity check on a private SFTP channel, not a security boundary — but it
  is still a hash we emit.
- **Scheme advices are SHA-1 signed.** Their interface, their timetable.

## Security

- PANs are encrypted before they reach the database. CVVs are never stored.
- API keys are stored as SHA-256 digests; the key is returned once at creation
  and cannot be read back.
- Logs are redacted at the logger (`src/utils/logger.js`), not at the call
  site — the fastest way to make a compliant system non-compliant is a debug
  log someone added in a hurry.
- No private key material is committed. See `certs/README.md`.
