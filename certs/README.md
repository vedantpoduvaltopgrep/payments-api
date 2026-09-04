# certs/

Pinned partner certificates and trust anchors. Public material only.

**No private key is committed to this repository, and none ever should be.**
Signing keys live in the KMS and are mounted at `/run/secrets/` at pod start;
see `src/config/index.js`.

| File | Holds | Notes |
|---|---|---|
| `acquirer.crt` | Northbank acquiring | Pinned for inbound webhook verification. |
| `scheme-advice.crt` | Cardinal scheme network | Signs settlement advices. |
| `northgate-legacy.crt` | Northgate gateway | Inherited with the 2021 acquisition. Retire with PLAT-4471. |
| `internal-ca.crt` | Aurora internal issuing CA | Signs mTLS client certificates. |
| `partner-ca-bundle.pem` | Trust bundle | The two live partner anchors, concatenated. |

Every certificate here is a **self-signed throwaway generated for this demo
repository**. They are not issued by any real CA, they authenticate nothing,
and the keys behind them were discarded at generation. Do not use them for
anything.
