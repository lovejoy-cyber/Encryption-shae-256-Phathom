# PhantomVault

A security platform under active build-out: real cryptography (audited primitives, no invented ciphers), passkey/MFA identity, capability-based revocable encryption, a tamper-evident audit log, and a genuine unsupervised ML anomaly-detection pipeline — engineered and tested module-by-module rather than demoed once and called done.

**Start here:**
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design, crypto design, data flow diagrams, and the honest **implementation status table** (nothing is marked done until it's tested)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE analysis, trust boundaries, adversary models, and the security guarantees table (what this system does and does **not** protect against)

## Quickstart

```bash
docker compose up -d          # postgres, redis, minio, api, ml-service, caddy
npm install
npm run --workspace=@phantomvault/backend db:migrate
node backend/scripts/smoke-test.mjs   # full register → org → capability → audit-log flow over real HTTP
```

Runs the whole platform locally with one command, no cloud account required. See `docker-compose.yml` for the service topology.

## Monorepo layout

```
docs/                Architecture + threat model — read these first
packages/crypto-core/  Shared, test-vector-verified crypto: AES-256-GCM, PBKDF2, HKDF-SHA256, X25519 sealed box
backend/               Fastify API: WebAuthn+TOTP auth, RBAC/orgs, capability-released content, audit log, rate limiting
ml-service/            Python/FastAPI + scikit-learn IsolationForest: per-user anomaly scoring
phantomvault/           Client PWA — Offline Mode (local, zero-account, AES-256 vault/duress vault/SOC log) AND
                        Capability Mode (backend-mediated: passkey login, server-revocable sharing) side by side;
                        android/ is a real (unbuilt) Capacitor-generated Android project skeleton
.github/workflows/     CI: lint, typecheck, unit + security-regression tests, CodeQL, Semgrep, npm/pip audit,
                        Trivy container scan, Gitleaks secret scan, ZAP DAST baseline
```

## What's real here, briefly

- **Crypto**: audited libraries only (`@noble/*`, native WebCrypto) — 29 tests in `packages/crypto-core`, including reference vectors independently generated with Python's `cryptography` library (two of which match the published GCM specification's own test cases).
- **Capability-released content**: a double-envelope design where the server holds an outer key it can revoke/expire without ever seeing plaintext or the inner content key — proven with concurrent-release race tests, not just described in prose (`docs/ARCHITECTURE.md` §5.2). Revoking now deletes the ciphertext blob itself, not just the key gating it.
- **Auth**: real WebAuthn ceremonies tested end-to-end against a FIDO2 authenticator emulator (not mocked-out), refresh-token rotation with theft/reuse detection, TOTP MFA, and a real (if incomplete, no authenticator available in CI) browser-side passkey UI.
- **Audit log**: hash-chained, with a database trigger blocking row-level UPDATE/DELETE, and a test that tampers with a row and confirms the chain verifier catches it.
- **ML**: a real `IsolationForest` over engineered behavioral features (time-of-day, novel device/ASN/country, event velocity) — not an LLM call. Tested against a live injected anomaly.
- **Transport abstraction**: encryption always happens before any transport is chosen. `ManualFileAdapter`/`PhantomRelayAdapter` are bit-perfect by construction; `ConcealedImageAdapter` (LSB steganography) is opt-in only and runs a **live** compatibility self-test — simulates the JPEG recompression a chat app's photo pipeline would do and re-attempts extraction — before ever claiming success. Verified against a real Chromium engine, which caught two real bugs a Node-only test suite couldn't have (see `docs/ARCHITECTURE.md` §9.1).

Every one of these claims has a corresponding automated test in the repo — that traceability is the point (`docs/THREAT_MODEL.md` §9).

## What isn't built yet

Tracked honestly in `docs/ARCHITECTURE.md`'s status table: the enterprise admin console UI, and native builds for the Android skeleton (no JDK/SDK in this environment) / iOS / desktop (no Rust toolchain — Tauri wasn't attempted rather than shipped unverified). Nothing in this list is claimed as done elsewhere in the repo.
