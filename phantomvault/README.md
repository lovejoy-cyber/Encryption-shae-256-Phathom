# PhantomVault

A local-first privacy suite: AES-256 file/text encryption, image steganography, self-destructing messages, a duress/decoy vault, a B2B secure-sharing portal, and a lightweight SOC monitor — all running client-side as an installable Progressive Web App.

No account, no server, no telemetry. Everything happens in your browser; your files and messages never leave your device unless you choose to share them.

## Features

| Module | What it does | Status |
|---|---|---|
| **Text Vault** | Encrypt a message in-app, paste the ciphertext into WhatsApp/any chat, recipient pastes it back to decrypt. Optional countdown timer + burn-after-reading. | Production-grade crypto; see [self-destruct honesty note](#self-destruct-is-device-local-not-server-enforced) below. |
| **File Locker** | AES-256-GCM encrypts any file, hides it inside a carrier image via LSB steganography. Looks like an ordinary photo. | Production-grade; **must be sent as a file/document attachment**, not a "photo" — see [steganography caveat](#steganography-only-survives-as-a-file-attachment). |
| **Metadata Cleaner** | Strips EXIF/GPS/device metadata from photos before you share them. | Production-grade. |
| **My Vault** | Encrypted-at-rest local file storage, gated by a password. | Production-grade. |
| **Duress / Decoy Vault** | A second password opens an empty decoy vault instead of your real one — plausible deniability under coercion. | Production-grade (VeraCrypt-style hidden-volume model). |
| **File Scanner** | SHA-256 hashing, magic-byte type sniffing, extension/content mismatch and entropy heuristics. Optional pluggable VirusTotal hash lookup (hash only, never file bytes, bring your own API key). | Heuristic, not an AV engine — by design, see code comments. |
| **B2B Portal** | Create a password-protected (optionally WebAuthn-biometric-gated) share for a client; every access is timestamped. | Working local demo; needs a backend for real multi-party use — see [roadmap](#roadmap-enterprise-backend). |
| **SOC Monitor** | Every sensitive action is logged and correlated into "investigations" (brute-force patterns, duress triggers, flagged files). | Production-grade for a single-device log. |
| **Key rotation** | Re-encrypts your vault's canary + every item under a new password. | Production-grade. |

## Getting started

```bash
cd phantomvault
npm install
npm run dev       # http://localhost:5173
npm test          # crypto/vault/ephemeral/scanner unit + fuzz tests
npm run build     # type-checks + production build + PWA manifest
```

Installable as a PWA on desktop, Android, and iOS directly from the browser ("Add to Home Screen" / the install icon in the address bar) — no app store needed. Wrapping it with [Capacitor](https://capacitorjs.com/) is a straightforward next step if you want native app-store builds later.

## Architecture

```
src/lib/            framework-free core — the actual security engine
  crypto.ts          AES-256-GCM + PBKDF2 (600k iterations), text/byte helpers
  steganography.ts   LSB image embed/extract
  ephemeral.ts        timer + burn-after-reading policy on top of crypto.ts
  vault.ts            true/decoy vault storage (IndexedDB via idb-keyval)
  filePayload.ts      packs {name, type, bytes} into one binary blob
  metadata.ts         EXIF/metadata stripping via canvas re-encode
  fileScanner.ts       hash/type/entropy heuristics, optional VT lookup
  b2bPortal.ts         encrypted shares + WebAuthn biometric gate
  soc.ts               event log + correlation rules

src/features/        one folder per screen, each a thin UI over src/lib
tests/                vitest: crypto, vault, ephemeral, file scanner, fuzz
.github/workflows/    CI: lint + typecheck + unit tests, npm audit, CodeQL SAST
.github/dependabot.yml  weekly dependency + Action update PRs
```

## Security model & honest limitations

Being upfront about what this design can and can't guarantee is more valuable than overclaiming — especially for a privacy tool.

### Self-destruct is device-local, not server-enforced
Because the ciphertext you paste into WhatsApp leaves the app entirely, PhantomVault cannot *cryptographically* guarantee it becomes unreadable after the timer — anyone holding both the ciphertext and the password could still decrypt it with the same math. What it does do: embed the expiry/burn policy inside the encrypted envelope itself, and maintain a local ledger so a burn-after-reading message can't be re-opened twice on the same device. True tamper-proof delete-on-read needs a server holding the key — see the roadmap below.

### Steganography only survives as a file attachment
WhatsApp, Telegram (default), and Messenger recompress images sent as "photos," which destroys every hidden LSB bit. The locked image must be sent as a raw file/document attachment. The UI has a persistent warning about this.

### Duress vault threat model
PBKDF2's ~100ms+ cost dominates any timing difference between trying the real vs. decoy password, but this hasn't been hardened against a sophisticated local timing side-channel attacker with instrumented access to the device.

### File scanner is heuristic, not antivirus
No bundled malware engine, no hardcoded API key. `lookupHashReputation()` is an opt-in integration point that sends only a SHA-256 hash — never file bytes — to VirusTotal, and only runs if you supply your own key in Settings.

### B2B portal / WebAuthn is demo-grade
`registerBiometric()`/`verifyBiometric()` use real browser WebAuthn APIs, but store the credential ID client-side with no attestation verification — fine for proving the UX, not for production multi-tenant use.

## Roadmap: enterprise backend

The natural next step for the B2B portal and a truly server-enforced self-destruct is a small **Cloudflare Workers + Durable Objects** backend:
- A Durable Object per secret/share gives atomic delete-on-read and TTL expiry — the actual key material lives server-side and is destroyed on first fetch or timeout, closing the gap described above.
- Workers can verify WebAuthn attestation properly and store public keys server-side, making the B2B biometric gate production-grade.
- This is also the natural monetization boundary: the free tier stays fully local/client-side (no server costs), while the relay/escrow service becomes the paid B2B/enterprise tier (MRR, per-seat, or usage-based).

## Monetization angles this architecture supports

- **Consumer**: free local encryption/steganography/messaging (no server costs to you).
- **Prosumer / journalists / OSINT**: duress vault, metadata cleaner — premium tier.
- **B2B**: white-labeled secure client portal for law firms, accountants, consultants — subscription, once the Durable Object backend lands.
- **Enterprise**: SOC log export/SIEM integration, org-wide key rotation policy, VirusTotal Enterprise integration — highest tier.
