# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

lzssh: Windows-only SSH host manager (Rust, egui/eframe) plus a Cloudflare Worker mailbox for device sync (`worker/`, TypeScript). Personal project; see README.md for features, data files and Worker deployment.

## Commands

Rust (repo root, Windows only: uses DPAPI, WebAuthn, named pipes, `C:\Windows\System32\OpenSSH\ssh.exe`):

- Test all: `cargo test --locked`
- Single test: `cargo test <name>` (substring match), e.g. `cargo test sync::mailbox::`
- Release build: `cargo build --release --bins` (produces `lzssh.exe` and `lzssh-ssh.exe`; both must ship together)
- Run GUI: `cargo run`

Worker (`cd worker`, pnpm):

- `pnpm test` (vitest + `@cloudflare/vitest-plugin`, single file: `pnpm vitest run test/auth.test.ts`)
- `pnpm check` (tsc), `pnpm dev` (needs `.env` copied from `.env.example`), `pnpm wrangler deploy`
- After editing `wrangler.jsonc` bindings, run `pnpm types` to regenerate `worker-configuration.d.ts`.

CI (`.github/workflows/ci.yml`) runs only the Rust tests and build on Windows; Worker tests are not in CI. Tags `vX.Y.Z` create a GitHub Release.

## Architecture

Two binaries share the library crate (`src/lib.rs`):

- `lzssh` (`src/main.rs`): GUI, single instance via a named mutex. Clears the run dir on start and exit.
- `lzssh-ssh` (`src/bin/lzssh-ssh.rs`): console helper that runs inside Windows Terminal tabs. Two modes: `--launch <file>` (reads and deletes an `SshInvocation` JSON written by the GUI) and SSH_ASKPASS client (env `LZSSH_ASKPASS=1` + `LZSSH_ASKPASS_TOKEN`).

Connect flow (`connect.rs`, `askpass.rs`): GUI builds an `SshInvocation` for the host, materializes keys into a run dir, and opens Windows Terminal running `lzssh-ssh --launch`. Password auth works via ssh's SSH_ASKPASS: the helper asks the running GUI over a per-user named pipe with a single-use 60 s token held in an in-memory `Registry`. Always uses the Windows OpenSSH `ssh.exe` (Git's ssh cannot do FIDO via WebAuthn).

Vault (`vault.rs`, `quick_unlock.rs`, `dpapi.rs`): secrets are Argon2id(PIN) + XChaCha20-Poly1305 per value, whole file DPAPI-wrapped. Quick unlock (Windows Hello or FIDO2 hmac-secret) wraps the vault key; the PIN always still works. `keys.rs` creates FIDO `-sk` keys via the native WebAuthn dialog.

Sync (`src/sync/`, `device.rs`, `ui/devices.rs`): end-to-end encrypted mailbox sync between paired installs.
- `crypto.rs`: device Ed25519/X25519 keys, `Envelope` seal/open, request `signing_string`.
- `code.rs`: pairing code. `payload.rs`: what gets sent (folders, secrets).
- `mailbox.rs`: synchronous `Core` state machine on a background thread, driven by `NetCmd` messages from the UI; pairing, send, receive, ack.
- `transport.rs`: `Transport` trait with `HttpTransport` (ureq) and an in-memory server for tests, so sync logic is tested without the Worker.
- `device.rs`: persisted identity, paired devices, server token (DPAPI-protected).

Worker (`worker/src/`): `index.ts` is a table-driven router (`ROUTE_DEFS`, `wildcard-match`; `*` = one segment) that checks the bearer `ACCESS_TOKEN`, caps the body at 1 MiB, verifies the Ed25519 request signature (`auth.ts`), then calls the `Mailbox` Durable Object (`mailbox.ts`, SQLite-backed, one per device public key, addressed by hex id). Server only ever sees ciphertext envelopes.

Rust and TypeScript must agree on the request signing string (`lzssh-req-v1\nMETHOD\nPATH\nTIME\nNONCE\nsha256hex(body)`), header names (`X-Lz-*`), limits (1 MiB envelope) and envelope schema: change both sides together.

## Conventions

- `docs/superpowers/specs` and `plans` hold the design docs for the MVP and mailbox sync; consult them for intent.
- FIDO / security keys stay touch-only (no user verification, no `-O verify-required`) by owner decision; do not add UV.
