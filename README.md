# lzssh

A small SSH host manager for Windows, loosely inspired by Termius. Written in Rust with egui.

> **Personal project.** I built this for my own use. It may or may not work for you, it may change or break at any time, and there is no support. Use at your own risk.

## What it does

- **Hosts and folders**: save hosts (name, IPv4/IPv6 address, port, user) in folders and connect with a click. Sessions open in Windows Terminal (or a plain console if Windows Terminal is missing) using the built-in Windows OpenSSH client.
- **Secrets vault**: passwords, private keys and FIDO keys, encrypted with a numeric PIN of 6 to 256 digits (Argon2id + XChaCha20-Poly1305) and additionally wrapped with Windows DPAPI.
- **Quick unlock**: unlock with Windows Hello (face, fingerprint, Hello PIN) or a FIDO2 security key (hmac-secret, e.g. YubiKey 5; needs Windows 11) instead of typing the PIN. Set it up on the Secrets screen. The PIN always keeps working.
- **FIDO / security keys**: create `ecdsa-sk` or `ed25519-sk` keys through the native Windows security key dialog (Windows Hello or a hardware key such as a YubiKey).
- **Install key on host**: on the Secrets page, append a key's public key to a server's `~/.ssh/authorized_keys`.
- **Known hosts**: view and remove entries from `~/.ssh/known_hosts`.
- **Device sync**: pair two installs with a one-time code and send selected folders and secrets to the other device. Data goes through a small mailbox on your own Cloudflare Worker (see [Sync server](#sync-server)) and is end-to-end encrypted: the Worker only sees ciphertext. The other device picks it up the next time it has lzssh unlocked.

## Requirements

- Windows 10/11 x64
- OpenSSH client (`C:\Windows\System32\OpenSSH\ssh.exe`, included with Windows)
- Windows Terminal (optional, recommended)

## Install

Download the zip from [Releases](../../releases), unzip it, and run `lzssh.exe`. Keep `lzssh-ssh.exe` in the same folder: it is the helper that runs each SSH session.

## Build from source

```sh
cargo build --release --bins
```

The binaries end up in `target/release/` (`lzssh.exe` and `lzssh-ssh.exe`). Run the tests with `cargo test`.

## Sync server

Sync needs the mailbox Worker in [`worker/`](worker/) deployed to your own Cloudflare account. Deployment is manual:

1. Install the dependencies: `cd worker && pnpm install`
2. Create an access token, for example with `openssl rand -base64 32`.
3. Store it as a Worker secret: `pnpm wrangler secret put ACCESS_TOKEN` (wrangler asks for the value; do not pass it on the command line).
4. Deploy: `pnpm wrangler deploy`. The route in `wrangler.jsonc` points at `lzssh.thelukez.com`; change it for your own domain (the zone must be in the same Cloudflare account).
5. In lzssh, open **Devices** on the first device and enter the server URL and the token under **Sync server**.

Other devices get the server URL and the token from the pairing code. Every request carries the token and is signed with the device's key; a device can only read its own mailbox and only paired devices can drop messages into it.

For local development, copy `worker/.env.example` to `worker/.env` and run `pnpm dev`. Run the Worker tests with `pnpm test`.

## Data

Everything lives in `%APPDATA%\lzssh\`:

| File           | Contents                                                                   |
| -------------- | -------------------------------------------------------------------------- |
| `hosts.json`   | Hosts and folders (plain JSON, no secrets)                                 |
| `secrets.json` | Encrypted vault                                                            |
| `device.json`  | Sync identity and sync server token (both DPAPI-protected), paired devices |

Forgetting the PIN means the vault cannot be recovered. Back up the folder if you care about it.

## Releases

Pushing a tag like `v0.1.0` builds the binaries on GitHub Actions and attaches them to a GitHub Release.

## License

MIT, see [LICENSE](LICENSE).
