# lzssh

A small SSH host manager for Windows, loosely inspired by Termius. Written in Rust with egui.

> **Personal project.** I built this for my own use. It may or may not work for you, it may change or break at any time, and there is no support. Use at your own risk.

## What it does

- **Hosts and folders**: save hosts (name, IPv4/IPv6 address, port, user) in folders and connect with a click. Sessions open in Windows Terminal (or a plain console if Windows Terminal is missing) using the built-in Windows OpenSSH client.
- **Secrets vault**: passwords, private keys and FIDO keys, encrypted with a 6-digit PIN (Argon2id + XChaCha20-Poly1305) and additionally wrapped with Windows DPAPI.
- **FIDO / security keys**: create `ecdsa-sk` or `ed25519-sk` keys through the native Windows security key dialog (Windows Hello or a hardware key such as a YubiKey).
- **Export key to host**: append a public key to a server's `~/.ssh/authorized_keys`.
- **Known hosts**: view and remove entries from `~/.ssh/known_hosts`.
- **Device sync**: pair two installs with a one-time code and send selected folders and secrets directly between them over [iroh](https://iroh.computer) (end-to-end encrypted, peer-to-peer with relay fallback).

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

## Data

Everything lives in `%APPDATA%\lzssh\`:

| File | Contents |
|------|----------|
| `hosts.json` | Hosts and folders (plain JSON, no secrets) |
| `secrets.json` | Encrypted vault |
| `device.json` | Sync identity (DPAPI-protected) and paired devices |

Forgetting the PIN means the vault cannot be recovered. Back up the folder if you care about it.

## Releases

Pushing a tag like `v0.1.0` builds the binaries on GitHub Actions and attaches them to a GitHub Release.
