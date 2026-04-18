# Secure Password Vault

A lightweight, offline password vault written in Python with modern cryptographic protections, including Argon2 key derivation, AES-GCM encryption, and HMAC-based integrity verification.

Written by Alayna Ferdarko — April 18, 2026

---

## Features

- **Argon2id key derivation** for strong master password protection
- **AES-GCM encryption** for authenticated encryption of vault data
- **HMAC integrity verification** to detect tampering
- **Offline-first design** (no network dependencies)
- **Secure password generator** using Python's `secrets` module
- Add, edit, search, and list credential entries
- Simple CLI-based interface
- Basic lockout mechanism for repeated failed attempts

---

## Security Overview

This vault uses a layered cryptographic approach:

### Key Derivation
- `Argon2id` is used to derive a 32-byte encryption key from the master password
- Each vault is protected by a unique 16-byte salt

### Encryption
- `AES-256-GCM` ensures confidentiality and authenticity of vault data
- A fresh nonce is generated for every encryption operation

### Integrity
- A separate HMAC-SHA256 key (derived from the encryption key) is used
- Prevents undetected tampering of stored vault data

---

## Requirements

Install dependencies:

```bash
pip install argon2-cffi cryptography
