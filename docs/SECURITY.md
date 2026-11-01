# TGLDS Security Policy

## Cryptographic primitives

- Argon2id version 1.3
- XChaCha20-Poly1305
- 256-bit encryption keys
- 192-bit random nonces
- 128-bit random salts
- Zeroize for secret-memory cleanup

## Security requirements

1. Never reuse a nonce with the same encryption key.
2. Never release unauthenticated plaintext.
3. Authenticate metadata using Associated Data.
4. Validate all archive parameters before processing.
5. Reject malformed or corrupted archives.
6. Never store passwords or plaintext keys in archives.
7. Never introduce cryptographic backdoors.

## Key management

A random Data Encryption Key (DEK) will protect archive data.

Argon2id will derive a Key Encryption Key (KEK) from the user's password.

The KEK will protect the DEK.

Password changes will rewrap the DEK without requiring all data to be encrypted again.

## Development status

These primitives are experimental.
They are not yet an audited production encryption system.
