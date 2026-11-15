# Security policy

## Release status

ForgeCrypt 0.1.0 is experimental and has not received an independent security audit. Do not market it as unbreakable, audited, or production-ready.

## Intended threat model

ForgeCrypt is designed to protect the contents of small local files against an attacker who obtains a copy of the encrypted envelope but does not know the passphrase. The AEAD tag detects ciphertext and authenticated-header modification.

It does not protect against a compromised or unlocked endpoint, malware, keyloggers, memory inspection while secrets are in use, weak/reused passphrases, filesystem metadata disclosure, backups outside the encrypted file, or an attacker who can replace the executable or its dependencies.

## Non-negotiable cryptographic rules

- Do not roll your own cipher, hash, KDF, random generator, or AEAD construction.
- Do not invent a network handshake by composing these primitives ad hoc.
- Generate a fresh salt and nonce from the operating-system CSPRNG for every encryption.
- Never decrypt or expose unauthenticated plaintext.
- Validate format version, suite identifiers, and KDF resource parameters before running the KDF.
- Keep secret material in zeroizing buffers where practical; do not claim this eliminates every memory copy.
- Review dependency updates and security advisories before releases.
- Do not change the on-disk format without a version/migration plan.

## Reporting

Until private vulnerability reporting is enabled in the repository, open a minimal issue without secrets or operational exploit details and request a private contact channel. Do not publish sensitive exploit details before maintainers can assess the issue.
