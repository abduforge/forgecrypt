# Contributing

Thanks for your interest in ForgeCrypt!

## Before opening a pull request

1. Open an issue to describe the proposed change, especially for cryptographic or file-format work.
2. Keep the command line simple and document user-visible behavior.
3. Do not implement custom ciphers, KDFs, random generators, or cryptographic handshakes.
4. Do not change a released container format without a new format identifier and a migration plan.
5. Never add real credentials, keys, passphrases, or private encrypted files to tests or examples.

## Local checks

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
```

## Pull requests

- Explain the problem and the change.
- Include tests for parser and error-handling changes.
- Document security assumptions and limitations.
- Keep changes focused and avoid unrelated formatting churn.

Please report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md), not in a public issue.
