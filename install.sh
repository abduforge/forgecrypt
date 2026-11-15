#!/usr/bin/env sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="${HOME}/.local/bin"

if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: Cargo is missing. Install a current stable Rust toolchain first." >&2
    exit 1
fi

cd "$PROJECT_DIR"
cargo build --release
mkdir -p "$BIN_DIR"
install -m 0755 target/release/forgecrypt "$BIN_DIR/forgecrypt"

echo "Installed ForgeCrypt to: $BIN_DIR/forgecrypt"
case ":${PATH}:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Add this to your shell profile if needed: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
