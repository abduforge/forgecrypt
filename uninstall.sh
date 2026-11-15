#!/usr/bin/env sh
set -eu
TARGET="${HOME}/.local/bin/forgecrypt"
if [ -e "$TARGET" ]; then
    rm -- "$TARGET"
    echo "Removed $TARGET"
else
    echo "ForgeCrypt is not installed in ~/.local/bin"
fi
