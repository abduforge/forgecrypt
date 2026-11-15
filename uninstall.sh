#!/usr/bin/env sh
set -eu
TARGET=${INSTALL_DIR:-"${HOME}/.local/bin"}/forgecrypt
if [ -e "$TARGET" ]; then
    rm -- "$TARGET"
    echo "Removed $TARGET"
else
    echo "ForgeCrypt is not installed at $TARGET"
fi
