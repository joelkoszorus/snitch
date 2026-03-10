#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$INSTALL_DIR/snitch"

mkdir -p "$INSTALL_DIR"
ln -sf "$SCRIPT_DIR/snitch" "$TARGET"

echo "snitch installed -> $TARGET"

# Warn if ~/.local/bin is not in PATH
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo ""
    echo "Note: $INSTALL_DIR is not in your PATH."
    echo "Add this to your shell config (~/.bashrc or ~/.zshrc):"
    echo ""
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
    echo "Then run: source ~/.bashrc"
fi
