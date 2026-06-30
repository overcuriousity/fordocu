#!/usr/bin/env bash
set -euo pipefail

REPO="overcuriousity/fordocu"

# Determine install prefix
if [ -n "${PREFIX:-}" ]; then
    INSTALL_DIR="$PREFIX"
elif [ -d "$HOME/.local/bin" ] && echo "$PATH" | grep -q "$HOME/.local/bin"; then
    INSTALL_DIR="$HOME/.local/bin"
else
    INSTALL_DIR="/usr/local/bin"
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64) ASSET="fordocu-x86_64-unknown-linux-gnu.tar.gz" ;;
            *) echo "Unsupported architecture for Linux: $ARCH"; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            arm64|aarch64) ASSET="fordocu-aarch64-apple-darwin.tar.gz" ;;
            *) echo "Unsupported architecture for macOS: $ARCH"; exit 1 ;;
        esac
        ;;
    mingw*|msys*|cygwin*|windows_nt)
        ASSET="fordocu-x86_64-pc-windows-msvc.zip"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Fetch latest release download URL
DOWNLOAD_URL=$(curl --proto '=https' --tlsv1.2 -sSf "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -o "https://github.com/$REPO/releases/download/[^\"]*/$ASSET" \
    | head -n 1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Could not find release asset: $ASSET"
    exit 1
fi

echo "Downloading $ASSET..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$ASSET" == *.zip ]]; then
    curl --proto '=https' --tlsv1.2 -sSfL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET"
    unzip -q "$TMP_DIR/$ASSET" -d "$TMP_DIR"
    BINARY="fordocu.exe"
else
    curl --proto '=https' --tlsv1.2 -sSfL "$DOWNLOAD_URL" | tar -xz -C "$TMP_DIR"
    BINARY="fordocu"
fi

mkdir -p "$INSTALL_DIR"
cp "$TMP_DIR/$BINARY" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY"

echo "Installed $BINARY to $INSTALL_DIR"
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "Warning: $INSTALL_DIR is not in your PATH."
fi
