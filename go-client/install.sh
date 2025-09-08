#!/usr/bin/env bash
set -euo pipefail

# Install Go 1.21.0 on Linux (amd64 / arm64 / 386)
# Usage: sudo ./install-go-1.21.sh
# (will use sudo for operations that require root)

VERSION="1.21.0"
BASE_URL="https://go.dev/dl"

# Official SHA256 checksums (from go.dev/dl for go1.21.0)
SHA_AMD64="d0398903a16ba2232b389fb31032ddf57cac34efda306a0eebac34f0965a0742"
SHA_ARM64="f3d4548edf9b22f26bbd49720350bbfe59d75b7090a1a2bff1afad8214febaf3"
SHA_386="0e6f378d9b072fab0a3d9ff4d5e990d98487d47252dba8160015a61e6bd0bcba"

# Determine architecture
_uname_m="$(uname -m)"
case "$_uname_m" in
  x86_64|amd64) ARCH="amd64"; FNAME="go${VERSION}.linux-amd64.tar.gz"; SHA_EXPECT="$SHA_AMD64" ;;
  aarch64|arm64) ARCH="arm64"; FNAME="go${VERSION}.linux-arm64.tar.gz"; SHA_EXPECT="$SHA_ARM64" ;;
  i386|i686) ARCH="386"; FNAME="go${VERSION}.linux-386.tar.gz"; SHA_EXPECT="$SHA_386" ;;
  *)
    echo "Unsupported architecture: $_uname_m"
    exit 1
    ;;
esac

URL="${BASE_URL}/${FNAME}"

# Download to tempdir
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

OUT="$TMPDIR/$FNAME"
echo "Downloading $URL ..."
if command -v curl >/dev/null 2>&1; then
  curl -fSL --retry 3 -o "$OUT" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$OUT" "$URL"
else
  echo "Error: neither curl nor wget is available."
  exit 1
fi

# Verify SHA256
if command -v sha256sum >/dev/null 2>&1; then
  SHA_ACTUAL="$(sha256sum "$OUT" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SHA_ACTUAL="$(shasum -a 256 "$OUT" | awk '{print $1}')"
else
  echo "Warning: no sha256 tool (sha256sum/shasum) found — skipping checksum (NOT recommended)."
  SHA_ACTUAL=""
fi

if [ -n "$SHA_ACTUAL" ]; then
  if [ "$SHA_ACTUAL" != "$SHA_EXPECT" ]; then
    echo "Checksum mismatch for $OUT!"
    echo " expected: $SHA_EXPECT"
    echo " actual:   $SHA_ACTUAL"
    exit 1
  else
    echo "Checksum OK."
  fi
fi

# Remove old install
echo "Removing old /usr/local/go (if exists) ..."
if [ "$(id -u)" -ne 0 ]; then
  sudo rm -rf /usr/local/go
else
  rm -rf /usr/local/go
fi

# Extract
echo "Extracting to /usr/local ..."
if [ "$(id -u)" -ne 0 ]; then
  sudo tar -C /usr/local -xzf "$OUT"
else
  tar -C /usr/local -xzf "$OUT"
fi

# Create /etc/profile.d/go.sh for all users (requires sudo)
PROFILE_SH_CONTENT='export PATH=$PATH:/usr/local/go/bin'
echo "Writing /etc/profile.d/go.sh ..."
if [ "$(id -u)" -ne 0 ]; then
  echo "$PROFILE_SH_CONTENT" | sudo tee /etc/profile.d/go.sh > /dev/null
  sudo chmod 644 /etc/profile.d/go.sh
else
  echo "$PROFILE_SH_CONTENT" > /etc/profile.d/go.sh
  chmod 644 /etc/profile.d/go.sh
fi

# Also add to invoking user's profile (~/.profile) if not already present
# If script run via sudo, use SUDO_USER to find the original user
if [ -n "${SUDO_USER:-}" ]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="$(id -un)"
fi
USER_HOME="$(eval echo "~$TARGET_USER")"
USER_PROFILE="$USER_HOME/.profile"

# Append PATH export to user's profile if not present
if ! grep -q "/usr/local/go/bin" "$USER_PROFILE" 2>/dev/null; then
  echo "" >> "$USER_PROFILE" || true
  echo "# Added by install-go-1.21.sh" >> "$USER_PROFILE" || true
  echo "export PATH=\$PATH:/usr/local/go/bin" >> "$USER_PROFILE" || true
  echo "Updated $USER_PROFILE for user $TARGET_USER"
else
  echo "$USER_PROFILE already contains /usr/local/go/bin"
fi

# Verify installation
echo "Verifying go installation..."
if command -v go >/dev/null 2>&1; then
  GO_BIN="$(command -v go)"
  echo "go binary: $GO_BIN"
  go version
else
  echo "go is not in PATH for current shell. Try 'source $USER_PROFILE' or open a new shell."
  echo "You can check with: /usr/local/go/bin/go version"
  /usr/local/go/bin/go version || true
fi

echo "Done. Installed Go ${VERSION} for arch ${ARCH}."
