#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-$HOME/research/TLSKeyHunter}"
TAG="v5.7.6-stable"
COMMIT="239b85c80438bf60d9a5b9e0ebe9ff097a760d0d"
ARCHIVE_SHA256="52b1e439e30d1ed8162a16308a8525a862183b67aa30373b11166ecbab000d63"
TOOLS="$REPO/.tools/wolfssl-5.7.6-no-keylog"
ARCHIVE="$TOOLS/wolfssl-v5.7.6-stable.tar.gz"
SOURCE="$TOOLS/source"
BUILD="$TOOLS/build"
PREFIX="$TOOLS/prefix"
OUTPUT="$REPO/ground_truth/wolfssl/compiled_clients_no_keylog"

if [[ -e "$OUTPUT" ]]; then
    echo "refusing to overwrite existing no-keylog baseline: $OUTPUT" >&2
    exit 2
fi

mkdir -p "$TOOLS"
if [[ ! -f "$ARCHIVE" ]]; then
    echo "[COMMAND] Download official wolfSSL $TAG source archive"
    curl -fsSL "https://github.com/wolfSSL/wolfssl/archive/refs/tags/$TAG.tar.gz" -o "$ARCHIVE"
fi
printf '%s  %s\n' "$ARCHIVE_SHA256" "$ARCHIVE" | sha256sum -c -

mkdir -p "$SOURCE"
tar -xzf "$ARCHIVE" --strip-components=1 -C "$SOURCE"
echo "[COMMAND] Configure wolfSSL $TAG with TLS 1.3 and without keylog export"
cmake -S "$SOURCE" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBUILD_SHARED_LIBS=ON \
    -DWOLFSSL_TLS13=yes \
    -DWOLFSSL_EXAMPLES=no \
    -DWOLFSSL_CRYPT_TESTS=no \
    | tee "$TOOLS/cmake-configure.log"
echo "[COMMAND] Build and install wolfSSL"
cmake --build "$BUILD" --parallel 2 | tee "$TOOLS/cmake-build.log"
cmake --install "$BUILD" | tee "$TOOLS/cmake-install.log"

library="$(find "$PREFIX/lib" -maxdepth 1 -type f -name 'libwolfssl.so.*' | sort | tail -n 1)"
if [[ -z "$library" || ! -f "$library" ]]; then
    echo "no shared wolfSSL library was produced" >&2
    exit 1
fi
if strings "$library" | grep -qE 'sslkeylog\.log|WOLFSSL_SSLKEYLOGFILE'; then
    echo "built library still contains keylog-export markers" >&2
    exit 1
fi

mkdir -p "$OUTPUT/libs"
cp -a "$PREFIX/lib"/libwolfssl.so* "$OUTPUT/libs/"
for protocol in 12 13; do
    source_file="$REPO/ground_truth/wolfssl/test_client_${protocol}_wolfssl.c"
    target="$OUTPUT/test_client_${protocol}_wolfssl_dl"
    echo "[COMMAND] Compile controlled TLS $protocol client against no-keylog wolfSSL"
    gcc -O0 -g -fno-omit-frame-pointer \
        -I"$PREFIX/include" "$source_file" \
        -L"$OUTPUT/libs" -Wl,-rpath,'$ORIGIN/libs' -lwolfssl \
        -o "$target"
done

{
    echo "tag=$TAG"
    echo "commit=$COMMIT"
    echo "archive_sha256=$ARCHIVE_SHA256"
    echo "cmake_build_type=RelWithDebInfo"
    echo "wolfssl_tls13=yes"
    echo "build_shared_libs=on"
    echo "keylog_export=disabled"
    sha256sum "$library"
    sha256sum "$OUTPUT"/test_client_*_wolfssl_dl
    readelf -n "$library" | grep -A1 'Build ID' || true
} > "$OUTPUT/build-provenance.txt"

echo "[OK] no-keylog wolfSSL baseline created at $OUTPUT"
