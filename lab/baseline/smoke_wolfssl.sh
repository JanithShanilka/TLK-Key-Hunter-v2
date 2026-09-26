#!/usr/bin/env bash
set -euo pipefail

repo_dir="${1:-$HOME/research/TLSKeyHunter}"
protocol="${2:-12}"

if [[ "$protocol" != "12" && "$protocol" != "13" ]]; then
    echo "usage: $0 [repo-dir] [12|13]" >&2
    exit 2
fi

case "$protocol" in
    12)
        port=4432
        openssl_protocol=(-tls1_2)
        ground_truth_client="test_client_12_wolfssl_key_export_dl"
        ;;
    13)
        port=4433
        openssl_protocol=(-tls1_3)
        ground_truth_client="test_client_13_wolfssl_key_export_dl"
        ;;
esac

client_dir="$repo_dir/ground_truth/wolfssl/compiled_clients"
library_dir="$client_dir/libs"
hook="$repo_dir/tlsKeyExtraction/wolfssl_key_dump_linux_x86_64.js"
frida="$HOME/.venv/bin/frida"
scratch="$(mktemp -d "/tmp/tlskh-wolfssl-${protocol}.XXXXXX")"
server_pid=""

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [[ "$scratch" == /tmp/tlskh-wolfssl-* ]]; then
        find "$scratch" -depth -delete
    fi
}
trap cleanup EXIT

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -subj "/CN=localhost" \
    -keyout "$scratch/server.key" \
    -out "$scratch/server.crt" \
    -days 1 \
    >/dev/null 2>&1

openssl s_server \
    -accept "127.0.0.1:$port" \
    -cert "$scratch/server.crt" \
    -key "$scratch/server.key" \
    "${openssl_protocol[@]}" \
    -quiet \
    >"$scratch/server.log" 2>&1 &
server_pid=$!

sleep 1

cd "$scratch"
set +e
printf "\n\n" |
    timeout 25s \
    env LD_LIBRARY_PATH="$library_dir" \
    "$frida" \
    -f "$client_dir/$ground_truth_client" \
    -l "$hook" \
    --runtime=v8 \
    >"$scratch/frida.log" 2>&1
frida_status=$?
set -e

if [[ ! -s "$scratch/sslkeylog.log" ]]; then
    echo "ground_truth_status=failed"
    echo "frida_exit=$frida_status"
    sed -n '1,100p' "$scratch/frida.log"
    echo "server_diagnostics:"
    sed -n '1,80p' "$scratch/server.log"
    exit 1
fi

comparison="$(
    python3 - "$scratch/frida.log" "$scratch/sslkeylog.log" <<'PY'
import re
import sys
from pathlib import Path

key_line = re.compile(
    r"((?:CLIENT_RANDOM|CLIENT_[A-Z0-9_]+|SERVER_[A-Z0-9_]+)"
    r"\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+)"
)
frida_lines = Path(sys.argv[1]).read_text(errors="replace").splitlines()
ground_truth_lines = {
    line.strip().upper()
    for line in Path(sys.argv[2]).read_text(errors="replace").splitlines()
    if key_line.fullmatch(line.strip())
}
hook_lines = set()
for line in frida_lines:
    if "[TLSKH_KEY]" not in line:
        continue
    match = key_line.search(line)
    if match:
        hook_lines.add(match.group(1).upper())

matches = ground_truth_lines & hook_lines
print(f"ground_truth_lines={len(ground_truth_lines)}")
print(f"frida_extracted_lines={len(hook_lines)}")
print(f"exact_matches={len(matches)}")
print(f"exact_match={'true' if matches else 'false'}")
PY
)"
pattern_matches="$(grep -c 'Pattern found at' "$scratch/frida.log" || true)"

echo "protocol=TLS1.$([[ "$protocol" == 12 ]] && echo 2 || echo 3)"
echo "$comparison"
echo "pattern_matches=$pattern_matches"
echo "frida_exit=$frida_status"
echo "frida_diagnostics:"
grep -E 'Found WolfSSL|Pattern found|TLSKH_KEY|Error|Failed|Unable|Established' \
    "$scratch/frida.log" |
    sed -E 's/(CLIENT_RANDOM|CLIENT_[A-Z0-9_]+|SERVER_[A-Z0-9_]+)[[:space:]]+[0-9A-Fa-f]+[[:space:]]+[0-9A-Fa-f]+/\1 <redacted>/' |
    head -n 100 || true

if [[ "$pattern_matches" -lt 1 ]] || ! grep -q '^exact_match=true$' <<<"$comparison"; then
    exit 1
fi
