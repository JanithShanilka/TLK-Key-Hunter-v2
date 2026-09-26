#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_SCRIPT_DIR=""
DEFAULT_INPUT_DIR="/usr/local/src/binaries"
DEFAULT_LOG_FILE="$SCRIPT_DIR/tls_key_hunter.log"
DEFAULT_PROJECT_ROOT="${TMPDIR:-/tmp}"

DEBUG_FLAG=false
POSITIONAL_ARGS=()

if [[ "${DEBUG_RUN:-false}" =~ ^([Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss])$ ]]; then
    DEBUG_FLAG=true
fi

usage() {
    cat <<'EOF'
Usage:
  ./ghidra_analysis.sh [--debug] [<binary-or-directory>] [<log-file>]

Examples:
  ./ghidra_analysis.sh ./binary/libssl.so
  ./ghidra_analysis.sh --debug ./binary ./results/tls_key_hunter.log

If no input path is provided, the script defaults to /usr/local/src/binaries.
EOF
}

log() {
    echo "[*] $*"
}

error() {
    echo "[-] $*" >&2
}

cleanup() {
    if [[ -n "$GHIDRA_SCRIPT_DIR" && -d "$GHIDRA_SCRIPT_DIR" ]]; then
        rm -rf "$GHIDRA_SCRIPT_DIR"
    fi
}

prepare_ghidra_script_dir() {
    local temp_root="${TMPDIR:-/tmp}"
    local bundle_root

    bundle_root="$(mktemp -d "$temp_root/tlskeyhunter-ghidra-bundle.XXXXXX")"
    GHIDRA_SCRIPT_DIR="$bundle_root/ghidra_scripts"
    mkdir -p "$GHIDRA_SCRIPT_DIR"
    cp "$SCRIPT_DIR/TLSKeyHunter.java" "$GHIDRA_SCRIPT_DIR/TLSKeyHunter.java"
    cp "$SCRIPT_DIR/MinimalAnalysisOption.java" "$GHIDRA_SCRIPT_DIR/MinimalAnalysisOption.java"
    GHIDRA_SCRIPT_DIR="$(cd "$GHIDRA_SCRIPT_DIR" && pwd -P)"
}

is_supported_binary() {
    local candidate="$1"
    local file_output

    file_output="$(file -b "$candidate" 2>/dev/null || true)"
    [[ "$file_output" =~ [Ee][Ll][Ff]|Mach-O|PE32 ]]
}

collect_binaries() {
    local input_path="$1"

    if [[ -f "$input_path" ]]; then
        if is_supported_binary "$input_path"; then
            printf '%s\n' "$input_path"
        else
            error "Unsupported file type: $input_path"
            return 1
        fi
        return 0
    fi

    if [[ ! -d "$input_path" ]]; then
        error "Input path does not exist: $input_path"
        return 1
    fi

    find "$input_path" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' candidate; do
        if is_supported_binary "$candidate"; then
            printf '%s\n' "$candidate"
        fi
    done
}

print_analysis_excerpt() {
    local log_file="$1"
    local binary_name="$2"

    sed -n "/=== Start analyzing ${binary_name} ===/,/=== Finished analyzing ${binary_name} ===/p" "$log_file" | \
        sed -n '/TLSKeyHunter/,/Thx for using TLSKeyHunter/p'
}

run_analysis() {
    local analyze_headless="$1"
    local ghidra_script_dir="$2"
    local binary_path="$3"
    local log_file="$4"
    shift 4
    local extra_script_args=("$@")

    local binary_abs_path
    local binary_name
    binary_name="$(basename "$binary_path")"
    binary_abs_path="$(cd "$(dirname "$binary_path")" && pwd)/$binary_name"
    local project_name="ghidra_project_${binary_name}_$(date +%s)"
    local command=(
        "$analyze_headless"
        "$DEFAULT_PROJECT_ROOT"
        "$project_name"
        -import "$binary_abs_path"
        -scriptPath "$ghidra_script_dir"
        -prescript MinimalAnalysisOption.java
        -postScript TLSKeyHunter.java
    )

    if [[ ${#extra_script_args[@]} -gt 0 ]]; then
        command+=("${extra_script_args[@]}")
    fi
    command+=(-deleteProject)

    log "Analyzing $binary_name..."

    {
        echo "=== Start analyzing $binary_name ==="
        (
            cd "$ghidra_script_dir"
            "${command[@]}"
        )
        echo "=== Finished analyzing $binary_name ==="
    } >> "$log_file" 2>&1

    print_analysis_excerpt "$log_file" "$binary_name"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--debug)
            DEBUG_FLAG=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

INPUT_PATH="${POSITIONAL_ARGS[0]:-$DEFAULT_INPUT_DIR}"
LOG_FILE="${POSITIONAL_ARGS[1]:-$DEFAULT_LOG_FILE}"

mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"

if $DEBUG_FLAG; then
    log "Debug mode enabled."
    DEBUG_ARGS=("DEBUG_RUN=true")
else
    DEBUG_ARGS=()
fi

ANALYZE_HEADLESS="$("$SCRIPT_DIR/ensure_prerequisites.sh" --print-analyze-headless)"
log "Using analyzeHeadless at $ANALYZE_HEADLESS"

prepare_ghidra_script_dir
trap cleanup EXIT
log "Using isolated Ghidra script directory at $GHIDRA_SCRIPT_DIR"

BINARIES=()
while IFS= read -r binary_path; do
    BINARIES+=("$binary_path")
done < <(collect_binaries "$INPUT_PATH")

if [[ ${#BINARIES[@]} -eq 0 ]]; then
    error "No supported binaries found in $INPUT_PATH"
    exit 1
fi

for binary_path in "${BINARIES[@]}"; do
    if [[ ${#DEBUG_ARGS[@]} -gt 0 ]]; then
        run_analysis "$ANALYZE_HEADLESS" "$GHIDRA_SCRIPT_DIR" "$binary_path" "$LOG_FILE" "${DEBUG_ARGS[@]}"
    else
        run_analysis "$ANALYZE_HEADLESS" "$GHIDRA_SCRIPT_DIR" "$binary_path" "$LOG_FILE"
    fi
done
