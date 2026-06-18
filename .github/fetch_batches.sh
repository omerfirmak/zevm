#!/usr/bin/env bash
set -euo pipefail

BASE="https://pub-5345007fbd06486bbb7cbbe9f3112c45.r2.dev/devnets/glamsterdam-devnet-5"
OUT_DIR="${1:-zk_fixtures}"
COUNT="${2:-10}"
GUEST="./zig-out/bin/zevm-guest"

mkdir -p "$OUT_DIR"

# Homebrew curl has modern TLS; macOS system curl uses old LibreSSL
if [[ -x /opt/homebrew/opt/curl/bin/curl ]]; then
    CURL=/opt/homebrew/opt/curl/bin/curl
elif [[ -x /usr/local/opt/curl/bin/curl ]]; then
    CURL=/usr/local/opt/curl/bin/curl
else
    CURL=curl
fi

# ── 1. Download latest N batches ─────────────────────────────────────────────

echo "Fetching batch index..."
while IFS= read -r line; do
    PATH_FIELD=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin)['path'])")
    FILENAME=$(basename "$PATH_FIELD")
    DEST="$OUT_DIR/$FILENAME"
    if [[ -f "$DEST" ]]; then
        echo "  skip (exists): $FILENAME"
        continue
    fi
    echo "  downloading: $FILENAME"
    "$CURL" -fsSL --progress-bar -o "$DEST" "$BASE/$PATH_FIELD"
done < <("$CURL" -fsSL "$BASE/batches.jsonl" | tail -n "$COUNT")

echo ""

# ── 2. Extract chainId and build native guest ─────────────────────────────────

FIRST_BATCH=$(ls "$OUT_DIR"/*.tar.zst | sort -V | head -1)
FIRST_JSON=$(zstd -d "$FIRST_BATCH" --stdout | tar -t | grep '\.json\.zst$' | head -1)
CHAIN_ID=$(zstd -d "$FIRST_BATCH" --stdout | tar -xO "$FIRST_JSON" | zstd -d --stdout \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['chainId'])")

echo "chainId = $CHAIN_ID — building native guest..."
zig build guest -Dchainid="$CHAIN_ID" -Doptimize=ReleaseSafe
echo ""

# ── 3. Run all blocks through the guest ──────────────────────────────────────

ok=0; fail=0

for tarball in "$OUT_DIR"/*.tar.zst; do
    echo "--- $(basename "$tarball")"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    zstd -d "$tarball" --stdout | tar -x -C "$tmp"

    for json_zst in $(find "$tmp" -name '*.json.zst' | sort); do
        block=$(basename "$json_zst" | cut -d- -f1)
        stderr=$(zstd -d --stdout "$json_zst" \
            | jq -r '.statelessInputBytes[2:]' \
            | xxd -r -p \
            | "$GUEST" 2>&1 >/dev/null || true)
        if [[ -z "$stderr" ]]; then
            echo "  block $block: ok"
            ok=$((ok + 1))
        else
            echo "  block $block: FAIL -- $(echo "$stderr" | head -1)"
            fail=$((fail + 1))
        fi
    done

    rm -rf "$tmp"
    trap - EXIT
done

echo ""
echo "$ok ok, $fail failed"
[[ $fail -eq 0 ]]
