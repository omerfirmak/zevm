#!/usr/bin/env bash
set -euo pipefail

BASE="https://pub-df22334654034ebab51bc096137a59d8.r2.dev/devnets/glamsterdam-devnet-7"
OUT_DIR="${1:-zk_fixtures}"
COUNT="${2:-1000}"
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
CHAIN_ID=$(zstd -d "$FIRST_BATCH" --stdout | tar -xO .meta/manifest.json \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['artifacts'][0]['chainId'])")

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

    for json in $(find "$tmp/blockchain_tests" -name '*.json' | sort); do
        block=$(basename "$json" | cut -d- -f1)
        stderr=$(jq -r '.[].blocks[].statelessInputBytes[2:]' "$json" \
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
