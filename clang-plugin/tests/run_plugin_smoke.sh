#!/usr/bin/env bash
# tests/run_plugin_smoke.sh — build + smoke both baseline plugins.
# Exits non-zero on any failure; suitable for CI/precommit.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
BUILD="$ROOT/build"

# Build (incremental; assumes build/ is already cmake-configured).
cmake --build "$BUILD" --target search_malloc search_um >/dev/null

# ── search_malloc ──────────────────────────────────────────────────────
SM_OUT="$(mktemp)"
clang -fsyntax-only \
      -Xclang -load -Xclang "$BUILD/libsearch_malloc.so" \
      -Xclang -plugin -Xclang search-malloc \
      -Xclang -plugin-arg-search-malloc -Xclang "$SM_OUT" \
      "$ROOT/tests/fixture_search_malloc.c"

sm_rows=$(tail -n +2 "$SM_OUT" | wc -l)
if [[ "$sm_rows" -ne 2 ]]; then
    echo "FAIL search_malloc: expected 2 rows, got $sm_rows" >&2
    cat "$SM_OUT" >&2
    exit 1
fi
echo "OK   search_malloc: 2 rows"

# ── search_um ──────────────────────────────────────────────────────────
UM_OUT="$(mktemp)"
clang -fsyntax-only \
      -Xclang -load -Xclang "$BUILD/libsearch_um.so" \
      -Xclang -plugin -Xclang search-um \
      -Xclang -plugin-arg-search-um -Xclang "$UM_OUT" \
      "$ROOT/tests/fixture_search_um.c"

um_rows=$(tail -n +2 "$UM_OUT" | wc -l)
if [[ "$um_rows" -ne 1 ]]; then
    echo "FAIL search_um: expected 1 row, got $um_rows" >&2
    cat "$UM_OUT" >&2
    exit 1
fi
echo "OK   search_um: 1 row"

rm -f "$SM_OUT" "$UM_OUT"
echo "All smoke checks passed."
