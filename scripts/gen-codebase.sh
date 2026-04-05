#!/usr/bin/env bash
# Generates CODEBASE.txt: file:line-anchored function/type map for the project.
# Run from anywhere inside the repo: scripts/gen-codebase.sh

REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
OUT="${REPO}/CODEBASE.txt"
PROJ=$(cd "$REPO" && go list -m)

{
echo "# ${PROJ} — Codebase Map"
echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "# Usage: grep for a type/func name to find its file and line number."
echo ""

# ── Per-file symbol index ─────────────────────────────────────────────────────
find "$REPO" -name "*.go" ! -name "*_test.go" | sort | while read -r f; do
  rel="${f#${REPO}/}"
  matches=$(grep -nE "^func |^type [A-Za-z]|^const [A-Za-z(]|^var [A-Za-z(]" "$f" 2>/dev/null || true)
  if [ -n "$matches" ]; then
    echo "── ${rel}"
    echo "$matches" | while IFS=: read -r lineno content; do
      printf "  %4d  %s\n" "$lineno" "$content"
    done
    echo ""
  fi
done

# ── go doc exported API (signatures only, no prose) ──────────────────────────
echo ""
echo "## Exported API (go doc)"
echo ""

for pkg in $(cd "$REPO" && go list ./... 2>/dev/null); do
  sigs=$(go doc -all "$pkg" 2>/dev/null | grep -E "^func |^type |^var |^const " || true)
  if [ -n "$sigs" ]; then
    echo "### ${pkg}"
    echo "$sigs" | sed 's/^/  /'
    echo ""
  fi
done

} > "$OUT"

echo "✓ wrote CODEBASE.txt ($(wc -l < "$OUT") lines, $(du -h "$OUT" | cut -f1))"
