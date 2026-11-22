#!/usr/bin/env bash
# Fetch the RAG knowledge corpus into knowledge/. Idempotent-ish: re-running
# refreshes the clones. Network required (one-time setup).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KDIR="$ROOT/knowledge"
mkdir -p "$KDIR"

echo "[*] OWASP WSTG (test-case markdown)..."
if [ ! -d "$KDIR/wstg/.git" ]; then
  git clone --depth 1 https://github.com/OWASP/wstg.git "$KDIR/wstg" || \
    echo "[!] WSTG clone failed (offline?); skipping."
else
  git -C "$KDIR/wstg" pull --ff-only || true
fi

echo "[*] Public pentest reports (style exemplars)..."
if [ ! -d "$KDIR/sample_reports/.git" ]; then
  git clone --depth 1 https://github.com/juliocesarfort/public-pentesting-reports.git \
    "$KDIR/sample_reports" || \
    echo "[!] sample-reports clone failed (offline?); skipping."
fi

echo "[*] PTES reporting guidance must be added manually to knowledge/ptes/"
mkdir -p "$KDIR/ptes" "$KDIR/remediation"

echo "[done] Knowledge corpus prepared under $KDIR"
echo "       The curated remediation snippets in knowledge/remediation/ ship with the repo."
echo "       Now run:  rednarrate ingest-kb"
