#!/usr/bin/env bash
# Renders web/card.html to web/og.png, the image a link preview shows.
#
# A scraper gets one request and does not run JavaScript, so the preview has
# to be a file in the repository rather than the live page. Re-run this after
# changing the card, or when the map on it has gone stale enough to bother:
#
#   ./scripts/render_social_card.sh
#
# Chrome is the only renderer here that resolves the webfonts and draws the
# SVG exactly as a browser does. 1200x630 is the size every network crops
# from, at device scale 2 so the type is not soft on a retina display.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CHROME="${CHROME:-}"
if [ -z "$CHROME" ]; then
    for candidate in google-chrome chromium chromium-browser google-chrome-stable; do
        if command -v "$candidate" >/dev/null 2>&1; then CHROME="$candidate"; break; fi
    done
fi
if [ -z "$CHROME" ]; then
    echo "no chrome or chromium on PATH, set CHROME=/path/to/browser" >&2
    exit 1
fi

PORT="${PORT:-8791}"
OUT="$ROOT/web/og.png"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [ -n "${SERVER:-}" ] && kill "$SERVER" 2>/dev/null || true' EXIT

# Served rather than opened as a file: the card fetches data/live.json, and a
# file:// origin is refused its own directory.
python3 -m http.server "$PORT" --directory web --bind 127.0.0.1 >/dev/null 2>&1 &
SERVER=$!
for _ in $(seq 1 40); do
    if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/card.html"; then break; fi
    sleep 0.25
done

"$CHROME" --headless=new --no-sandbox --disable-gpu --hide-scrollbars \
    --user-data-dir="$TMP/profile" \
    --force-device-scale-factor=2 \
    --window-size=1200,630 \
    --virtual-time-budget=10000 \
    --screenshot="$OUT" \
    "http://127.0.0.1:${PORT}/card.html" >/dev/null 2>&1

if [ ! -s "$OUT" ]; then
    echo "the browser produced no image" >&2
    exit 1
fi

echo "wrote web/og.png, $(du -h "$OUT" | cut -f1), $(file -b "$OUT" | cut -d, -f2)"
