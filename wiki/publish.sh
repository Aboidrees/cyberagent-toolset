#!/usr/bin/env bash
#
# Publish these pages to the GitHub wiki.
#
# Prerequisite: the wiki must be ENABLED on the repo. GitHub only allows wikis on
# private repos with a paid plan (Pro/Team/Enterprise); on the free plan, make the
# repo public (Settings → General → Danger Zone) or upgrade. Then enable the wiki
# (Settings → Features → Wikis) and create one page in the web UI so the wiki repo
# exists. After that, run this script.
#
# Usage:  ./wiki/publish.sh [owner/repo]   (default: Aboidrees/cyberagent-toolset)
set -euo pipefail

REPO="${1:-Aboidrees/cyberagent-toolset}"
WIKI_URL="https://github.com/${REPO}.wiki.git"
SRC="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"

echo "Cloning wiki: $WIKI_URL"
if ! git clone "$WIKI_URL" "$TMP" 2>/dev/null; then
  echo "ERROR: the wiki git repo does not exist yet."
  echo
  echo "GitHub creates it only after the FIRST page is saved in the web UI"
  echo "(there is no API to do this). One-time step:"
  echo
  echo "  1. Open  https://github.com/${REPO}/wiki"
  echo "  2. Click 'Create the first page', type anything, 'Save Page'."
  echo "  3. Re-run ./wiki/publish.sh  — it overwrites that page with all pages."
  echo
  echo "(Wiki feature must be enabled and, on a free plan, the repo public —"
  echo " both already done for this repo.)"
  exit 1
fi

# Copy every page except this folder's README (not a wiki page).
for f in "$SRC"/*.md; do
  [ "$(basename "$f")" = "README.md" ] && continue
  cp "$f" "$TMP"/
done
cd "$TMP"
git add -A
if git diff --cached --quiet; then
  echo "Wiki already up to date — nothing to publish."
else
  git commit -m "docs(wiki): sync from repo wiki/ ($(date -u +%Y-%m-%d))"
  git push origin HEAD
  echo "Published to https://github.com/${REPO}/wiki"
fi
rm -rf "$TMP"
