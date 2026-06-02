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
  echo "ERROR: could not clone the wiki repo."
  echo "  - Is the wiki enabled? (repo Settings → Features → Wikis)"
  echo "  - On a free plan the repo must be PUBLIC for wikis."
  echo "  - Create one page in the web UI first so the wiki repo is initialized."
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
