# Wiki (source)

These Markdown files are the source for the project's GitHub wiki. They are kept
in the repo so the wiki is versioned, reviewable, and stays in sync with the code.

`Home.md` is the wiki landing page; `_Sidebar.md` is the navigation. Cross-links
use the wiki `[[Page Name]]` syntax (GitHub maps `Page Name` → `Page-Name.md`).

## Publishing to GitHub

GitHub hosts wikis in a separate `*.wiki.git` repo. **Wikis on private repos
require a paid plan** (Pro/Team/Enterprise); on the free plan, make the repo public
or upgrade. Then:

1. Repo **Settings → Features → Wikis** → enable.
2. Create one page in the web UI (this initializes the wiki repo).
3. Run the publisher:

   ```bash
   ./wiki/publish.sh
   ```

It clones the wiki repo, copies these pages, and pushes. Re-run any time to sync.

> The same content also lives under `docs/` for in-repo reading without GitHub.
