#!/bin/sh
# One-shot: enable repo hooks so Cursor co-author lines are stripped from commits.
set -e
root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "Run this script from inside the cloned repository."
  exit 1
}
cd "$root"
git config core.hooksPath .githooks
cp -f .githooks/commit-msg .git/hooks/commit-msg
chmod +x .git/hooks/commit-msg .githooks/commit-msg
echo "Git hooks installed (core.hooksPath=.githooks; backup copy in .git/hooks/commit-msg)."
