#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_REPO="${UPSTREAM_REPO:-zeroxjf/cyanide-ios}"
FORK_REPO="${FORK_REPO:-hxhlb/cyanide-ios}"
BRANCH="${BRANCH:-main}"

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is dirty; commit or stash local changes first" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: GitHub CLI (gh) is required" >&2
  exit 1
fi

echo "Syncing GitHub fork: ${FORK_REPO}:${BRANCH} <- ${UPSTREAM_REPO}:${BRANCH}"
gh repo sync "$FORK_REPO" --source "$UPSTREAM_REPO" --branch "$BRANCH"

echo "Fetching remotes"
git fetch upstream --prune
git fetch origin --prune

echo "Updating local ${BRANCH}"
git switch "$BRANCH"
git pull --ff-only origin "$BRANCH"

echo "Done: local ${BRANCH} is synced with ${FORK_REPO}:${BRANCH}"
