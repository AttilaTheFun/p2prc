#!/bin/bash
# Attaches a folder of signed builds (build_tools' `sign --out`) to
# the repository's release `<tag>`, a
# draft or published: every file but builds.lines, builds.json last, so a
# reader that finds builds.json finds the files it names. An asset of the
# same name is replaced (a proposal run again on its commit), only once its
# replacement is uploaded. What
# Applications lists (the private AttilaTheFun/applications' docs/RELEASE_ASSETS.md).
#
#   tools/ci/attach_release.sh <tag> <dir>
#
# From the job's environment: GH_TOKEN, the job's, with `contents: write`;
# GITHUB_REPOSITORY. bash, curl and gh (gh_ready.sh, beside this file).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
tag="${1:?usage: tools/ci/attach_release.sh <tag> <dir>}"
dir="${2:?usage: tools/ci/attach_release.sh <tag> <dir>}"
repo="${GITHUB_REPOSITORY:?}"
: "${GH_TOKEN:?GH_TOKEN, the job token with contents: write}"
[ -f "$dir/builds.json" ] || { echo "attach_release: $dir has no builds.json" >&2; exit 1; }
# shellcheck source=tools/ci/gh_ready.sh
. "$ROOT/tools/ci/gh_ready.sh"

# A draft has no tag yet: it is found by its tag's name among the releases.
# A draft just made may not be listed for a few seconds: asked again, up to
# a minute.
release=""
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  release="$(gh api "repos/$repo/releases?per_page=100" --jq ".[] | select(.tag_name == \"$tag\") | .id" | head -1)"
  [ -z "$release" ] || break
  [ "$attempt" = 12 ] || sleep 5
done
[ -n "$release" ] || { echo "attach_release: no release $tag in $repo" >&2; exit 1; }

work="$(mktemp -d)"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
# The token in a file, never on a command line.
printf 'Authorization: Bearer %s\nX-GitHub-Api-Version: 2022-11-28\n' "$GH_TOKEN" > "$work/headers"

# Each file is uploaded under a name of its own first, and only once GitHub
# has it does the asset it replaces go and the upload take its name: a
# failure part way (P2PRC 0.1.3's release met a 502 after the old APK was
# deleted, and the release had no APK) leaves the old asset in place. A 5xx
# from GitHub is asked again, up to five times.
gh_retry() {
  local try
  for try in 1 2 3 4 5; do
    "$@" && return 0
    [ "$try" = 5 ] || { echo "attach_release: retrying ($try): $*" >&2; sleep $((try * 10)); }
  done
  return 1
}

attach() {
  local file="$1" name type existing staged staged_id status try
  name="$(basename "$file")"
  case "$name" in
    *.json) type=application/json ;;
    *.apk) type=application/vnd.android.package-archive ;;
    *) type=application/octet-stream ;;
  esac
  staged="new-${GITHUB_RUN_ID:-$$}-$name"
  for try in 1 2 3 4 5; do
    status="$(curl -sS -H @"$work/headers" -H "Content-Type: $type" --data-binary @"$file" --max-time 1800 \
      -o "$work/answer" -w '%{http_code}' "https://uploads.github.com/repos/$repo/releases/$release/assets?name=$staged")" || status=000
    [ "$status" = 201 ] && break
    # A failed upload can leave a half-made asset of that name behind.
    existing="$(gh api "repos/$repo/releases/$release/assets?per_page=100" --jq ".[] | select(.name == \"$staged\") | .id" || true)"
    [ -z "$existing" ] || gh api -X DELETE "repos/$repo/releases/assets/$existing" > /dev/null || true
    case "$status" in 000 | 5*) [ "$try" = 5 ] || { echo "attach_release: $name upload answered $status, retrying" >&2; sleep $((try * 10)); continue; } ;; esac
    echo "attach_release: $name was not attached ($status): $(head -c 300 "$work/answer" 2> /dev/null)" >&2
    exit 1
  done
  [ "$status" = 201 ] || { echo "attach_release: $name was not attached ($status)" >&2; exit 1; }
  staged_id="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["id"])' "$work/answer")"
  existing="$(gh_retry gh api "repos/$repo/releases/$release/assets?per_page=100" --jq ".[] | select(.name == \"$name\") | .id")"
  [ -z "$existing" ] || gh_retry gh api -X DELETE "repos/$repo/releases/assets/$existing" > /dev/null
  gh_retry gh api -X PATCH "repos/$repo/releases/assets/$staged_id" -f name="$name" > /dev/null
  echo "attach_release: $name attached to $tag"
}

for file in "$dir"/*; do
  case "$(basename "$file")" in builds.json|builds.lines|builds.lines.new) continue ;; esac
  [ -f "$file" ] && attach "$file"
done
attach "$dir/builds.json"
