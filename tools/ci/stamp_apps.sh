#!/bin/bash
# Stamps a publishing job's checkout with its builds' version, before they
# are built (AGENTS.md, "Versions and releases"). The apps commit
# MAJOR.MINOR.0; a build is MAJOR.MINOR.N, the number releases are tagged
# with (v0.1.N), from the repository's own releases
# (tools/ci/version_from_tags.sh): the version of a release already made on
# the job's commit (a proposal run again, or the release job of a published
# one), else one past the highest v<line>.N among the releases, drafts
# included, and tags. A new line (a minor bumped and committed as
# MAJOR.MINOR.0) has none yet, so its builds count from MAJOR.MINOR.1. Then
# CI's own tool writes it wherever the apps show it (`convo_ci
# stamp-version`: both Info.plists, Client.version, Android's version_name
# and version_code), and the job's commit into the Apple apps' Info.plists
# (ConvoCommit, which their signatures seal and `convo_ci verify-alphas`
# reads back). Never committed: each job checks out afresh. The
# Playground's tools/ci/stamp_apps.sh, with convo_ci in place of its
# stamp.py.
#
#   tools/ci/stamp_apps.sh             # the version from the releases
#   tools/ci/stamp_apps.sh <version>   # that version, of the committed line,
#                                      # as another job of the run found it
#
# The version is also written to $GITHUB_OUTPUT as `version`, when there is
# one, so the run's other jobs stamp the same: a workflow's jobs build on
# several machines (the Apple apps on a Mac, Android on an x86_64 runner).
#
# From the job's environment, with no <version>, as version_from_tags.sh's:
# GH_TOKEN, the job's (with `contents: write`, which lists drafts; a
# published release is listed with `contents: read`), GITHUB_REPOSITORY and
# GITHUB_SHA. convo_ci is built here (Bazel's settings written first:
# .github/actions/bazel_cache).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# The iPhone app first: version_from_tags.sh takes the line from the first
# Info.plist.
plists=(
    "$ROOT/applications/p2prc_ios/Info.plist"
    "$ROOT/applications/p2prc_macos/Info.plist"
)
# An Info.plist's CFBundleShortVersionString (its first <string> after the key).
plist_version() {
    awk '
        /<key>CFBundleShortVersionString<\/key>/ { found = 1 }
        found && match($0, /<string>[^<]*<\/string>/) { print substr($0, RSTART + 8, RLENGTH - 17); exit }' "$1"
}
if [ $# -eq 0 ]; then
    "$ROOT/tools/ci/version_from_tags.sh" "${plists[@]}"
    version="$(plist_version "${plists[0]}")"
else
    # The version given: of the line the first Info.plist commits.
    version="$1"
    line="$(plist_version "${plists[0]}" | cut -d. -f1,2)"
    case "$version" in
        "$line".[0-9]*) [[ "${version#"$line".}" =~ ^[0-9]+$ ]] ||
            { echo "stamp_apps: $version is not $line.N" >&2; exit 1; } ;;
        *) echo "stamp_apps: $version is not of the committed line, $line" >&2; exit 1 ;;
    esac
fi
case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "stamp_apps: ${plists[0]}'s version, \"$version\", is not MAJOR.MINOR.BUILD" >&2; exit 1 ;;
esac

# convo_ci, built for this machine and run from the checkout (it stamps the
# current directory's tree).
cd "$ROOT"
bazel build //tools/convo_ci
convo_ci="$(bazel info execution_root)/$(bazel cquery --output=files //tools/convo_ci 2> /dev/null | head -1)"
[ -x "$convo_ci" ] || { echo "stamp_apps: no convo_ci at $convo_ci" >&2; exit 1; }
commit=()
[ -z "${GITHUB_SHA:-}" ] || commit=(--commit "$GITHUB_SHA")
"$convo_ci" stamp-version "$version" ${commit[@]+"${commit[@]}"}
[ -z "${GITHUB_OUTPUT:-}" ] || echo "version=$version" >> "$GITHUB_OUTPUT"
echo "stamp_apps: P2PRC is $version"
