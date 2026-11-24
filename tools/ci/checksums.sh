#!/bin/bash
# A release's SHA256SUMS, written into <assets>: every file there (but
# SHA256SUMS and sign's builds.lines), and those in each <other> folder (a
# release's assets already attached, such as its web client), by name.
#
#   tools/ci/checksums.sh <assets> [<other>…]
set -euo pipefail
assets="${1:?usage: tools/ci/checksums.sh <assets> [<other>…]}"
sums="$(mktemp)"
trap 'rm -f "$sums"' EXIT
for folder in "$@"; do
    (cd "$folder" && find . -maxdepth 1 -type f ! -name 'builds.lines*' ! -name SHA256SUMS -printf '%P\n' |
        sort | xargs -r sha256sum) >> "$sums"
done
sort -k2 "$sums" > "$assets/SHA256SUMS"
cat "$assets/SHA256SUMS"
