#!/bin/bash
# The web client a release carries, as <out>.zip: P2PRC's static site
# (//applications/p2prc_web), built with the given flags, zipped with its
# index.html at the top. pages.yml deploys it to p2prc.org when the release
# is published.
#
#   tools/ci/package_web.sh <out.zip> [<bazel flags>…]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:?usage: tools/ci/package_web.sh <out.zip> [<bazel flags>…]}"
shift
mkdir -p "$(dirname "$out")"
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
cd "$ROOT"
bazel build "$@" //applications/p2prc_web:p2prc_web
site="$(bazel info "$@" execution_root)/$(bazel cquery "$@" --output=files //applications/p2prc_web:p2prc_web 2> /dev/null | head -1)"
[ -f "$site/index.html" ] || { echo "package_web: no index.html in $site" >&2; exit 1; }
rm -f "$out"
(cd "$site" && python3 -I -m zipfile -c "$out" .)
echo "package_web: $(basename "$out"), $(du -h "$out" | cut -f1)"
