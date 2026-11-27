#!/bin/bash
# The Apple targets' downloads on Nimbus (its CI runners and leased
# containers): MODULE.bazel's placeholders for Xcode 27.2's SDK archive
# (apple-sdks.invalid) and rules_applecross's ported tools
# (ported-tools.invalid) rewritten to Nimbus' files, by SHA-256, read with
# the cache's token in ~/.netrc. Apple's SDKs may not be redistributed:
# Nimbus serves them to its own machines alone, and no host is named in the
# repository. As Monitor's tools/ci/shireworks_files.sh.
#
#   tools/ci/nimbus_files.sh <downloader.cfg>   # the rewrites, appended
#
#   NIMBUS_FILES_HOST  the host Nimbus' files are reached at (default: the
#                      remote cache's, which Nimbus writes in ~/.bazelrc)
set -euo pipefail

# Xcode 27.2's SDK archive (rules_applecross' //tools:package_sdks).
SDK_SHA256="b1583e60f9fd35881b5a948ce71627079877f1ced7ea231e14d3c342dd389668"

out="${1:?usage: tools/ci/nimbus_files.sh <downloader.cfg>}"
host="${NIMBUS_FILES_HOST:-}"
if [ -z "$host" ]; then
    host="$(grep -ho -- '--remote_cache=[^ ]*' "$HOME/.bazelrc" 2> /dev/null | head -1 | sed 's/^--remote_cache=//')"
fi
host="${host#*://}"
host="${host%%[/?]*}"
[ -n "$host" ] || { echo "nimbus_files.sh: no Nimbus host: no --remote_cache in ~/.bazelrc (set NIMBUS_FILES_HOST)" >&2; exit 1; }
# The cache's port when the host names none.
case "$host" in *:*) ;; *) host="$host:7490" ;; esac
cat >> "$out" << EOF
rewrite apple-sdks\.invalid/.* http://$host/files/sha256/$SDK_SHA256
rewrite ported-tools\.invalid/sha256/(.*) http://$host/files/sha256/\$1
EOF
echo "nimbus_files.sh: the SDK and the ported tools from Nimbus' files ($host)"
