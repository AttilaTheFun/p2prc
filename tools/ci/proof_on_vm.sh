#!/bin/bash
# The proof (tools/ci/e2e_proof.sh) on a macOS VM leased from Nimbus, for
# the proof job on a Nimbus runner (a Linux container: the simulators need
# a Mac). The owner, 2026-11-27: no paid GitHub runners. Nimbus' recipe, as
# its own CI's (tools/ci/mac_vm.sh): a key of the job's own, the VM leased
# for an hour (xcode_27_2: Xcode 27.2 and its iOS simulators, Homebrew's
# bazelisk) and renewed every 10 minutes while the proof runs, the
# committed tree copied in, the proof run there, its files copied out, the
# VM released however this ends (a job killed outright leaves it an hour at
# most). Bazel in the VM reads Nimbus' cache, as every lease's does. No
# secret goes to the VM: it isn't network-locked yet, and the proof needs
# none.
#
#   tools/ci/proof_on_vm.sh <proof dir> <run dir>
#
# Out, as e2e_proof.sh leaves them on a Mac: the proof in <proof dir>, the
# run's own files in <run dir> and tools/e2e/out (the job's artifacts).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
proof="${1:?usage: tools/ci/proof_on_vm.sh <proof dir> <run dir>}"
run="${2:?usage: tools/ci/proof_on_vm.sh <proof dir> <run dir>}"
mkdir -p "$proof" "$run" "$ROOT/tools/e2e/out"
nimbus="$(command -v nimbus || echo /opt/nimbus/bin/nimbus)"
step() { echo "proof_on_vm: $(date -u +%T) $*"; }

work="$(mktemp -d)"
chmod 700 "$work"
id="" renewer=""
cleanup() {
    [ -z "$renewer" ] || kill "$renewer" 2> /dev/null || true
    [ -z "$id" ] || "$nimbus" job release "$id" || echo "proof_on_vm: lease $id was not released" >&2
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh-keygen -q -t ed25519 -N '' -C "p2prc proof $GITHUB_RUN_ID" -f "$work/key"
step "leasing a macOS VM (it waits for room)"
"$nimbus" job lease macos --config=xcode_27_2 --minutes=60 --key="$work/key.pub" \
    --label="${GITHUB_REPOSITORY:-p2prc} proof" > "$work/lease"
# shellcheck disable=SC1091
. "$work/lease"
id="${NIMBUS_ID:?the lease named no NIMBUS_ID}"
step "leased $id"
(while sleep 600; do "$nimbus" job renew "$id" --minutes=60 > /dev/null || true; done) &
renewer=$!

vm() {
    ssh -p "$NIMBUS_SSH_PORT" -i "$work/key" -o IdentitiesOnly=yes -o BatchMode=yes -o ServerAliveInterval=30 \
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$work/known_hosts" \
        "$NIMBUS_SSH_USER@$NIMBUS_HOST" "$@"
}
for _ in $(seq 60); do vm true 2> /dev/null && break; sleep 5; done
vm true

step "copying the tree in"
git -C "$ROOT" archive HEAD | vm 'rm -rf ~/w && mkdir ~/w && tar -xf - -C ~/w'

# zsh -lc: Homebrew's bazelisk on the PATH. The proof's own limits stop a
# step that hangs (e2e_proof.sh).
step "the proof, in the VM"
status=0
vm "cd ~/w && PROOF_VERSION='${PROOF_VERSION:-}' zsh -lc 'tools/ci/e2e_proof.sh ~/proof ~/e2e'" || status=$?

step "copying the proof out"
vm 'tar -cf - -C ~ proof e2e' | tar -xf - -C "$work" || true
vm 'tar -cf - -C ~/w/tools/e2e/out --exclude=./site .' | tar -xf - -C "$ROOT/tools/e2e/out" || true
cp -R "$work/proof/." "$proof/" 2> /dev/null || true
cp -R "$work/e2e/." "$run/" 2> /dev/null || true
[ -n "$(ls -A "$proof")" ] || { echo "proof_on_vm: the VM wrote no proof" >&2; [ "$status" -ne 0 ] || status=1; }
exit "$status"
