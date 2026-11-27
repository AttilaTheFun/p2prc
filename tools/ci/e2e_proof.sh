#!/bin/bash
# The proof, on a Mac with Xcode (the proof job, on GitHub's `xcode-27`
# runner): the end-to-end run (tools/e2e/run_pair.sh) on two simulators made
# for it, the status bar held still (AGENTS.md), relay only
# (CONVO_E2E_RELAY=1: the clients' peer link through the nodes' TURN alone,
# its candidate pair in the log): two web clients in Safari create
# identities, pair and message each other through the p2prc nodes, and one
# reopens the thread. Its log and screenshots (masked) are then written in
# Reviews' proof format 2 by `convo_ci proof`, which judges the run by what
# happened (both messages, the one after reopening, a relayed link on both
# ends, no trap, the run's end). Its logic is the Nimbus-era
# tools/ci/mac_build.sh's `e2e`, on the runner itself.
#
#   tools/ci/e2e_proof.sh <proof dir> [<run dir>]
#
# <run dir> (default: a temporary one) gets pair.log and the pictures,
# <platform>-<name>.png. The proof's version is PROOF_VERSION, else the
# committed line's (the iPhone's Info.plist), as the Playground's proof.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
proof="${1:?usage: tools/ci/e2e_proof.sh <proof dir> [<run dir>]}"
run="${2:-$(mktemp -d)}"
mkdir -p "$proof" "$run"
cd "$ROOT" || exit
# Every step under a time limit (perl's alarm: macOS has no timeout(1)), and
# said as it starts, so a step that hangs fails the proof with its name in
# the log, rather than holding the runner until the job's timeout (0.3.1's
# proof ran two hours and its log was lost).
limit() { perl -e 'alarm shift; exec @ARGV' "$@"; }
step() { echo "e2e_proof: $(date -u +%T) $*"; }
# The site the simulators open (run_pair.sh takes it from Bazel's output),
# and convo_ci, which writes the proof: 30 minutes at most.
step "building the web client and convo_ci"
limit 1800 bazel build //applications/p2prc_web:p2prc_web //tools/convo_ci || { step "the build failed or took over 30 minutes"; exit 1; }
convo_ci="$(bazel info execution_root)/$(bazel cquery --output=files //tools/convo_ci 2> /dev/null | head -1)"
# Two iPhones, the run's own: the iOS runtime that supports the most device
# types (a device-specific runtime supports one) and its first iPhone.
step "finding the iOS runtime"
read -r runtime device <<< "$(limit 120 xcrun simctl list runtimes -j | python3 -I -c 'import json, sys
r = max((x for x in json.load(sys.stdin)["runtimes"] if x["platform"] == "iOS" and x["isAvailable"]),
        key=lambda x: len(x.get("supportedDeviceTypes", [])))
print(r["identifier"], next(d["identifier"] for d in r["supportedDeviceTypes"] if d["productFamily"] == "iPhone"))')" || exit
echo "e2e_proof: two $device on $runtime"
step "making the simulators"
a="$(limit 180 xcrun simctl create p2prc-e2e-a "$device" "$runtime")" || exit
b="$(limit 180 xcrun simctl create p2prc-e2e-b "$device" "$runtime")" || exit
echo "e2e_proof: made $a and $b"
# run_pair.sh erases and boots them; the status bar is set once each is up.
(
    for sim in "$a" "$b"; do
        for _ in $(seq 1 120); do limit 20 xcrun simctl bootstatus "$sim" > /dev/null 2>&1 && break; sleep 2; done
        limit 60 xcrun simctl status_bar "$sim" override --time 9:41 --dataNetwork wifi --wifiMode active --wifiBars 3 \
            --cellularMode active --cellularBars 4 --operatorName "" --batteryState charged --batteryLevel 100
    done
) &
status_bar=$!
# The run's log as it's written, in the job's log, so a run that stalls shows
# where (run_pair.sh starts it afresh: -F follows the new file).
tail -n 0 -F tools/e2e/out/pair.log 2> /dev/null | sed -u 's/^/pair: /' &
progress=$!
# The run: 40 minutes at most (a passing one takes under 10).
CONVO_E2E_RELAY=1 CONVO_E2E_SIM_A="$a" CONVO_E2E_SIM_B="$b" limit 2400 bash tools/e2e/run_pair.sh
status=$?
[ "$status" -ne 142 ] || { echo "e2e_proof: the run took more than 40 minutes and was stopped"; pkill -f cmdserver.py; limit 60 xcrun simctl shutdown "$a"; limit 60 xcrun simctl shutdown "$b"; }
# The status bar's loop and the log's tail stopped, not waited for: on
# simulators that never came up the loop could run for most of an hour (0.3.1's
# proof, after its run was stopped, waited on it until the job was cancelled).
kill "$status_bar" "$progress" 2> /dev/null
pkill -f "tail -n 0 -F tools/e2e/out/pair.log" 2> /dev/null
wait 2> /dev/null
cp tools/e2e/out/pair.log "$run/pair.log" 2> /dev/null || echo "e2e_proof: the run wrote no log" > "$run/pair.log"
# Masked by run_pair.sh (--mask=black): a fresh simulator draws the Dynamic
# Island and another doesn't.
[ ! -f tools/e2e/out/web_thread.png ] || cp tools/e2e/out/web_thread.png "$run/ios-web-thread.png"
[ ! -f tools/e2e/out/web_composer_b.png ] || cp tools/e2e/out/web_composer_b.png "$run/ios-web-composer.png"
limit 120 xcrun simctl delete "$a" "$b"
cat "$run/pair.log"
version="${PROOF_VERSION:-$(awk '/<key>CFBundleShortVersionString<\/key>/ { found = 1 }
    found && match($0, /<string>[^<]*<\/string>/) { print substr($0, RSTART + 8, RLENGTH - 17); exit }' applications/p2prc_ios/Info.plist)}"
# The proof whatever came of the run (convo_ci fails it when the run failed).
"$convo_ci" proof --pictures "$run" --tests-log "$run/pair.log" --out "$proof" --version "$version" || status=1
exit "$status"
