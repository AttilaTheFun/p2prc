#!/bin/bash
# CI's build of every platform, on GitHub's own runners, each platform where
# its tools run (ISOMER_PLATFORMS), as the Playground's and isomer's
# tools/ci/container_build.sh:
# - web and android: together, in one job and one Bazel output base, on
#   GitHub's x86_64 Ubuntu runner, in Swift's own image with the job's tools
#   added (tools/ci/job_tools.sh): Google's Android SDK and NDK tools, and
#   the hermetic JDK, are x86_64 programs, which GitHub's arm64 runners have
#   nothing to run (no Rosetta);
# - apple: on GitHub's `xcode-27` Macs (a standard runner, free for a public
#   repository), with their own Xcode: Apple's SDKs may not be
#   redistributed, so CI never takes the SDK archive the Apple targets take
#   on Linux (rules_applecross, .bazelrc's apple_on_linux, for a builder
#   that has it).
# Bazel's settings (its caches in GitHub's cache, BuildBuddy's) are
# tools/ci/ci_bazel.sh's, written before this runs (the workflow's
# .github/actions/bazel_cache).
#
#   tools/ci/container_build.sh [<bazel build args>…]   # default: every
#                                     # app and CI's tools built (verify's)
#   tools/ci/container_build.sh all   # the same: main's populate (the one
#                                     # writer of GitHub's cache)
#   tools/ci/container_build.sh pr    # the same: a pull request's
#   tools/ci/container_build.sh package <dir> <bazel build args>…
#                                     # the build, then the targets' packages
#                                     # (.ipa, a Mac app's .zip, the .apk)
#                                     # copied to <dir>, in this checkout, for
#                                     # CI to sign and publish
#
#   ISOMER_PLATFORMS  which of apple, android and web (default: a Mac's
#                    apple; a Linux machine's web and android)
#   ISOMER_EXECUTION_LOGS  a folder for Bazel's execution logs (compact),
#                    to compare two runs' action keys when the cache misses
#
# P2PRC's Bazel graph has no tests without a GUI: the protocol's tests are
# SwiftPM's (tools/ci/protocol_test.sh, a step of the Linux jobs), and the
# end-to-end run (tools/e2e/run_pair.sh) drives two simulators, in the
# proof (tools/ci/e2e_proof.sh).
#
# package (the publishing jobs'): the targets' files, found by cquery with
# the build's own flags, copied out of the execution root into the checkout.
# Flags as --name=value (--compilation_mode=opt, not -c opt): every argument
# that doesn't start with "-" is taken for a target. An Android app's files
# are its .apk (signed by its build with a debug key, which
# build_tools' `sign android` replaces with the release key), its unsigned one
# and its deploy jar; only the first is copied.
set -euo pipefail
# Bash 3.2 too: GitHub's Macs have no other (no mapfile, no ${!name}).
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [ "$(uname -s)" = Darwin ]; then
    default=apple
else
    default="web android"
fi
platforms=" ${ISOMER_PLATFORMS:-$default} "
for platform in $platforms; do
    case "$platform" in
        apple | android | web) ;;
        *) echo "container_build.sh: no platform $platform (ISOMER_PLATFORMS: apple, android, web)" >&2; exit 2 ;;
    esac
    if [ "$(uname -s)" = Darwin ] && [ "$platform" != apple ]; then
        echo "container_build.sh: a Mac builds the Apple platforms alone here; $platform is built on Linux" >&2; exit 2
    fi
    if [ "$(uname -s)" != Darwin ] && [ "$platform" = apple ]; then
        echo "container_build.sh: the Apple platforms are built on a Mac, with its Xcode" >&2; exit 2
    fi
done
has() { [[ $platforms == *" $1 "* ]]; }
echo "container_build.sh: the platforms here:$platforms"

mode=build
out=""
apps=()
if [ "${1:-}" = package ]; then
    [ $# -ge 3 ] || { echo "usage: tools/ci/container_build.sh package <dir> <bazel build args…>" >&2; exit 1; }
    mkdir -p "$2"
    out="$(cd "$2" && pwd)"
    case "$out/" in
        "$ROOT"/*) ;;
        *) echo "container_build.sh: package's folder must be in this checkout ($ROOT)" >&2; exit 1 ;;
    esac
    rm -f "$out"/*
    chmod 775 "$out"
    mode=package
    shift 2
elif [ $# -eq 0 ] || [ "$*" = all ] || [ "$*" = pr ]; then
    mode=checks
    [ $# -eq 0 ] || mode="$*"
    # Each platform's app, and CI's own tool (convo_ci, which the publishing
    # jobs run on a Mac and on Linux). The iPhone's for the simulator: a
    # device build needs a provisioning profile, which only the publishing
    # jobs make up (--config=ci_device).
    if has apple; then
        apps+=(//applications/p2prc_ios:p2prc_ios //applications/p2prc_macos:p2prc_macos //tools/convo_ci)
    fi
    has web && apps+=(//applications/p2prc_web:p2prc_web //tools/convo_ci)
    # With Android's, the release jobs' tools (build_tools' sign and what it
    # runs), built where the release jobs build them: a pull request that
    # breaks them fails here, not at a release.
    has android && apps+=(//applications/p2prc_android:p2prc_android_apk //tools/ci_tools:all)
    set -- --ios_multi_cpus=sim_arm64 ${apps[@]+"${apps[@]}"}
fi

# The build, then (package) the packages copied out.
steps='
root=$1 mode=$2 out=$3 platforms=$4; shift 4
cd "$root"
# An execution log an invocation, named for what it builds (ISOMER_EXECUTION_LOGS).
logs="${ISOMER_EXECUTION_LOGS:-}"
[ -z "$logs" ] || mkdir -p "$logs"
log_of() { [ -z "$logs" ] || printf -- "--execution_log_compact_file=%s/%s.zst" "$logs" "$1"; }
built=0
targets=0
for argument in "$@"; do case "$argument" in -*) ;; *) targets=1 ;; esac; done
if [ $targets -eq 1 ]; then
    bazel build --keep_going $(log_of build) "$@"
    built=$?
fi
if [ "$mode" = package ]; then
    [ $built -eq 0 ] || exit $built
    options=()
    query=""
    # cquery takes one expression: the targets as a union of them.
    for argument in "$@"; do
        case "$argument" in -*) options+=("$argument") ;; *) query="${query:+$query + }$argument" ;; esac
    done
    exec_root="$(bazel info "${options[@]}" execution_root)" || exit
    files="$(bazel cquery "${options[@]}" "$query" --output=files 2> /dev/null)" || exit
    for file in $files; do
        case "$file" in
            *_unsigned.apk) ;;
            *.ipa | *.zip | *.apk) cp "$exec_root/$file" "$out/" || exit ;;
        esac
    done
    ls -l "$out"
    exit 0
fi
df -h / /mnt 2> /dev/null || df -h /
exit $built
'

cd "$ROOT"
exec bash -c "$steps" container_build "$ROOT" "$mode" "$out" "$platforms" "$@"
