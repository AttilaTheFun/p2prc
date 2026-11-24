#!/bin/bash
# The protocol's tests (protocol/, a SwiftPM package: swift Testing) on
# Linux, in CI's Swift image, as protocol/Dockerfile builds the node there:
# a copy of the package with Package.swift's apple-only blocks taken out
# (Communication, Apple's WebRTC) and their two targets with them
# (ConvoWebRTC, ConvoCalling). In a copy: Bazel takes the checkout's
# protocol/ as a local package, as it is.
#
#   tools/ci/protocol_test.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/protocol"
(cd "$ROOT/protocol" && tar --exclude=./.build -cf - .) | tar -xf - -C "$work/protocol"
cd "$work/protocol"
sed -i '/apple-only-begin/,/apple-only-end/d' Package.swift
rm -rf Sources/ConvoWebRTC Sources/ConvoCalling
swift --version
swift test --parallel
