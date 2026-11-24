#!/bin/bash
# Installs P2PRC's optimized Android build on a device, compiles it ahead of
# time, reads the version back and stops. It never launches the app: a
# person's phone is theirs (test the UI in the Android emulator instead).
#
#   tools/android/install.sh [adb serial]     # default: the only device attached
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
bazel build -c opt //applications/p2prc_android >/dev/null
bazel build @@isomer++android_tools+android_platform_tools//:adb >/dev/null
ADB="$(bazel info output_base)/external/isomer++android_tools+android_platform_tools/adb"
APK="$ROOT/bazel-out/darwin_arm64-opt/bin/applications/p2prc_android/p2prc_android_apk.apk"
SERIAL=(); [ $# -ge 1 ] && SERIAL=(-s "$1")
"$ADB" "${SERIAL[@]}" install -r "$APK"
"$ADB" "${SERIAL[@]}" shell cmd package compile -m speed -f com.loganshire.p2prc
"$ADB" "${SERIAL[@]}" shell dumpsys package com.loganshire.p2prc | grep -E 'versionName|versionCode' | sed 's/^ */installed /'
