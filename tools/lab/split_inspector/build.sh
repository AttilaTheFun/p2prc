#!/bin/sh
# Builds the control app with swiftc alone (no Bazel, no isomer) into
# an .app bundle and launches it: tools/lab/split_inspector/build.sh
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/out"}
app="$out/SplitInspectorLab.app"
mkdir -p "$app/Contents/MacOS"
swiftc -O -parse-as-library -target arm64-apple-macos14.0 \
    -o "$app/Contents/MacOS/SplitInspectorLab" "$here/SplitInspectorLab.swift"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>SplitInspectorLab</string>
<key>CFBundleIdentifier</key><string>com.LoganShire.SplitInspectorLab</string>
<key>CFBundleName</key><string>SplitInspectorLab</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
</dict></plist>
PLIST
echo "built $app"
