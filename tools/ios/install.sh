#!/bin/bash
# Build, sign, and install Convo on the attached iPhone.
#
# Bazel signs with whatever it can infer, which is not the team profile Xcode
# manages, so the app is re-signed here against the profile Xcode already
# fetched for com.LoganShire.P2PRC. That profile is the one thing this cannot
# create: if it is missing or expired, open the throwaway Xcode project once
# with -allowProvisioningUpdates and Xcode will renew it.
set -euo pipefail

BUNDLE_ID="com.LoganShire.P2PRC"
# The signing team: P2PRC_TEAM, else the team of the profile found for the
# app (its own, not a wildcard). No team id is written in the repository.
TEAM="${P2PRC_TEAM:-}"
# The signing certificate is the one the chosen profile lists (read below):
# signing with any other installs cleanly right up until the device refuses it.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${TMPDIR:-/tmp}/convo-install"
mkdir -p "$WORK"

# The profile has to match the bundle id AND actually list the target device
# — a free-team profile covers only devices Xcode has registered, so "first
# profile for this bundle id" installs onto one phone and 0xe8008012s on the
# next. When the device is known, we prefer the newest profile that contains
# its UDID.
profile() {
  local dir="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
  local udid="$1"
  local f id best="" best_mtime=0 mtime
  for f in "$dir"/*.mobileprovision; do
    [[ -f "$f" ]] || continue
    local xml; xml=$(security cms -D -i "$f" 2>/dev/null) || continue
    id=$(printf '%s' "$xml" | plutil -extract Entitlements.application-identifier raw - 2>/dev/null || true)
    # This app's own profile on the team, or the team's wildcard one; an
    # exact profile wins over the wildcard (its mtime is lifted below).
    if [[ -n "$TEAM" ]]; then
      [[ "$id" == "$TEAM.$BUNDLE_ID" || "$id" == "$TEAM.*" ]] || continue
    else
      [[ "$id" == *".$BUNDLE_ID" ]] || continue
    fi
    if [[ -n "$udid" ]]; then
      printf '%s' "$xml" | grep -q "$udid" || continue
    fi
    mtime=$(stat -f %m "$f")
    [[ "$id" == *".$BUNDLE_ID" ]] && mtime=$(( mtime + 1000000000 ))
    if (( mtime > best_mtime )); then best="$f"; best_mtime=$mtime; fi
  done
  [[ -n "$best" ]] && { echo "$best"; return 0; }
  return 1
}

# Resolve the target device first: its name → CoreDevice id (for install) and
# hardware UDID (for picking a profile that actually covers it).
TARGET="${1:?usage: tools/ios/install.sh <the device's name, as Finder shows it>}"
# devicectl reports a reachable phone as "available (paired)" over wifi and
# "connected" when a tunnel is up; both can take an install.
# The table no longer prints the CoreDevice identifier; the JSON does.
DEVICE=$(xcrun devicectl list devices --json-output "$WORK/devices.json" >/dev/null 2>&1 && python3 - "$TARGET" "$WORK/devices.json" <<'PY'
import json, sys
name, path = sys.argv[1], sys.argv[2]
for d in json.load(open(path))["result"]["devices"]:
    if d["deviceProperties"].get("name") == name and d["connectionProperties"].get("pairingState") == "paired" \
       and d["connectionProperties"].get("tunnelState") != "unavailable":
        print(d["identifier"]); break
PY
)
[[ -n "$DEVICE" ]] || { echo "no available device named $TARGET" >&2; exit 1; }
UDID=$(xcrun devicectl device info details --device "$DEVICE" 2>/dev/null |
  grep -i "UDID:" | grep -oE '[0-9A-F]{8}-[0-9A-F]{16}' | head -1)

PROFILE=$(profile "$UDID") || {
  echo "no provisioning profile for $BUNDLE_ID covering $TARGET." >&2
  echo "Register the device: open a throwaway Xcode project for $BUNDLE_ID" >&2
  echo "with this phone attached and build with -allowProvisioningUpdates." >&2
  exit 1
}
echo "using profile $(basename "$PROFILE")"
[[ -n "$TEAM" ]] || TEAM=$(security cms -D -i "$PROFILE" 2>/dev/null | plutil -extract TeamIdentifier.0 raw - 2>/dev/null)
[[ -n "$TEAM" ]] || { echo "the profile names no team; set P2PRC_TEAM" >&2; exit 1; }
# Sign with the exact certificate the profile lists, by its SHA-1: a revoked
# certificate can stay in the keychain under the same name as its
# replacement, and codesign refuses a name that matches both.
VALID=$(security find-identity -v -p codesigning | grep -v REVOKED | awk '{print $2}')
IDENTITY=""
for i in 0 1 2 3 4 5 6 7 8 9; do
  fp=$(security cms -D -i "$PROFILE" 2>/dev/null | plutil -extract DeveloperCertificates.$i raw - 2>/dev/null |
    base64 -D | openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null | sed 's/.*=//; s/://g') || break
  [[ -n "$fp" ]] || break
  if printf '%s\n' "$VALID" | grep -qx "$fp"; then IDENTITY="$fp"; break; fi
done
[[ -n "$IDENTITY" ]] || { echo "no valid signing identity in this keychain for $(basename "$PROFILE")" >&2; exit 1; }
echo "signing with certificate $IDENTITY"

# An expired profile installs fine and then refuses to launch, which reads as
# an app bug rather than a signing one. Fail here instead.
EXPIRY=$(security cms -D -i "$PROFILE" | plutil -extract ExpirationDate raw -)
if [[ "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$EXPIRY" ]]; then
  echo "profile expired $EXPIRY — reopen the Xcode project to renew" >&2
  exit 1
fi

# --ios_multi_cpus=arm64 is mandatory: without it, on an Apple-Silicon Mac
# the default cpu is the *simulator* (sim_arm64), and a simulator binary
# installed on a device crashes at launch — dyld rejects the first system
# dylib it loads as "wrong platform to load into process". Device arm64 is
# the only build that runs on a phone.
# CONVO_BAZEL_FLAGS: extra flags when the default toolchain can't build —
# e.g. on a beta macOS where only a beta Xcode can launch, pass
# --xcode_version=… --repo_env=DEVELOPER_DIR=… here so this build matches
# the one the caller already made and stays a cache hit.
(cd "$ROOT" && bazel build //applications/p2prc_ios:p2prc_ios --ios_multi_cpus=arm64 ${CONVO_BAZEL_FLAGS:-})

rm -rf "$WORK" && mkdir -p "$WORK"
unzip -q "$ROOT/bazel-bin/applications/p2prc_ios/p2prc_ios.ipa" -d "$WORK"
APP=$(echo "$WORK"/Payload/*.app)

cp "$PROFILE" "$APP/embedded.mobileprovision"
security cms -D -i "$PROFILE" | plutil -extract Entitlements xml1 -o "$WORK/ent.plist" -
# A wildcard profile grants "TEAM.*"; the app is signed as itself.
plutil -replace application-identifier -string "$TEAM.$BUNDLE_ID" "$WORK/ent.plist"
if plutil -extract keychain-access-groups xml1 -o /dev/null "$WORK/ent.plist" 2>/dev/null; then
  plutil -replace keychain-access-groups -json "[\"$TEAM.$BUNDLE_ID\"]" "$WORK/ent.plist"
fi

# Sign inside out: nested code must be valid before the bundle seals over it.
find "$APP" -name '*.framework' -o -name '*.dylib' | while read -r nested; do
  codesign --force --sign "$IDENTITY" --timestamp=none "$nested"
done
codesign --force --sign "$IDENTITY" --entitlements "$WORK/ent.plist" \
  --timestamp=none --generate-entitlement-der "$APP"

echo "installing to $TARGET ($DEVICE)"

xcrun devicectl device install app --device "$DEVICE" "$APP" | tail -3
# Install, read the version back, stop. A person's phone is theirs: the app is
# never launched or driven on it unless they ask (test in the iOS Simulator
# instead).
xcrun devicectl device info apps --device "$DEVICE" --json-output "$WORK/apps.json" >/dev/null 2>&1
python3 - "$BUNDLE_ID" "$WORK/apps.json" <<'PY2'
import json, sys
bundle, path = sys.argv[1], sys.argv[2]
for app in json.load(open(path))["result"]["apps"]:
    if app.get("bundleIdentifier") == bundle:
        print(f"installed {bundle} {app.get('version')} ({app.get('bundleVersion')})")
        break
else:
    print(f"{bundle} not found on the device after install", file=sys.stderr)
    sys.exit(1)
PY2
