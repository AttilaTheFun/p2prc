"""The Info.plist keys and entitlements only the team's own builds carry.

With a team (CONVO_TEAM_ID, extension.bzl), an app's build carries the
team's shared GitHub sign-in (Shireworks' docs/shared-sign-in.md) and
UpdateKit's app group, shared with Shireworks; without one, an empty plist
and the entitlements the app always has.
"""

load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@convo_signing//:signing.bzl", "TEAM_ID")

# Shared with Shireworks, and every app of the team's with UpdateKit or the
# shared sign-in (it replaced group.com.LoganShire.Applications, 2026-11-23).
APP_GROUP = "group.com.LoganShire.Shireworks"

# The "shireworks" OAuth App: a public client id, never a secret.
_SHARED_CLIENT_ID = "Ov23lirA462eCBvV8YgP"
_SHARED_SERVICE = "com.LoganShire.github"

def _string(key, value):
    return ["\t<key>%s</key>" % key, "\t<string>%s</string>" % value]

def _plist(lines):
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
    ] + lines + ["</dict>", "</plist>", ""]

def team_plist(name, applications_bundle_ids = []):
    """`<name>.plist`: the shared sign-in's keys and UpdateKit's app group in
    the team's own builds (on a Mac, with Applications' bundle ids); empty
    otherwise. Merged with the app's own Info.plist."""
    lines = []
    if TEAM_ID:
        lines = (
            _string("GitHubSharedClientID", _SHARED_CLIENT_ID) +
            _string("GitHubSharedKeychainGroup", "%s.%s" % (TEAM_ID, _SHARED_SERVICE)) +
            _string("GitHubSharedLockGroup", APP_GROUP) +
            _string("GitHubSharedKeychainService", _SHARED_SERVICE) +
            _string("UpdateKitAppGroup", APP_GROUP)
        )
        if applications_bundle_ids:
            lines += ["\t<key>UpdateKitApplicationsBundleIDs</key>", "\t<array>"]
            lines += ["\t\t<string>%s</string>" % i for i in applications_bundle_ids]
            lines += ["\t</array>"]
    write_file(name = name, out = name + ".plist", content = _plist(lines))

def team_entitlements(name, bundle_id):
    """`<name>.entitlements` for an iPhone app that signs as itself: its
    application identifier and keychain group, and in the team's own builds
    the shared sign-in's keychain group and UpdateKit's app group. The team
    prefix is `$(AppIdentifierPrefix)`, which the signing fills in from the
    provisioning profile."""
    groups = ["\t\t<string>$(AppIdentifierPrefix)%s</string>" % bundle_id]
    extra = []
    if TEAM_ID:
        groups.append("\t\t<string>$(AppIdentifierPrefix)%s</string>" % _SHARED_SERVICE)
        extra = ["\t<key>com.apple.security.application-groups</key>", "\t<array>", "\t\t<string>%s</string>" % APP_GROUP, "\t</array>"]
    lines = (
        _string("application-identifier", "$(AppIdentifierPrefix)" + bundle_id) +
        ["\t<key>keychain-access-groups</key>", "\t<array>"] + groups + ["\t</array>"] +
        extra
    )
    write_file(name = name, out = name + ".entitlements", content = _plist(lines))

def ci_placeholder_profile(name):
    """`<name>.mobileprovision`: the profile CI's ad hoc iPhone build
    (--config=ci_device) carries, so the machine that builds needs none. It
    allows what the app's entitlements ask for, with the team's prefix
    (CONVO_TEAM_ID, from CI's secret); CI's signer replaces it with the bundle
    id's own development profile and makes the entitlements that profile's."""
    team = TEAM_ID or "PLACEHOLD0"
    lines = (
        _string("AppIDName", "Convo (CI placeholder)") +
        ["\t<key>ApplicationIdentifierPrefix</key>", "\t<array>", "\t\t<string>%s</string>" % team, "\t</array>"] +
        ["\t<key>CreationDate</key>", "\t<date>2026-01-01T00:00:00Z</date>"] +
        ["\t<key>DeveloperCertificates</key>", "\t<array>", "\t</array>"] +
        ["\t<key>Entitlements</key>", "\t<dict>"] +
        ["\t" + l for l in _string("application-identifier", "%s.*" % team)] +
        ["\t" + l for l in _string("com.apple.developer.team-identifier", team)] +
        ["\t\t<key>com.apple.security.application-groups</key>", "\t\t<array>", "\t\t\t<string>%s</string>" % APP_GROUP, "\t\t</array>"] +
        ["\t\t<key>get-task-allow</key>", "\t\t<true/>"] +
        ["\t\t<key>keychain-access-groups</key>", "\t\t<array>", "\t\t\t<string>%s.*</string>" % team, "\t\t</array>"] +
        ["\t</dict>"] +
        ["\t<key>ExpirationDate</key>", "\t<date>2036-01-01T00:00:00Z</date>"] +
        _string("Name", "Convo CI placeholder") +
        ["\t<key>Platform</key>", "\t<array>", "\t\t<string>iOS</string>", "\t</array>"] +
        ["\t<key>ProvisionedDevices</key>", "\t<array>", "\t</array>"] +
        ["\t<key>TeamIdentifier</key>", "\t<array>", "\t\t<string>%s</string>" % team, "\t</array>"] +
        _string("TeamName", "CI placeholder") +
        ["\t<key>TimeToLive</key>", "\t<integer>3652</integer>"] +
        _string("UUID", "00000000-0000-4000-8000-00000000c0e1") +
        ["\t<key>Version</key>", "\t<integer>1</integer>"]
    )
    write_file(name = name, out = name + ".mobileprovision", content = _plist(lines))
