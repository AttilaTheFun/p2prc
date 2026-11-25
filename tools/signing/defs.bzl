"""The Info.plist keys and entitlements only the distribution's builds carry.

Their values come from the build's environment (extension.bzl), never this
repository: Shireworks Kit's repository for reports, UpdateKit's app group
and the Applications bundle ids, and the shared GitHub sign-in reports are
filed with. Each key is written only
when its values are set; a build without them gets an empty plist and the
entitlements the app always has.
"""

load("@bazel_skylib//rules:write_file.bzl", "write_file")
load(
    "@convo_signing//:signing.bzl",
    "APPLICATIONS_BUNDLE_IDS",
    "APP_GROUP",
    "SHARED_CLIENT_ID",
    "SHARED_SERVICE",
    "SHIREWORKS_REPOSITORY",
    "TEAM_ID",
)

# Whether this build carries the shared sign-in: its client id, its keychain
# service, the app group its lock lives in, and the team its keychain group
# is prefixed with.
_SHARED = bool(SHARED_CLIENT_ID and SHARED_SERVICE and APP_GROUP and TEAM_ID)

def _string(key, value):
    return ["\t<key>%s</key>" % key, "\t<string>%s</string>" % value]

def _plist(lines):
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
    ] + lines + ["</dict>", "</plist>", ""]

def team_plist(name):
    """`<name>.plist`: UpdateKit's app group (on a Mac, with the Applications
    bundle ids) and the shared sign-in's keys, where the build has them;
    empty otherwise. Merged with the app's own Info.plist."""
    lines = []
    if SHIREWORKS_REPOSITORY:
        lines += _string("ShireworksRepository", SHIREWORKS_REPOSITORY)
    if _SHARED:
        lines += (
            _string("GitHubSharedClientID", SHARED_CLIENT_ID) +
            _string("GitHubSharedKeychainGroup", "%s.%s" % (TEAM_ID, SHARED_SERVICE)) +
            _string("GitHubSharedLockGroup", APP_GROUP) +
            _string("GitHubSharedKeychainService", SHARED_SERVICE)
        )
    if APP_GROUP:
        lines += _string("UpdateKitAppGroup", APP_GROUP)
        if APPLICATIONS_BUNDLE_IDS:
            lines += ["\t<key>UpdateKitApplicationsBundleIDs</key>", "\t<array>"]
            lines += ["\t\t<string>%s</string>" % i for i in APPLICATIONS_BUNDLE_IDS]
            lines += ["\t</array>"]
    write_file(name = name, out = name + ".plist", content = _plist(lines))

def team_entitlements(name, bundle_id):
    """`<name>.entitlements` for an iPhone app that signs as itself: its
    application identifier and keychain group, and where the build has them
    the shared sign-in's keychain group and UpdateKit's app group. The team
    prefix is `$(AppIdentifierPrefix)`, which the signing fills in from the
    provisioning profile."""
    groups = ["\t\t<string>$(AppIdentifierPrefix)%s</string>" % bundle_id]
    extra = []
    if _SHARED:
        groups.append("\t\t<string>$(AppIdentifierPrefix)%s</string>" % SHARED_SERVICE)
    if APP_GROUP:
        extra = ["\t<key>com.apple.security.application-groups</key>", "\t<array>", "\t\t<string>%s</string>" % APP_GROUP, "\t</array>"]
    lines = (
        _string("application-identifier", "$(AppIdentifierPrefix)" + bundle_id) +
        ["\t<key>keychain-access-groups</key>", "\t<array>"] + groups + ["\t</array>"] +
        extra
    )
    write_file(name = name, out = name + ".entitlements", content = _plist(lines))

def mac_entitlements(name, bundle_id):
    """`<name>.entitlements` for the Mac app CI signs (--config=ci_device):
    its identifier, its keychain groups (its own first, where an item goes
    when none is named, then the shared sign-in's, which Shireworks Kit files
    reports with) and UpdateKit's app group, named for the team. CI's signer
    makes them its Developer ID profile's, which grants them. Only a profile
    grants these, and macOS refuses to launch an app that claims them without
    one, so a build signed ad hoc carries none (the app's `select`). A build
    with no team gets an empty set, and the signer takes the profile's."""
    lines = []
    if TEAM_ID:
        groups = ["\t\t<string>%s.%s</string>" % (TEAM_ID, bundle_id)]
        if _SHARED:
            groups.append("\t\t<string>%s.%s</string>" % (TEAM_ID, SHARED_SERVICE))
        lines = (
            _string("com.apple.application-identifier", "%s.%s" % (TEAM_ID, bundle_id)) +
            ["\t<key>keychain-access-groups</key>", "\t<array>"] + groups + ["\t</array>"]
        )
        if APP_GROUP:
            lines += ["\t<key>com.apple.security.application-groups</key>", "\t<array>", "\t\t<string>%s</string>" % APP_GROUP, "\t</array>"]
    write_file(name = name, out = name + ".entitlements", content = _plist(lines))

def ci_placeholder_profile(name):
    """`<name>.mobileprovision`: the profile CI's ad hoc iPhone build
    (--config=ci_device) carries, so the machine that builds needs none. It
    allows what the app's entitlements ask for, with the team's prefix
    (P2PRC_TEAM_ID, from CI's settings); CI's signer replaces it with the bundle
    id's own development profile and makes the entitlements that profile's."""
    team = TEAM_ID or "PLACEHOLD0"
    lines = (
        _string("AppIDName", "P2PRC (CI placeholder)") +
        ["\t<key>ApplicationIdentifierPrefix</key>", "\t<array>", "\t\t<string>%s</string>" % team, "\t</array>"] +
        ["\t<key>CreationDate</key>", "\t<date>2026-01-01T00:00:00Z</date>"] +
        ["\t<key>DeveloperCertificates</key>", "\t<array>", "\t</array>"] +
        ["\t<key>Entitlements</key>", "\t<dict>"] +
        ["\t" + l for l in _string("application-identifier", "%s.*" % team)] +
        ["\t" + l for l in _string("com.apple.developer.team-identifier", team)] +
        (["\t\t<key>com.apple.security.application-groups</key>", "\t\t<array>", "\t\t\t<string>%s</string>" % APP_GROUP, "\t\t</array>"] if APP_GROUP else []) +
        ["\t\t<key>get-task-allow</key>", "\t\t<true/>"] +
        ["\t\t<key>keychain-access-groups</key>", "\t\t<array>", "\t\t\t<string>%s.*</string>" % team, "\t\t</array>"] +
        ["\t</dict>"] +
        ["\t<key>ExpirationDate</key>", "\t<date>2036-01-01T00:00:00Z</date>"] +
        _string("Name", "P2PRC CI placeholder") +
        ["\t<key>Platform</key>", "\t<array>", "\t\t<string>iOS</string>", "\t</array>"] +
        ["\t<key>ProvisionedDevices</key>", "\t<array>", "\t</array>"] +
        ["\t<key>TeamIdentifier</key>", "\t<array>", "\t\t<string>%s</string>" % team, "\t</array>"] +
        _string("TeamName", "CI placeholder") +
        ["\t<key>TimeToLive</key>", "\t<integer>3652</integer>"] +
        _string("UUID", "00000000-0000-4000-8000-00000000c0e1") +
        ["\t<key>Version</key>", "\t<integer>1</integer>"]
    )
    write_file(name = name, out = name + ".mobileprovision", content = _plist(lines))
