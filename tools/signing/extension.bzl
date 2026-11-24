"""The builder's own signing values, from the machine and the build's
environment, never the repository.

`@convo_signing//:signing.bzl` defines:

- IOS_PROFILE: the name of the newest unexpired iOS development profile on
  this Mac for com.LoganShire.P2PRC itself, of P2PRC_TEAM_ID's team when
  that's set (not a wildcard: iOS refuses an app signed as `<team>.*`), from
  Xcode's and MobileDevice's profile folders, or "" when there is none (on
  Linux, say);
- TEAM_ID: the Apple team that signs the builds: P2PRC_TEAM_ID if it's set,
  else that profile's team, else "";
- APP_GROUP, APPLICATIONS_BUNDLE_IDS: what the apps tell UpdateKit (the
  distributor's app group and, on a Mac, its bundle ids, comma-separated in
  P2PRC_APPLICATIONS_BUNDLE_IDS);
- SHARED_CLIENT_ID, SHARED_SERVICE: the shared GitHub sign-in ShakeKit
  reports bugs with (its OAuth App's client id, and the keychain service its
  token is kept under).

None of them is named in this public repository: CI's distribution builds
set them (`--repo_env`) from the repository's secrets, and a builder sets
their own in a `.bazelrc.user` at the root (not checked in):

    common --repo_env=P2PRC_TEAM_ID=<team id>

A build without them carries neither UpdateKit's settings nor the shared
sign-in (ShakeKit then does nothing), and asks for no app group.
"""

BUNDLE_ID = "com.LoganShire.P2PRC"

_FOLDERS = [
    "Library/Developer/Xcode/UserData/Provisioning Profiles",
    "Library/MobileDevice/Provisioning Profiles",
]

def _value(rctx, plist, key):
    result = rctx.execute(["/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist])
    return result.stdout.strip() if result.return_code == 0 else ""

def _ios_profile(rctx, want_team):
    """(name, team) of the newest unexpired development profile for BUNDLE_ID,
    of `want_team` when it's set."""
    home = rctx.getenv("HOME", "")
    if rctx.os.name != "mac os x" or not home:
        return ("", "")
    best = ("", "", "")  # (expiration, name, team)
    for folder in _FOLDERS:
        path = rctx.path("%s/%s" % (home, folder))
        if not path.exists:
            continue
        for profile in path.readdir():
            if not profile.basename.endswith(".mobileprovision"):
                continue
            plist = "profile-%s.plist" % profile.basename
            if rctx.execute(["/usr/bin/security", "cms", "-D", "-i", str(profile), "-o", plist]).return_code != 0:
                continue
            team = _value(rctx, plist, "TeamIdentifier.0")
            expiration = _value(rctx, plist, "ExpirationDate")
            development = _value(rctx, plist, "Entitlements.get-task-allow") == "true"
            platform = _value(rctx, plist, "Platform.0")
            if (team and development and platform == "iOS" and (not want_team or team == want_team) and
                _value(rctx, plist, "Entitlements.application-identifier") == "%s.%s" % (team, BUNDLE_ID) and
                expiration > best[0]):
                best = (expiration, _value(rctx, plist, "Name"), team)
            rctx.delete(plist)
    if best[0] and best[0] < rctx.execute(["/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]).stdout.strip():
        return ("", "")
    return (best[1], best[2])

_ENVIRONMENT = [
    "P2PRC_TEAM_ID",
    "P2PRC_APP_GROUP",
    "P2PRC_APPLICATIONS_BUNDLE_IDS",
    "P2PRC_SHARED_CLIENT_ID",
    "P2PRC_SHARED_SERVICE",
]

def _signing_impl(rctx):
    env = {k: (rctx.getenv(k, "") or "").strip() for k in _ENVIRONMENT}
    name, profile_team = _ios_profile(rctx, env["P2PRC_TEAM_ID"])
    team = env["P2PRC_TEAM_ID"] or profile_team
    ids = [i.strip() for i in env["P2PRC_APPLICATIONS_BUNDLE_IDS"].split(",") if i.strip()]
    rctx.file("BUILD.bazel", 'exports_files(["signing.bzl"])\n')
    rctx.file("signing.bzl", "\n".join([
        "TEAM_ID = %r" % team,
        "IOS_PROFILE = %r" % name,
        "APP_GROUP = %r" % env["P2PRC_APP_GROUP"],
        "APPLICATIONS_BUNDLE_IDS = %r" % ids,
        "SHARED_CLIENT_ID = %r" % env["P2PRC_SHARED_CLIENT_ID"],
        "SHARED_SERVICE = %r" % env["P2PRC_SHARED_SERVICE"],
        "",
    ]))

_signing = repository_rule(
    implementation = _signing_impl,
    environ = _ENVIRONMENT + ["HOME"],
    # A new profile on the machine is found on the next `bazel sync` or
    # `--repo_env` change; `bazel fetch --force @convo_signing` sooner.
    local = True,
)

def _extension_impl(_mctx):
    _signing(name = "convo_signing")

signing = module_extension(implementation = _extension_impl)
