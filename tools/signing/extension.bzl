"""The builder's own signing values, from the machine, not the repo.

`@convo_signing//:signing.bzl` defines:

- IOS_PROFILE: the name of the newest unexpired iOS development profile on
  this Mac for com.LoganShire.P2PRC itself, of CONVO_TEAM_ID's team when
  that's set (not a wildcard: iOS refuses an
  app signed as `<team>.*`), from Xcode's and MobileDevice's profile folders,
  or "" when there is none (on Linux, say);
- TEAM_ID: the Apple team that signs Convo's builds: CONVO_TEAM_ID if it's
  set (a `.bazelrc.user` at the repository's root, not checked in:
  `common --repo_env=CONVO_TEAM_ID=<your team id>`), else that profile's
  team, else "".

A build with a team is one of the team's own: it carries the shared GitHub
sign-in (Shireworks' docs/shared-sign-in.md: the `GitHubShared…` Info.plist
keys and the `<team>.com.LoganShire.github` keychain group) and UpdateKit's
app group, shared with Shireworks. A build without one carries neither;
ShakeKit is in every build, and works only where the person is signed in to
Shireworks on the same device (it has no sign-in of its own).
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

def _signing_impl(rctx):
    set_team = rctx.getenv("CONVO_TEAM_ID", "").strip()
    name, profile_team = _ios_profile(rctx, set_team)
    team = set_team or profile_team
    rctx.file("BUILD.bazel", 'exports_files(["signing.bzl"])\n')
    rctx.file("signing.bzl", "TEAM_ID = %r\nIOS_PROFILE = %r\n" % (team, name))

_signing = repository_rule(
    implementation = _signing_impl,
    environ = ["CONVO_TEAM_ID", "HOME"],
    # A new profile on the machine is found on the next `bazel sync` or
    # `--repo_env` change; `bazel fetch --force @convo_signing` sooner.
    local = True,
)

def _extension_impl(_mctx):
    _signing(name = "convo_signing")

signing = module_extension(implementation = _extension_impl)
