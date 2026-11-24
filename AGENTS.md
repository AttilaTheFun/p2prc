# P2PRC, for agents

Read README.md for the parts. The protocol's spec is normative:
`protocol/Docs/convo-protocol-spec-v2.0.md`; `protocol/AGENTS.md` has the
protocol package's own rules. `docs/` holds the app's architecture and
milestones, `tools/e2e/README.md` the end-to-end checks.

## Changes

This repository is public. Every change to `main` goes through a pull
request: `main` is protected, and CI's checks must pass before a pull
request merges. Keep each pull request to one focused change, and say in it
how the change was verified (the targets built, the tests run, an
end-to-end run).

## Rules

- No Apple team ids, certificates, provisioning profiles, device UDIDs,
  keys or tokens in the repository, a commit, a pull request or a log. The
  team comes from the builder's own `.bazelrc.user` (`tools/signing`), which
  is not checked in.
- No attribution lines in commits.
- One SwiftUI source: shared code calls one cross-platform API (Isomer's,
  or a small protocol the app owns, like `ConvoHost` in
  `libraries/convo_services`), and platform specifics live behind it, in as
  few files as possible. Avoid new `#if os(...)` in shared code.
- No Combine and no `ObservableObject`: the client is `@Observable`, and
  async work is async/await.
- The protocol and the code must agree: when they don't, fix one and record
  it in `protocol/Docs/deviations.md`.
- Nodes are held to account by witnesses and fraud proofs alone, so anyone
  can run one for free. Keep the node within Cloudflare's free plan
  (`protocol/Worker/README.md` has its limits).
- Snapshot tests and proofs hold still what changes between runs: a fixed
  clock and locale in fixtures, the simulator's status bar overridden
  (`xcrun simctl status_bar … override --time 9:41 …`), screenshots masked
  (`--mask=black`), and no live data in a picture.

## Versions and releases

The Info.plists, `Client.version` and Android's `version_name` carry the
committed line (`MAJOR.MINOR.0`); CI stamps each build's own
`MAJOR.MINOR.N` and a release is tagged `vMAJOR.MINOR.N`. Each release
carries its proof: two clients paired and messaging through the nodes,
their link relayed by TURN, with the run's log and screenshots.

CI is `.github/workflows/build.yml` (its header says what runs when, on
GitHub's runners) and `pages.yml` (a published release's web client to
p2prc.org). Its scripts are in `tools/ci`, its Swift tool in
`tools/convo_ci`; signing is build_tools' `sign`, with the `release`
environment's keys. Drafts are CI's: no agent publishes one or makes a tag.
