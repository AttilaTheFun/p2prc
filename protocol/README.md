# ConvoProtocol

The Convo Protocol (`Docs/convo-protocol-spec-v2.0.md`) and its reference
implementation: an open protocol for distributed, end-to-end-encrypted group
chat. Messages are MLS-encrypted and author-signed in a DAG that members
agree on by signing heads. Independent nodes store and forward for offline
members and commit every item they accept to a log that other nodes witness,
so a node that drops or rewrites what it promised is caught by a proof
anyone can check. Anyone can run a node for free on a Cloudflare account
(`Worker/`), or self-host one (spec §26–§27).

- **Library** (SwiftPM, iOS / macOS / Linux): `ConvoCore`, `ConvoMLS`,
  `ConvoNet`, `ConvoNode`, `ConvoSession`, `ConvoClient`, and on Apple
  `ConvoWebRTC` (data channel + signaling) and `ConvoCalling` (audio and
  video calls, §25). Appendix C of the spec says what each holds.
- **Demo app**: `Examples/ConvoDemo`, a plain SwiftUI iOS/macOS app that
  exercises text, audio and video end to end against a node
  (`cd Examples/ConvoDemo && xcodegen && open ConvoDemo.xcodeproj`).
- **`convo`**: the reference CLI client: create and fork groups, send, pull,
  attest, resolve commitments, read a node's checkpoint, republish, rebase,
  probe nodes, keep and gossip fraud proofs.
- **`convo_node`**: the reference node: mailbox with receipts, signed fetch
  responses, acks, KeyPackages, identity records, blobs, discovery,
  rendezvous, STUN/TURN, its witnessed log, and a witness for other nodes'
  logs. `Dockerfile` builds it as an OCI image; `Docs/node-api.md` is the
  operator's reference.
- **Vectors**: `Tests/Vectors/*.json`, the conformance set of Appendix A.6.

```sh
swift test                      # swift Testing
swift run LoopbackChat          # two members, three witnessing nodes, in process
swift run convo --help
swift run convo_node --help
```

The P2PRC apps (this repository's `applications/`) consume it as a local
Swift package.
`Docs/deviations.md` says where the implementation stands against the spec.

## Running a node

- **Free, on Cloudflare**: `Worker/` (its README) builds the node to
  WebAssembly and deploys it as a Durable Object on a free Cloudflare
  account, with Cloudflare TURN. node-1..3.p2prc.org run this way and are
  the P2PRC apps' defaults.
- **Self-hosted**: the `Dockerfile`'s image, with a volume for its data
  directory, `CONVO_PUBLIC_URL`, and TURN from the built-in relay (publish
  its UDP ports), coturn (`CONVO_TURN_SECRET`), or Cloudflare
  (`CLOUDFLARE_TURN_KEY_ID` + `CLOUDFLARE_TURN_API_TOKEN`).

Give it witnesses (`WITNESSES` on Cloudflare, `--witness URL` in the
container): a log is published once two other nodes cosign it.
