# Milestones

Where P2PRC stands and what each launch step needs. `TODO.md` and
`protocol/TODO.md` hold the long lists; this is the short one, ordered. Tick
items as they land and date them. (The app was called Convo, and its
protocol and app were two repositories, until P2PRC's first release.)

Convo is an open protocol with a closed client: anyone can run a node, as
people run Nostr relays or AT Protocol servers, and the protocol's spec and
reference implementation are meant to be published alongside a whitepaper.
Until 2026-11-18 the nodes committed to a public ledger; that revision of
the app and protocol is archived in AttilaTheFun/convo_crypto.

## Done before v2.0

The app's features as of the archived revision, all of which carry over:

- [x] Pairing across devices, messaging through the nodes' mailboxes with
  commitments and attestations, calls over Cloudflare TURN (2026-09-14).
- [x] Offline queue and delivery feedback (2026-09-14): a message with no
  node reachable is kept and re-posted on every pull tick until a host
  receipts it; the thread shows "Waiting for a node", then "Sent to the
  nodes". `CONVO_DEBUG_NET=1` traces the directory on stdout.
- [x] Signed GETs for the member-only routes (2026-09-20).
- [x] Pictures and reactions (2026-09-20): message kinds 4 and 3
  (`Docs/deviations.md` in the protocol repo). A picture is picked and
  downscaled by the host, sealed under a fresh key, put at the hosts as a
  blob, and shown through the host once fetched; a long press on a bubble
  offers reactions, folded under the bubble; the same emoji again takes
  one back. Android has no picker yet (the host stubs it).
- [x] One identity across a person's devices (2026-09-22): Settings →
  "Add a device" seals the seed, the name, the contacts and every
  conversation's record (genesis, roster, MLS secret) under a fresh key
  and leaves it in a rendezvous box for ten minutes; the new device
  scans the code (or opens the link) from onboarding's "Use another
  device", becomes the identity and fetches the messages the hosts hold.
  Both devices share one leaf: reading a message our own leaf sealed
  moves the ratchet past its generation (convo_protocol ebdb154), so
  they never seal at the same generation. Not yet: an MLS Update commit
  from one device cannot be applied by the other (the path secrets are
  sealed to the other leaves), so epoch rotation must seal the commit
  secret to its own leaf before rotation lands.
- [ ] Background delivery, so a closed app receives. The protocol side
  landed 2026-09-22 (convo_protocol 5b51f81, "wakes" in
  `Docs/deviations.md`): a member registers a relay URL and an opaque
  handle with each host; when a message lands the host calls the relay
  with the item, signed by the node key, skipping the author. Still to
  do: the push gateway (a Cloud Run service holding the APNs key; the
  handle is the device token sealed under the gateway's key, so it keeps
  no table and handles are unlinkable across groups), the app's
  registration on launch, and a notification service extension that
  opens the item from the shared container. The gateway needs the paid
  developer membership for the APNs key.
- [x] Key rotation on the clock (2026-09-22): the app's KeyPackage
  `hpke_index` advances every `HPKE_ROTATION` of calendar time (derived,
  so every device agrees; groups keep the index they were made with) with
  `not_after` at `KP_LIFETIME`; MLS Update commits after
  `MLS_UPDATE_INTERVAL` by count or on the clock (the epoch clock is
  persisted), issued from the send path and the pull tick; a commit
  carries its leaf secret sealed to the author's own key so a second
  device of the identity follows the rotation (convo_protocol 23e1c9a).
- [x] Syncing and recovery (2026-09-22): an attestation over a head this
  member does not hold marks it syncing (§9.2: it stops attesting and
  asks the hosts for the head by hash every tick, convo_protocol 1f65d47);
  after `RECOVERY_PATIENCE` without it (member 1 after the stagger) the
  app starts a recovery fork. `CONVO_DEBUG_RECOVERY_PATIENCE` (seconds)
  shortens the wait for tests.
- [x] Delivery on a phone-layout web client held up under the three-device
  harness (2026-09-22) after three fixes it exposed: a Borsh length above
  the input trapped on wasm32 instead of throwing, aborting a fetch reply
  before the message in it (convo_protocol a714dce); a client that never
  got a reading of the nodes' clock signed fetches with its own and could
  never learn better, since a reply below the request's time is discarded
  (now a pull without a reading asks a node for its clock first, and a
  first reply's clock is adopted); and Compose failed at once when no node had
  answered yet (it now retries for a while). The thread also lists every
  branch, so two members who sent at once both show.
- [x] Secrets at rest on the web and Android (2026-09-22): the web seals
  secrets (AES-GCM) under a non-extractable key held in IndexedDB, clear
  values from earlier builds sealed on first read; Android seals them
  under an Android Keystore AES-GCM key. WebAuthn's PRF would bind the
  web key to the authenticator but needs a tap at every launch, so it is
  deferred. Android also has the image picker now (isomer's picker
  host).

## M1: the open protocol (spec v2.0)

- [x] Spec v2.0 and its reference implementation (2026-11-18,
  convo_protocol `open-protocol`): witnessed logs instead of a ledger,
  signed node descriptors and gossip, identity records, portable fraud
  proofs F1–F6, unix-ms time. 74 tests on Linux.
- [x] The app on v2.0 (2026-11-18): identities from a recovery phrase
  alone; commitments resolved against the checkpoints their refs carry.
  The macOS, iOS-library, web and Android apps build under Bazel against it.
- [x] Three v2 nodes on Cloud Run, scaled to zero (2026-11-18):
  `convo-v2-node-1..3` in p2prc-org, built by Cloud Build, scaled to zero,
  one instance each, bucket volumes, Cloudflare TURN through `/ice`; the
  apps' seed lists point at them. Two CLI identities paired, messaged and
  attested through them, and the items were committed in checkpoints with
  two witnesses each. Cloud Run ran two instances of node 3 despite
  `--max-instances 1`, the second serving stale state; the nodes now hold
  their data directory under a lease (convo_protocol 2a965ad) and mount it
  uncached. After the redeploy every node published at seq 3 with two
  witnesses and no fraud proof held anywhere. The v1 nodes `convo-node-1..3` and their buckets were
  deleted the same day, so builds from before v2.0 have no nodes.
- [x] The web app against the v2 nodes (2026-11-18): `tools/e2e/run_pair.sh` in
  two iOS simulators on a macOS VM. Two new identities paired through
  the nodes' rendezvous boxes, messaged both ways ("Delivered"), and reopened
  the thread; the nodes logged the key packages, genesis, messages, fetches
  and acks.
- [x] Usage on 2026-11-18, from Cloud Monitoring, across all three nodes and
  every test that day (two deploys, two CLI runs, the simulator run): 341
  billable instance-seconds (1 vCPU, 512 MiB each) and 1,322 requests, about
  0.2% of Cloud Run's monthly free tier (180,000 vCPU-s, 360,000 GB-s, 2M
  requests; Google's Free Tier usage limits page). Not free: the buckets'
  operations, about 95 Class A and 160 Class B per node per minute of
  activity through Cloud Storage FUSE, against 5,000 and 50,000 free a month
  (convo_protocol#2 cut the renames; the rest needs the storage redesign in
  convo_protocol's TODO), and Cloudflare's TURN at $0.05 per relayed GB.
- [x] The nodes on Cloudflare's free plan (2026-11-23): convo_protocol's
  node core compiled to WebAssembly in a Durable Object per node, its files
  in the object's SQLite; node-1..3.p2prc.workers.dev witness each other and
  mint Cloudflare TURN credentials. A group homed on them paired, messaged,
  attested and committed. CPU per request: 1.8 ms at the median, 30 ms at
  most, no errors. The apps seed from them, and the Cloud Run nodes are
  retired.
- [ ] A month of a real community's use against Cloudflare's free caps.
- [ ] A self-hosting walkthrough tried end to end on a small VPS (Docker,
  the built-in relay, a public URL).

- [x] Convo 0.35.2 (2026-11-24): the last release as Convo, built, signed
  and proved by CI, its proof two web clients paired and messaging through
  node-1..3.p2prc.org with their link relayed by Cloudflare TURN.

## M2: P2PRC, public

- [ ] One public repository, P2PRC (the app and the protocol together),
  under the Apache License: bundle id com.LoganShire.P2PRC, Android
  com.loganshire.p2prc, current Isomer, CI on GitHub's runners, the web
  client on GitHub Pages at p2prc.org.
- [ ] The web and Android WebRTC on communication.
- [ ] TestFlight for iOS.

## M3: beyond two

- [ ] Groups above two members, membership and host-change forks in the UI.
- [ ] Call polish: trickle ICE and ICE restart, CallKit, mute/camera
  controls, the macOS video panel.
- [ ] MLS RFC 9420 vectors and RFC-shaped framing.
- [ ] The whitepaper.
