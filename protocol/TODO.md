# TODO (spec v2.0)

`Docs/deviations.md` lists where the implementation stands against the spec;
each item there is work too.

## Protocol and node

- Witness independence: clients compare witnesses' descriptors (operator
  and site) before counting a cosignature (§11).
- Nodes fetch and compare each other's checkpoints, and gossip F6 they find
  (§11), not only what witnessing shows them.
- Nodes verify descriptors in their own directory (§24); advertisements
  carry the descriptor.
- Identity records in invitation links and QR codes (§13.2).
- Spam: invitation codes or puzzles for new identities, beyond rate limits.

## Client library and app

- HPKE index rotation and KeyPackage expiry (`HPKE_ROTATION`,
  `KP_LIFETIME`); MLS Update commits on the time interval, not only the
  message count.
- Recovery forks after `RECOVERY_PATIENCE` from the client loop (the fork
  itself works; only the trigger is manual).
- Groups above two members and blobs in the app; §9.4 side-branch
  rendering in the thread (the CLI shows it; the app shows a marker).
- Web: the identity secret is in localStorage (no keychain); consider
  WebAuthn-wrapped storage.
- Android: Keystore-encrypted secret storage.
- Push notifications, CallKit.

## MLS

- RFC 9420 vectors and RFC-shaped framing (D.4) before open-sourcing the
  target.

## Nodes on Cloudflare

- wasi.js loads every file into the object at start, and the node keeps its
  own copy: read files from SQLite on demand (and the mailbox's blobs from
  disk), so the 24 MB budget can grow toward the 5 GB of storage.
- `/ice` takes any `for=`: TURN credentials are per request and rate
  limited per IPv4 address or IPv6 /64, but anyone may ask. Require
  `X-Convo-Auth` (an identity's signed GET) once the clients send it, and a
  Cloudflare rate-limiting rule in front of the Workers, since the free
  plan's 100k requests a day can be spent from many addresses.
- The Worker node runs no discovery or health checks; it uses its
  `WITNESSES` and `SEEDS`. Give it the directory walk on its alarm.
- Batch bodies go to the node's witnesses; send them to each group's other
  home nodes instead (§13), resolving their URLs from descriptors.
- `node-<n>.p2prc.org`: a custom domain on the same Workers.
- A month of a real community's use against the account's free caps.
- CI for the Worker: build the wasm on Linux and deploy on release.

## Next version: storage on swift_sql drivers (Logan, 2026-11-23)

- **In swift_sql (public; its owner merges and tags):**
  - a `SQLDriver` protocol (synchronous) and an `AsyncSQLDriver` protocol;
  - a `SQLClient` and an `AsyncSQLClient` wrapping them;
  - an adapter that lifts a synchronous driver into the async client.
- **Drivers:**
  - SQLite (synchronous, today's CSwiftSQL);
  - Durable Object SQLite (synchronous: `ctx.storage.sql.exec` imported into the wasm, transactions through `transactionSync`);
  - Postgres (async, PostgresNIO, its own product so SQLite users don't link NIO).
- **Where each is used:** clients keep synchronous SQLite; a backend uses synchronous Durable Object SQLite, or Postgres through the async client.
- **The node's storage** (Mailbox, the witnessed logs, wakes) moves onto tables over these drivers, and the Worker's WASI file layer goes. TURN minting moves into Swift, and the JS glue becomes swift_ffi.

## Next version: communities (Logan, 2026-11-23)

A self-hosted Slack or Discord on the same foundations:

- **Communities.** A community is a key pair and a signed record (name, domain, rules, the nodes it blesses). The key signs each node's endorsement. The domain proves the key at `https://<domain>/.well-known/convo-community`. p2prc (node-<n>.p2prc.org) is the first community; anyone can start another under their own domain on a free Cloudflare account.
- **Trust in the community.** Clients trust the communities their user joined, and the app ships trusting the primary one. A community's standing comes from its blessed nodes, its age, measured uptime and, above all, witnessing by other communities' nodes. Node count alone is cheap to fake.
- **Channels.** Groups whose members change in place (MLS adds and removes, gated by the community's role keys), not by fork. A history key lets newcomers read back, and channels may be public within a community. Private chats stay as they are.
- **Roles and moderation,** signed by the community key and enforced by clients.
- **The app:** communities, channels, threads, mentions, and search on the device.
- **The spec:** a "Trust and incentives" section. Nodes are free and easy, so communities run their own. Reputation and cross-community witnessing replace stake. Money stays outside the protocol.

## Tooling

- CI for this package: `swift test` on Linux (GitHub's runners once it is
  public), the Apple targets at release verification.
- A published `convo_node` image for self-hosters.
