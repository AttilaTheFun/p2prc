# A Convo node on Cloudflare

The reference node's portable core (`ConvoNodeCore`) compiled to WebAssembly
and run as a Cloudflare Durable Object, so a free Cloudflare account is all it
takes to run a node (spec Part IV).

- **One writer.** A Durable Object is a single instance per ID, so the node
  key's log has exactly one author (spec §28), with no lease.
- **Storage.** `src/wasi.js` gives the reactor a WASI file system kept in the
  object's SQLite: one row per file, written when the file is closed, so
  everything a request wrote is stored before its response leaves.
- **Commitment and witnessing.** The object's alarm closes batches
  (`COMMIT_INTERVAL_MS`, default five minutes) and asks the `WITNESSES` to
  cosign each checkpoint (spec §7, §11).
- **TURN.** `/ice` hands out Cloudflare's STUN and, to a client the node's
  rate limit lets through, a Cloudflare Realtime TURN credential of its own
  for an hour (the first 1,000 GB a month free).
- **Limits.** Bodies over 2 MB aren't read; blobs are 1.5 MB at most (a
  SQLite row holds 2 MB), 16 MB in all; everything the node holds for others
  fits 24 MB (at start the object holds each file twice in its 128 MB),
  past which it answers 507 until retention frees room. Rendezvous boxes
  hold 8 MB at most. Rate limits count an IPv4 address (IPv4-mapped IPv6
  included) or an IPv6 /64.
- **Geneses** of groups with nothing held here go after the retention period
  unless a member posts them again (clients do while the group is in use);
  a group offline that long has its genesis back with its members' next post.

## Build

On a Linux machine with Swift 6.4 and swift.org's WebAssembly SDK
(`swift sdk install …swift-6.4.2-RELEASE_wasm.artifactbundle.tar.gz`), from
this repository's `protocol/`:

```sh
cd protocol/Worker
swift build --swift-sdk swift-6.4.2-RELEASE_wasm -c release --product convo_node_worker
cp .build/release/convo_node_worker.wasm src/
```

The module is about 14 MB (4 MB gzipped), under Workers' 64 MiB. The node's
modules build on FoundationEssentials there (`ConvoFoundation`), which keeps
ICU's 30 MB of locale data out.

## Run

```sh
npx wrangler dev                       # locally, in workerd
npx wrangler deploy                    # to your account; the node is at <name>.<you>.workers.dev
npx wrangler secret put CLOUDFLARE_TURN_KEY_ID
npx wrangler secret put CLOUDFLARE_TURN_API_TOKEN
```

Set `WITNESSES` and `SEEDS` in `wrangler.toml` (other nodes' URLs, comma
separated; at least two witnesses other than this node). The node's URL is
its first request's origin unless `PUBLIC_URL` says otherwise.

## The p2prc nodes

Three nodes run this way on a free account, at
`https://node-1.p2prc.org`, `node-2` and `node-3` (custom domains in the
p2prc.org zone, since 2026-11-23; `node-<n>.p2prc.workers.dev` still
answers), each the other two's witness. Each is its own Worker:

```sh
npx wrangler deploy --name node-1 --domain node-1.p2prc.org \
  --var WITNESSES:https://node-2.p2prc.org,https://node-3.p2prc.org \
  --var SEEDS:https://node-2.p2prc.org,https://node-3.p2prc.org \
  --var NODE_ID:node-1 --var PUBLIC_URL:https://node-1.p2prc.org
```

Measured on Cloudflare (2026-11-23): a group homed on the three paired,
messaged, attested and committed, each node's checkpoint cosigned by the
other two. CPU per request: the routing Worker 0.75 ms at the median and
2 ms at p99; the Durable Objects 1.8 ms at the median, 18 ms at p90 and
30 ms at the most (a cold start or a commit), with no errors.

## The reactor's interface

`Sources/convo_node_worker/Reactor.swift` exports C functions that take and
return JSON: `convo_node_init` (configuration), `convo_node_handle` (one HTTP
request, answered with the response and any calls to make), `convo_node_alarm`
(retention, closing a batch, witness requests), `convo_node_answers`
(witnesses' replies, answered with requests to resend), and
`convo_node_logs`.
