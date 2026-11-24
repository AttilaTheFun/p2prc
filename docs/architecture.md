# Architecture: four node types, one responsibility each

Settled 2026-09-04 (proposal + Logan's answers). Supersedes the "every client is also a server" model in
[mesh_signaling.md](mesh_signaling.md) and [turn.md](turn.md); those stay as
history of what was tried. Nothing here is cloud-provider specific: the
first deployment uses Cloud Run, Cloudflare and GitHub Pages because they are
free or scale to zero, but each node type is defined by an interface any host
can satisfy.

## 1. Signaling servers

A container built from this repository (`applications/convo_linux`), reachable
over HTTPS (or plain HTTP where only native clients need it). Responsible for
one thing: helping clients connect and reconnect. RESTful only — no UDP, no
long-lived sockets — so a request-scoped platform can run it.

### API (JSON over HTTP)

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthcheck` | `{ok, id, kind:"signaling", version, site, turn, now}` — cheap, unauthenticated. `site` is the static web host this server vouches for; `turn` whether `/ice` carries a relay |
| GET | `/servers` | `{servers:[{url, id, site, turn}]}` — the signaling servers this one has confirmed healthy, itself first |
| POST | `/servers` | `{"known_signaling_servers":[urls]}` — what another server, or a contributing client, believes are signaling servers. Nothing is taken on faith: each URL is queued for this server's own health check and shared only once it passes |
| GET | `/ice?for=<client id>` | `{iceServers:[{urls, username, credential}], ttl}` — RFC-shaped STUN/TURN entries minted from the operator's TURN |
| POST | `/rendezvous/<box>` | Drop one sealed blob (an offer or answer) for `<box>` |
| GET | `/rendezvous/<box>` | Take the oldest blob, or 404 |

**TURN is the operator's, configured through the environment, never
advertised or relayed between servers.** `CONVO_TURN_URLS` with either
long-term credentials (`CONVO_TURN_USERNAME` / `CONVO_TURN_CREDENTIAL`, any
provider or coturn `lt-cred-mech`) or a TURN-REST shared secret
(`CONVO_TURN_SECRET`, coturn `use-auth-secret` or this repo's relay, minted
per client); or `CLOUDFLARE_TURN_KEY_ID` / `CLOUDFLARE_TURN_API_TOKEN`
(Cloudflare Realtime's credential API — the one provider adapter, server-side
only, minted ahead and served from memory). `CONVO_STUN_URLS` adds STUN. A
signaling server without TURN still signals; peers behind carrier NAT then
need the other side's. Usage and spend are watched in the provider's own
dashboard; the app has no part in it. There is no in-app TURN enrolment.

**The static web host is the operator's too**: `CONVO_SITE_URL`, reported in
`/healthcheck` and `/servers`, so clients learn a verified site from the
server they trust rather than from a compiled-in URL.

**The rendezvous is not a mailbox.** It holds sealed WebRTC offers and
answers for two minutes so two clients can find each other; nothing else
ever passes through a server. Chat history lives on the clients: each
remembers, per contact, the last message the other side had seen, and on
reconnect the two catch each other up over the data channel and reconcile.

### Discovery and health

- **Health checks with backoff**: 10 min, 30 min, 1 h, 3 h, 1 day, 1 week.
  A passing check resets to 10 min. After a week of failures the record is
  evicted until re-published.
- **Graph traversal**: on start and whenever the healthy count drops, walk
  `GET /servers` from every known signaling server, breadth-first, POSTing
  our own record to each one reached. Stop at **20** healthy signaling
  servers. Never more than once an hour.
- TURN and static records are shared the same way and health-checked on the
  same schedule.

### Abuse resistance

Per-IP throttling with backoff responses, and hard caps, so the cheap
attacks are bounded: token buckets on `POST /servers` (6/min), `/ice`
(30/min), rendezvous drops (60/min) and polls (240/min), answering 429 with
a retry-after; advertisements ≤ 4 KB and ≤ 20 URLs; blobs ≤ 16 KB, ≤ 32 per
box, 2-minute lifetime, ≤ 4096 boxes with the oldest evicted. Advertised
servers are never shared until this server's own health check passes. On
Cloud Run `--max-instances` bounds the compute bill.

### State

In-memory, rebuilt from peers: a fresh instance seeds from `CONVO_SEEDS`
and the graph walk (`CONVO_STATE_DIR` persists the directory where there is
a disk). `CONVO_NODE_ID` keeps the id stable across restarts; unset, one is
minted per boot. The rendezvous is per instance, so a deployment with more
than one instance needs sticky routing or a shared store — start with
`--max-instances 1` and revisit.

### Binary and image

`applications/convo_linux` is the server: a Swift binary that runs bare on a
VM or bare metal, and the same binary in a container built with rules_oci,
ready for Cloud Run or any service that runs containers. The first
deployment: `api.p2prc.org` on Cloud Run, configured with the Cloudflare
TURN key and `CONVO_SITE_URL=https://p2prc.org` (GitHub Pages behind a custom
domain).

## 2. TURN / STUN servers

RFC 5389 / 5766 / 8656 servers, anyone's: Cloudflare Realtime, another
provider, or `libraries/convo_turn` run by the signaling binary itself
(`--relay`) on a VPS with UDP open. Each belongs to a signaling server's
operator and is configured on that server (above); clients get credentials
from `/ice` and never learn how the server obtained them. Usage and spend
are the provider's business: the app neither polls analytics nor enforces a
budget.

## 3. Static web servers

Any HTTPS host serving a release of the web client: GitHub Pages, S3 +
CloudFront, Cloudflare Pages, a VPS. Each is named by a signaling server's
operator (`CONVO_SITE_URL`) and learned by clients from `/healthcheck`;
the server verifies it by release signature (`bundle-signature.json`, the
same check the client makes) before vouching for it. Native clients need
none. Invite links point at the site of the signaling server in the QR; the
app has no compiled-in site URL.

## 4. Clients (web and native)

Clients only consume. Removed: UPnP, the embedded HTTP server and "server
mode", the native TURN relay, the Cloudflare broker / self-relay / spend
guard, the inline-offer (`#p=`) pairing and the reverse-scan reply (`#a=`).

- **Discovery**: the same walk as a signaling server, bounded at **10**
  servers, same backoff and eviction, persisted locally. A fresh install
  starts from a **seed list** shipped as configuration by each app shell
  (Info.plist / assets / a JSON in the site), initially one Cloud Run URL —
  data, not code, so no provider is baked into the client.
- **Pairing**: the QR / link carries `#m=<public key>.<signaling server
  URL(s)>` — identity plus rendezvous, nothing else (today's mesh form;
  small and quick to scan). The joiner posts a sealed offer to the
  presenter's box on that server; the presenter answers through it. The
  spoken six-character code stays as the proof of physical presence.
- **ICE**: `GET /ice` on the signaling server used for the connection.
- **Reconnect**: unchanged in principle (sealed re-offers through mailboxes),
  now always through a signaling server both sides discovered.
- **Contributing**: Settings → "Advertise a signaling server": a URL,
  POSTed as `{"known_signaling_servers":[url]}` to the client's known
  servers, exactly as servers advertise to each other. TURN and the static
  site are that server's configuration, not separate advertisements.
- **Chat history**: persisted locally; on reconnect each side sends what the
  other has not seen (last-seen per contact) and the two reconcile.
- **Later**: groups. Pairing stays the trust root for DMs; group create /
  invite / membership changes ride as signed messages through the same
  signaling servers.

## Phases

1. **Signaling server** (done 2026-09-04): `SignalingServer` in
   `libraries/convo_server` (the API above, discovery, health/backoff/
   eviction, `/ice` for the three TURN modes, per-IP throttles), the
   `ServerDirectory` logic in `libraries/convo_directory`, unit tests for
   backoff, eviction, the bounded hourly walk, throttles and the rendezvous;
   `applications/convo_linux` rewritten around it; the rules_oci image.
2. **Clients**: discovery + seeds; mesh-only pairing; `/ice`; remove the
   server/relay/UPnP/Cloudflare/inline paths from `Client`, the hosts and the
   UI; the Advertise settings; web + native builds.
3. **Deploy**: Cloud Run (`gcloud run deploy --source .`), advertise GitHub
   Pages and the Cloudflare TURN key to it, ship the seed, verify phone (5G)
   ↔ Mac end to end.
4. **Docs**: retire mesh_signaling.md / turn.md into this file; TODO.
