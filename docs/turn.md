> **Superseded 2026-09-04 by [architecture.md](architecture.md).** Native
> clients no longer relay or broker TURN; a signaling server's operator
> configures TURN through the environment and clients fetch credentials
> from `/ice`. `libraries/convo_turn` remains for `convo_linux --relay` on
> a VPS. What follows is the earlier design, kept for the reasoning it
> records.

# TURN relays and the server node

Settled 2026-08-31. Extends [mesh_signaling.md](mesh_signaling.md): signaling
already survives NAT (a mailbox on any reachable server), but media and data
channels need a path, and behind CGNAT — most mobile carriers, many ISPs —
neither side can accept a packet the other sends first. ICE's answer is a
relay: a TURN server (RFC 5766 / RFC 8656) both sides can reach, that
forwards between them. This is Convo's.

## What relays

Every server in the directory can relay, not just a cloud box. The relay is
`libraries/convo_turn`: a STUN server (RFC 5389 Binding) and TURN relay on
POSIX sockets, UDP and TCP client transports, long-term credentials with MD5
keys — the dialect every WebRTC stack speaks. One thread, one poll loop, no
locks in the data path. It cross-compiles unchanged to macOS, iOS, Android
(the NDK toolchain) and Linux, which is how "clients act as TURN servers"
costs one implementation.

`libraries/convo_server` is the serving half every host shares: `Serving`
(the mailbox, directory, gossip, bootstrap site — moved out of the Apple app
so the Android image and the Linux node run the same code) plus
`RelayService` (the TURN server and the credential minter, bound to one
secret) and `DirectoryNode` (directory participation for a node with no chat
client).

Ports: HTTP stays on 18091; STUN/TURN listens on **3478** (IANA's port, UDP
and TCP — it can't share the HTTP port, TURN-over-TCP is a different protocol
on the same socket); relay sockets bind to a small range (18100–18115 on a
phone or laptop, 18100–18199 on the node) so a NAT can be asked to map them
ahead of time.

## Credentials

The TURN REST shape (draft-uberti-behave-turn-rest): a client GETs
`<server>/turn?for=<its id>` and receives

```json
{"urls":["turn:203.0.113.4:3478?transport=udp","turn:203.0.113.4:3478?transport=tcp"],
 "username":"1725000000:4008a1bc8b5fff51","credential":"<base64 HMAC-SHA1>","ttl":3600}
```

The username is `<expiry>:<client id>`, the password is HMAC-SHA1(secret,
username); the relay validates from the secret alone, with no user table.
Trust model: the same as the mailbox — anyone who can reach the server gets
a short-lived credential. What that buys an abuser is an hour of relay
bandwidth bounded by the relay's port range; the price of a public TURN
deployment, and why lifetimes are short.

## Policy (the guest)

- A record advertises `relay: true` (and `relayPort`) when its host's
  capabilities include a relay. The guest fetches credentials from the best
  three relays it knows (`Client.refreshRelayCredentials`), caches them until
  a minute before expiry, and hands its WebRTC stack the structured list —
  STUN peers, then TURN entries with credentials, then Google's STUN as the
  cold-start fallback (`BootstrapDirectory.iceServers`).
- Hosts receive `setIceServers` as `[{urls, username?, credential?}]`. All
  three stacks take that shape natively (RTCIceServer, PeerConnection.IceServer,
  the browser dictionary).
- ICE decides when to use the relay: it tries direct first and falls back to
  relayed candidates when nothing else pairs. Nothing here forces a relay;
  the Android host's `debug.convo.relay_only` system property does, for
  proving one end to end.

## Reachability: how a host gets its relay reached

- **UPnP + STUN** (a home router): the native hosts already map the HTTP
  port; they now map 3478 (UDP+TCP) and each relay port (UDP) too, and
  advertise the router's external address as the relay host. STUN confirms
  the mapping from outside. Where UPnP fails, the relay still serves the LAN.
- **A tunnel or overlay** (ngrok, tailscale, a VPN): the Linux node takes
  `--public-host` — whatever address the tunnel presents — and advertises
  that. Tailscale's 100.x address relays for the tailnet; an ngrok TCP tunnel
  gives TURN-over-TCP a public port.
- **A cloud machine with ports** (a VM, a container with published ports): the
  full node — mailbox, site, STUN, TURN — at its public IP.
- **A request-only platform** (Cloud Run): HTTP/WebSocket ingress only, no
  UDP, no raw TCP. The node runs `--no-turn --public-url https://…` and is a
  **CA-tier** server: the one kind a browser on an HTTPS page can reach for
  its first contact, which is the cold-browser pairing gap in TODO.md. It
  cannot relay. For a free always-on relay, a GCE e2-micro (free tier) with
  UDP 3478 + 18100–18199 open runs the same image.

## Donating Cloudflare's relay (the broker)

A person with a Cloudflare account can contribute Cloudflare's managed TURN
service to the network instead of (or on top of) their own relay: Settings →
"Cloudflare relay", enter a TURN key ID and API token from the dashboard
(Realtime → TURN keys). Their server's `/turn` then answers with short-lived
credentials minted from that key — the key never leaves the device, peers
need no new code, and Cloudflare's anycast relay reaches peers a home relay
cannot. Priced per use ($0.05/GB after 1 TB free); their STUN rides along
free.

Brokering is plain HTTPS, so it works where relaying does not: a Cloud Run
node with `CLOUDFLARE_TURN_KEY_ID` / `CLOUDFLARE_TURN_API_TOKEN` set (or
`--cloudflare-key-id/--cloudflare-token`) advertises `relay: true` even with
`--no-turn` — the scale-to-zero relay. Credentials are minted ahead on a
refresh loop and served from memory: one mint covers every peer, `/turn`
never blocks on Cloudflare.

**A key holder also relays their own calls, with no server at all.** The host
mints from the key for the guest's own connections too (the `localTURN`
host call), so a CGNAT peer that serves nobody still emits a Cloudflare relay
candidate in its offers and answers. That closes the fully-serverless case:
two CGNAT peers (native or browser) pair by QR — the human is the signalling
channel, the inline offer/answer QR carrying each side's relay candidate —
and relay entirely through Cloudflare, with only GitHub Pages (or any static
host) delivering the browser app. Native-to-native needs no hosted service
at all. Only one of the two needs a Cloudflare account: TURN credentials are
bearer tokens, so a credential minted by one side works for both if shared.

**Spending is bounded only best-effort.** Cloudflare TURN zero-rates the
first 1 TB/month and bills $0.05/GB after, and enabling Realtime requires a
payment method on the account — there is no "free plan with no card" that
cannot be charged, so nothing on Cloudflare's side hard-stops spend. What
the app offers is a **monthly dollar budget** slider ($0 = free tier only,
up to $20/mo, or unlimited). Enforcing it needs read-only usage access (an
API token with Account Analytics: Read, plus the account id): the broker
then polls Cloudflare's own TURN usage (`callsTurnUsageAdaptiveGroups`,
egress + ingress bytes, month to date) and, once at the cap, **stops handing
out credentials** — no new relay allocation can start on the key, and
existing ones drain within their credential TTL. It fails closed on confirmed
usage but not on transient query errors (it keeps its last state rather than
flapping the relay). Limits of the guarantee: the app can only pause while a
process holding the key is running and watching (the app, or the Linux node),
and the ten-minute poll means it can overshoot the cap a little. So a key
holder should also set Cloudflare's own budget alerts (email, roughly a day
behind), keep the dollar budget low, and know the real kill switch: deleting
or rotating the TURN key at Realtime → TURN in the dashboard, from any
device, stops new allocations instantly and needs no app. Convo traffic is
audio and data, no video, on the order of 100 kbps per call, so reaching
1 TB in a month is unlikely for a personal relay.

**What has to be running.** The relay itself is Cloudflare's, up whether or
not the app is. The app (or node) is needed only to *offer* the relay: to
mint credentials for its own calls, to answer `/turn` for other peers when
in server mode, and to watch usage against the budget. Close the app and
the network loses that offer (peers fall back to other relays) but nothing
on Cloudflare stops — and neither does the budget watch, which is why the
key in the dashboard is the backstop.

The settings section appears where the host reports the `relayBroker`
capability — the Apple apps and Android. (A browser tab cannot serve
`/turn`, so the web client consumes brokered credentials but cannot
broker.) On Android the keys live in the app's SharedPreferences and ride
to the Swift server with each enrolment.

## The Linux node

`applications/convo_linux`: `convo_linux [--port 18091] [--turn-port 3478]
[--relay-ports A-B] [--public-host H | --public-url U] [--no-turn] [--site DIR]
[--state DIR] [--seed URL]… [--capacity N]`. It announces itself to every
`--seed` (any running server, e.g. a Mac's `http://<lan>:18091`), absorbs the
answers, re-announces every half-lifetime, and serves `/directory`, so one
seed spreads it through gossip; clients then fetch `/turn` from it.

Build and run in podman (the image is what a VM or Cloud Run runs):

```
bash tools/linux/build.sh      # bazel inside ubuntu:24.04; cache mount keeps rebuilds incremental
bash tools/linux/run.sh        # 18091 + 3478 + 18100-18115 published on this Mac's LAN address
bazel run //libraries/convo_turn:turn_probe -- <host> 3478 <username> <credential>
```

The probe runs the whole ceremony from a real socket — challenge, allocate,
permission, Send/Data, ChannelBind/ChannelData, refresh-to-zero — and its
Send step only passes if the advertised relay address really routes back to
the caller, which is the check that matters for a deployment. Its peer
socket learns its own mapped address with a Binding request first, the way
an ICE agent does: podman's port forwarding is a NAT (the relay sees every
caller as 10.88.0.2 with rewritten ports), and so is a home router.

Verified 2026-09-01: the node in podman, seeded with a Mac's server, gossiped
into the Mac's directory; the Android emulator, forced to relay-only ICE,
reconnected to the Mac in ~10 s through the container's relay (its log shows
the Allocates; the Mac's own relay was not used).

Cloud Run: `gcloud run deploy convo-node --source . --port 18091` with
`--args=--no-turn,--public-url=https://<service>.run.app`; instances have no
disk, so the node id is minted per instance (harmless: records are refreshed
every fifteen minutes and age out in thirty).

## Not yet

- Android's UPnP + broker paths are linked and running (the SDK ships
  libcurl/libssl/libcrypto/libxml2 static archives; the app names them in
  linkopts — the "does not link" era is over), but UPnP hasn't met a real
  router from Android yet: the emulator's NAT answers no SSDP.

- Relay quotas per credential (bytes, concurrent allocations) beyond the
  port-range cap.
- The Cloudflare token is stored with the app's other settings (UserDefaults
  / SharedPreferences), not the platform keychain. When it moves: sign the
  Mac app with a stable identity first (bazel's `--ios_signing_cert_name`
  applies to macOS too) — ad-hoc signatures differ per build, so Keychain
  items re-prompt on every rebuild, and after a `SecItemUpdate` the old
  creator's ACL persists (re-create the item to transfer ownership). Learned
  in Overcast.
- TURN over TLS (`turns:`) for networks that block plain 3478.
- The seed list clients start with is still empty: a deployed node's URL
  should be injected as configuration by each app shell so a fresh install
  finds it without a peer.
