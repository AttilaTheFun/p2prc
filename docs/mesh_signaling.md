> **Superseded 2026-09-04 by [architecture.md](architecture.md).** Clients
> no longer serve, gossip a directory, or advertise through UPnP; signaling
> servers are dedicated nodes with a health-checked directory, and the
> mailbox is a two-minute rendezvous for offers and answers. What follows
> is the earlier design, kept for the reasoning it records.

# Mesh signaling

The design settled 2026-08-08. Supersedes both the peer-HTML bootstrap (removed)
and the carrier question left open by the code-ceremony pairing.

## The idea

Every client joins a mesh: paired clients keep WebRTC links, and any client
whose stack can accept inbound HTTP (a Mac with UPnP, a phone that got a port
mapped) advertises itself as a **server** — shorthand for "reconnection and
signaling point", nothing more. A client is connected as long as it can reach
one member of the mesh. Servers never see plaintext: everything they carry is
HPKE-sealed between the peers, so the trust required of them is zero — they
are Tor-style relays for signaling, not authorities.

## Pairing (the tiny QR)

The presenter is a server or is connected p2p to one. Its QR carries only:

- the presenter's public key
- the address of a server it can be reached through

Below the QR: the six-character code (existing ceremony, unchanged rules —
rotation, alphabet, sealed-only travel).

Recipient flow: scan → type code → talk to the named server over HTTP:

1. `GET /pair?to=<presenterFP>&from=<tempID>` — asks the server to obtain an
   offer from the presenter. If the presenter *is* the server, it answers
   locally; otherwise the server relays the request over its existing WebRTC
   link to the presenter (one hop in v1).
2. The presenter returns a fresh offer **sealed to nobody but signed into the
   session**: recipient polls `GET /mail?for=<tempID>` until it lands.
3. Recipient answers, and posts `GET /pair-reply?to=<presenterFP>&envelope=…`
   where the envelope is HPKE(presenterKey, {code, recipientKey, answerSDP}).
4. Server relays; presenter opens, checks the code, applies the answer;
   channel opens; joinAck receipt seals the code back (existing frames).

The code check makes relay tampering pointless: a server that substitutes
keys or SDP cannot produce the code, and cannot read anything.

## Reconnection (no re-pairing, ever)

Paired clients hold each other's X25519 keys. Reconnect envelopes use **HPKE
auth mode** (`HPKE.Sender(recipientKey:…, authenticatedBy: senderPrivateKey)`),
which proves the sender's key cryptographically — the receiving peer verifies
the re-offer came from the peer it already trusts, no signatures and no new
key types needed. On disconnect or IP change:

1. The mover creates a fresh offer, seals it auth-mode to the peer.
2. Hands it to any server it knows (its own listener's directory, gossiped
   during the session — the existing BootstrapDirectory carries these).
3. The peer receives it (direct if it is that server; relayed if connected to
   it; polled from the mailbox otherwise), verifies, answers the same way.

Directory gossip (already in the wire protocol) is how both sides accumulate
servers to try. Both sides try all servers they know; first exchange wins.

## The browser constraint (design around, not away)

An HTTPS page cannot fetch `http://<ip>` (mixed content). Therefore:

- Browser clients participate in mesh signaling **through their live WebRTC
  links** (relay frames), which covers relaying for others and their own
  re-signaling while at least one link survives.
- A fresh browser recipient (no links yet) cannot reach an http-only server.
  Fallback: the QR also carries the inline offer (today's format) and the
  reverse-scan / share-reply return path.
- Full browser parity later, two options: servers with real HTTPS via
  DuckDNS + Let's Encrypt (env vars already on hand), or WebTransport with
  `serverCertificateHashes` (cert hash in the QR; needs a QUIC stack in the
  native server — check Safari support before betting on it).

## What this reuses

- `Serving` + SimpleHTTPServer + UPnP + STUN + `/whoami` (dormant since the
  bootstrap removal — the listener returns, carrying only sealed signaling).
- `BootstrapDirectory` + gossip frames → server discovery.
- The code ceremony, join/joinAck, key pinning — unchanged.
- `MLSHPKE` grows an auth-mode seal/open pair.

## Capacity and server selection (2026-08-08 refinement)

A server advertises not just *whether* it can help but *how much*: its
available capacity for new connections. A Mac behind UPnP should not be
hammered by 10,000 clients the way a cloud-run instance can absorb. So the
directory record carries, per server:

- IP address, and hostname if it has DNS
- tier (ip / dns / selfSigned / ca) — whether a browser can reach it
- available capacity for new connections (a server-reported integer, decaying
  toward its own ceiling; 0 means "don't send me more right now")
- how recently it advertised (freshness), so stale servers sink in ranking

**Client selection heuristic**, applied to the known directory:

- Web clients: only ca-tier is reachable; pick the ca server with the most
  advertised capacity.
- Native clients: prefer ip-tier (mostly other native peers) to keep load off
  the HTTPS servers — but fall back to ca-tier when no native server answers
  or they are at zero capacity. A ca server advertising abundant capacity is
  used by native clients too.
- Either way, clients **ping servers in ranked order with backoff** until one
  answers, rather than all hammering the top choice — the anti-thundering-herd
  rule. A server at zero capacity is skipped, not pinged.

**How the directory is built and kept fresh:**

- Servers gossip to *other servers* over HTTP: `GET /directory` to retrieve a
  server's view, `POST /directory` to add themselves to another's. This is the
  shared server directory; it converges without any central registry.
- Servers periodically re-advertise to the servers they know (refreshing their
  freshness and current capacity).
- Clients refresh their own directory periodically — from a server over HTTP,
  or from a connected peer over the WebRTC channel (a peer relays the server
  list it holds). Clients never talk to unpaired clients.

Load stays light by construction: servers move signaling blobs, not media, and
a client only reaches a server to establish/re-establish a P2P link or to
refresh its directory. Everything else is peer-to-peer.

**Communication matrix:**

- server ↔ server: HTTP (GET/POST directory, relayed signaling)
- client ↔ server: HTTP (fetch directory, negotiate a WebRTC connection)
- client ↔ paired client: WebRTC (messages, and directory refresh relay)
- client ↔ unpaired client: never

## Order of work

1. Serving: `/pair`, `/pair-reply`, `/mail` mailbox (sealed blobs, minutes-
   lived, polled). Native client re-enables listener + advertisement.
2. Client: presenter session slots (serve an offer on request), recipient
   server-path join, tiny-QR format `#m=<presenterKeyB64url>.<serverAddr>`
   with inline-offer fallback appended when QR budget allows.
3. Reconnect: auth-mode envelopes, disconnect → try known servers loop,
   peer side accept-and-answer. Kill "connection lost" as a dead end.
4. Relay hop: forward pair/mail frames over live WebRTC links so non-server
   presenters and browsers participate.
5. HTTPS servers (DuckDNS/LE) or WebTransport, for browser first contact.
