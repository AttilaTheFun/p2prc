# The node's HTTP API (§19)

The reference node (`convo_node`) serves the endpoints of §19. Bodies are
the Part I/II wire objects; JSON where a record or list is returned.

| Method and path | Body → response |
|---|---|
| `GET /health` | `{ok, id, kind, version, site?, turn, now}` |
| `GET /v1/node` | the signed descriptor (§24) `{nodePk, operatorPk, url, site, turn, version, time, sig}` with `{id, stun, deliveryWindowMs, retentionMs, now, batchSeq}` beside it |
| `GET/POST /servers` | node discovery (§24) |
| `GET /ice?for=<client>` | STUN/TURN with short-lived credentials (§21) |
| `POST/GET /rendezvous/<box>` | rendezvous boxes (§20) |
| `POST /v1/groups/<id>/messages` / `attestations` / `republishes` | item → `Receipt` naming the open batch |
| `POST /v1/groups/<id>/fetch` | `FetchRequest` → `FetchReply` (members of a held genesis only) |
| `GET /v1/groups/<id>/attestations` | JSON `[{wire, head, contentRoot, msgCount, signerIdx, committed?}]` (signed GET, members) |
| `POST/GET /v1/groups/<id>/genesis` | `GenesisRecord` (genesis bytes ‖ carries); kept only by a home node (GET is a signed GET, members) |
| `POST /v1/groups/<id>/acks` | `Ack` → 204 |
| `POST/GET /v1/groups/<id>/blobs/<sha256>` | blob → `Receipt`; bytes |
| `POST /v1/groups/<id>/wake` | `WakeRegistration` wire → 204 (§19.1; members; an empty handle withdraws) |
| `POST/GET /v1/keypackages/<id_pk>` | `KeyPackage` → `Receipt` (group id zero); the wire |
| `POST/GET /v1/identities/<id_pk>` | `IdentityRecord` → `Receipt` (409 if older than the one held); the newest record |
| `GET /v1/items/<hash>/commitment` | `CommitmentRef` wire once its batch is published, or 404 (signed GET: members of the item's group; any signer for identity-scoped items) |
| `GET /v1/notary/<pk>/checkpoint` | the newest `WitnessedCheckpoint` held for that log (this node's, or one it witnessed) |
| `GET /v1/notary/<pk>/batches` | JSON `[{seq, root, time, count}]`: the log's entries (this node's, or a log it witnesses) |
| `GET /v1/notary/<pk>/batches/<seq>` | `CommitmentBatch` wire (own or pushed) |
| `GET /v1/notary/<pk>/batches/<seq>/proof` | `MmrProof` against the newest witnessed checkpoint |
| `POST /v1/notary/<pk>/batches` | a committing node pushing a body → 204 |
| `POST /v1/witness` | `WitnessRequest` → `Cosignature`, or 409 with `u64 size ‖ Option<WitnessedCheckpoint>` |
| `POST /v1/fraud` | `FraudProof` wire → 202 when it verifies (kept, and passed on once to the nodes this node knows) |
| `GET /v1/fraud?node=<pk>` | JSON `[hex]`: the proofs held against that node |
| `OPTIONS <any>` | 204: the CORS preflight a browser sends before a byte POST |

Every response carries `Access-Control-Allow-Origin: *`,
`Access-Control-Allow-Methods: GET, POST, OPTIONS` and
`Access-Control-Allow-Headers: Content-Type, X-Convo-Auth`, so the web
client can call any route cross-origin.

**Signed GETs** (§19): the routes marked above carry
`X-Convo-Auth: <hex pubkey> <hex time> <hex sig>`, `sig` over
`H("convo/get" ‖ method ‖ request-target ‖ time)` (`NodeAPI.getAuth`), the
time (unix ms) within six minutes of the node's clock; anything else is 401.

A signed request's `time` (fetches) must be at most `REQUEST_MAX_AHEAD` (six
minutes) ahead of the node's clock and at most `REQUEST_MAX_AGE` (an hour)
behind it, else the response is `expired`.

**The log.** Every `COMMIT_INTERVAL` (five minutes) with anything receipted,
or at `BATCH_MAX`, the node closes the open batch into its log, signs a
checkpoint, and asks witnesses to cosign it: the `--witness` URLs first,
then the healthy nodes of its directory, until it has `WITNESS_QUORUM` (2)
and one more. A checkpoint short of the quorum is retried every poll; until
it is published the batch's items have no `CommitmentRef` and are never
expired. The node then pushes the batch body to the other home nodes of the
groups it covers.

State under `CONVO_STATE_DIR`: `node.key` (0600), `mailbox/` (items with
their receipts, written before the receipt goes out; blobs; KeyPackages;
identity records; geneses; the log `batches/<seq>.bin` with each batch's
time, the open batch `batches/open.bin`, the newest checkpoint
`batches/checkpoint.bin`; foreign batch bodies; the logs it witnesses
`witness/<pk>.bin`; fraud proofs `fraud/<pk>/`; acks), `servers.json`,
`wakes.bin`. Keep it on a durable volume (a disk, or a Cloud Storage bucket
mounted on Cloud Run): a receipt for bytes that were lost is F1, and a batch
published without a receipted item is F4 (§17). Run one instance per key:
two writers to one log sign two histories, which is F6. The node enforces it
through `owner` in the state directory: a starting instance claims it, waits
`CONVO_TAKEOVER_SECONDS` (15) before reading its state, and an instance that
finds a newer claim answers writes with 503 and exits. On Cloud Storage FUSE
mount with `metadata-cache-ttl-secs=0` so the claim is seen at once.

Ports: HTTP on `PORT` (8080), STUN/TURN on 3478 UDP+TCP, relay sockets on
18100–18199 UDP. TURN from a service instead of the built-in relay:
`CLOUDFLARE_TURN_KEY_ID` + `CLOUDFLARE_TURN_API_TOKEN` (Cloudflare Realtime
TURN), or `CONVO_TURN_URLS` with `CONVO_TURN_USERNAME` +
`CONVO_TURN_CREDENTIAL` or `CONVO_TURN_SECRET` (coturn); `CONVO_STUN_URLS`
adds STUN. The relay doesn't start when a service is named.

Environment: `PORT`, `CONVO_PUBLIC_URL`, `CONVO_SITE_URL`, `CONVO_SEEDS`,
`CONVO_NODE_ID`, `CONVO_STATE_DIR`, `CONVO_WITNESSES`, `CONVO_OPERATOR_PK`,
`CONVO_COMMIT_INTERVAL_MS`, `CONVO_TAKEOVER_SECONDS`, `CONVO_STATE_OBJECT_STORE` (1 on Cloud Storage FUSE), and the TURN variables above
(`convo_node --help`).
