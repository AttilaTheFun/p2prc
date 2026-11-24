# The Convo Protocol — Specification v2.0 (draft)

*An open protocol for distributed, end-to-end-encrypted group messaging:
messaging, node accountability, transport, and how to run a node.*

Convo is durability, consistency and accountability for end-to-end-encrypted
messaging over WebRTC, with no central server.
Conversations are append-only DAGs of author-signed, MLS-encrypted messages.
Members agree on history by signing heads. Independent nodes store and
forward for offline members, and **commit every item they accept to a
public, witnessed log in their next batch**, so a node that drops or rewrites
what it promised is caught by a proof anyone can check. Groups are
immutable and change by forking; unrecoverable history becomes a visible side
branch rather than a hole. Anyone can run a node, self-hosted or on hosted
services' free allowances (§26 says how far they go).

**Status.** Draft for the reference implementation and for publication.
Parts I–III and Appendices A–B are normative; Part IV and Appendices C–E are
guidance.

**Version 2.** Each node's commitments are **checkpoints of its log,
cosigned by independent witnesses** (§6, §11). Nodes describe themselves with
signed descriptors and find each other by gossip (§24); identities name their
nodes in signed records (§13.2). Fraud proofs (§17) are portable evidence that
every client acts on. Time is Unix milliseconds throughout.

**Core invariant:** the history of a group is its DAG (§4), agreed by member
attestations (§5) and committed item by item to its home nodes' witnessed
logs (§6). Nothing outside the group's members decides what the history *is*;
the logs only prove what existed, and when.

**How to read it.** Part I is the messaging protocol (identities, genesis,
messages, DAG, attestation, commitment, forks, the witnessed log, sync,
hosts). Part II is how nodes are held accountable (receipts, signed responses,
acks, fraud proofs). Part III is transport. Part IV is running a node.
Appendix A pins wire encoding; B lists parameters; C suggests a package
layout; D collects implementation notes; E records why.

---

## 0. Deliverables and scope

- **Parts I–III and Appendices A–B** are normative. **Part IV** and
  **Appendices C–E** are guidance.
- **The reference implementation** is open-source Swift, in the
  `convo_protocol` repository. It ships as a Swift package plus:
  - a **CLI client** exercising the full protocol (create and fork groups,
    send, sync, attest, republish, fetch, ack, check commitments, report
    fraud);
  - a **node**, distributed as an **OCI container**, implementing Part II and
    the witness role of §11 (mailbox, relay, commitment, witnessing,
    rendezvous, STUN and TURN, optional archive).
- **Conformance** is defined by the test vectors of Appendix A.6, which the
  reference implementation generates and checks in. Where this document and
  the reference implementation disagree, the discrepancy is a bug in one of
  them and must be resolved explicitly; neither silently wins.
- **The Convo app** consumes the package and provides the user interface. It
  is a separate, proprietary codebase and out of scope here: an open
  protocol, any number of clients. Everything a UI needs (message states,
  branch structure, host health) is exposed by the package as data;
  rendering belongs to the app, subject to the normative display rules here
  (currently only §9.4).

# Part I — Messaging protocol

## 1. Cryptographic primitives, keys, encoding

| Item | Choice |
|---|---|
| Hash `H` | SHA-256. Every hash and signature preimage starts with a domain tag (Appendix A). |
| Signatures | Ed25519. |
| Encoding | **borsh** (Appendix A.1): one canonical encoding per value, and a Swift encoder is a few dozen lines. |
| Time | Unix milliseconds (`u64`), from each party's own clock; advisory except where a section bounds skew. |
| **Identity** | An Ed25519 keypair `(id_sk, id_pk)`, derived from a **recovery phrase**: 12 or 24 words from the standard English 2,048-word list (`vectors/wordlist.txt`), the last word carrying a SHA-256 checksum of the entropy, as the common recovery-phrase format defines it. Its seed is `s = PBKDF2-HMAC-SHA512(password = the phrase's NFKD UTF-8 bytes, salt = "mnemonic", iterations = 2048, length = 64)`, and `id_sk = HKDF-SHA256(ikm = s, salt = "convo", info = "convo/identity/v1")` truncated to the 32-byte Ed25519 seed. **How the key is persisted and unlocked is the implementer's decision**: the reference app shows the recovery phrase once and keeps the key in the platform keychain; passkeys, Face ID or Touch ID are optional. The protocol requires only that `id_sk` signs Ed25519 over arbitrary bytes. |
| Per-group signing key | `gk = Ed25519 keypair from HKDF-SHA256(ikm = id_sk, salt = genesis.salt, info = "convo/gk/v1")`. Signs messages and attestations in this group only; nodes and other members see `gk`, never `id_pk`, except where the identity reveals it (§2, §13.2). |
| MLS leaf key | `hpke_sk[n] = X25519 key from HKDF-SHA256(ikm = id_sk, salt = n as u32 LE, info = "convo/hpke/v1")`; index `n` advances on `HPKE_ROTATION` or after use; expired indices' keys are deleted (forward secrecy for past invites). |
| Payload encryption | **MLS (RFC 9420)**, one MLS group per Convo group, `group_id = genesis.salt`, ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; a fork is a new MLS group. Members issue self-Update commits every `MLS_UPDATE_INTERVAL` (§2). |
| Node key | An Ed25519 keypair per node deployment. `node_pk` signs receipts, responses, checkpoints, witness cosignatures and the node's descriptor. |

---

## 2. Group genesis (immutable)

```
Genesis {
  version:                    u8          // = 3
  salt:                       [u8; 32]    // random; also the MLS group_id
  members:                    Vec<[u8;32]>  // gk pubkeys; index = member_idx; 1..=64
  quorum:                     u8          // attestations that make a head `attested` (§5); 1..=|members|
  max_parents:                u8
  max_payload:                u32         // bytes
  max_uncommitted_republish:  u8
  home_nodes:                 Vec<[u8;32]>  // node pubkeys (§24); 1..=16 (§13.1)
  parent:                     Option<ParentRef>
  carry:                      Vec<(u8, u8)>   // (parent_idx, child_idx) for identities in both
  reason:                     u8          // 0 root, 1 membership, 2 recovery, 3 key rotation, 4 other, 5 host change
}

ParentRef {
  group_id:   [u8; 32]
  head:       [u8; 32]        // the fork point: a message hash in the parent
  source:     CommitmentRef   // §6: a committed parent ATTESTATION on `head` (carries content_root)
}

group_id = H("convo/genesis" ‖ borsh(Genesis))
```

`quorum` is what members and clients treat as "the group agrees" (§5).
Nothing waits for it.

**KeyPackage.** What an identity publishes so others can add it to a group:

```
KeyPackage {
  version:      u8          // = 2
  identity_pk:  [u8; 32]    // id_pk
  hpke_index:   u32         // n (§1)
  hpke_pk:      [u8; 32]    // X25519 public key hpke_pk[n]
  not_after:    u64         // unix seconds; a creator must not use an expired KeyPackage
  name:         String      // display name, advisory
  sig:          [u8; 64]    // Ed25519(id_sk, H("convo/kp" ‖ borsh(fields)))
}
```

A node keeps the newest KeyPackage per identity (highest `hpke_index`, then
latest `not_after`) and drops expired ones. `not_after` is at most
`KP_LIFETIME` after publication. Identities publish KeyPackages to the nodes
their identity record names (§13.2).

**Genesis handshake (via MLS).** Frames are borsh with a leading tag byte and
travel through rendezvous boxes (§20) or any data channel; the creator's
frames go to `box(salt, recipient_id_pk)`, members' replies to
`box(salt, creator_id_pk)`.
1. The creator picks `salt`, fetches each member's KeyPackage from the nodes
   of the member's identity record (§13.2), builds the MLS group with
   `group_id = salt` and the roster (creator first), creates the commit that
   adds everyone, and sends **`invite` (tag 0)** =
   `salt ‖ Vec<KeyPackage> ‖ commit ‖ Proposal{quorum, max_parents, max_payload, max_uncommitted_republish, home_nodes, parent, reason}`
   to every member.
2. Each member checks it is on the roster and that `home_nodes` is within its
   bounds (§13.1; otherwise it drops the invite and is not in the group),
   applies the commit, derives `gk` from `salt`, and sends **`announce`
   (tag 1)** = `id_pk ‖ sealed("gk-announce:" ‖ hex(gk_pk))`, the payload an
   MLS application message of the new epoch.
3. The creator assembles `members` (creator at index 0, others in the order
   announced), fixes `carry` from identities present in both the parent roster
   and this one, and sends **`genesis` (tag 2)** =
   `sealed("genesis:" ‖ hex(borsh(Genesis))) ‖ Vec<id_pk>` (identities in
   member order). Every member verifies its own `gk` pubkey is at the claimed
   index, that `home_nodes` matches the proposal, and computes `group_id`.
4. A member of the parent group sends **`carry` (tag 3)** =
   `parent_idx ‖ sig` over `H("convo/fork" ‖ parent_group_id ‖ group_id)`
   (§9.3). Carry signatures are gossiped to all child members and stored by
   home nodes alongside the genesis.

For a fork, the creator's invite (the `Proposal`) also carries **the parent
attestation the `ParentRef` cites** (`Attestation ‖ att_sig`), so each joiner
checks, before announcing, that it is over the fork point `head` and signed by
a member of the parent roster (§9.3); the `CommitmentRef` itself is resolved
through the citing node (§6) and may be resolved later if that node is
unreachable at handshake time.

The group now exists. Members and home nodes hold the genesis bytes; anyone
can verify a claimed `group_id` by rehashing them. The group's public trace is
the set of commitment batches (§6) that include its items, as hashes only.

Membership never changes, but the MLS epoch does: each member issues a
self-**Update** commit at least every `MLS_UPDATE_INTERVAL` of its own
activity (Appendix B), as an MLS handshake message carried in a `kind = 1`
control message (§3.1), so that a compromised member key stops decrypting new
traffic once the others have processed the next commit (post-compromise
security). Update commits change no roster entry and no Convo state; a client
that falls behind processes them in order as part of sync. A client stores
each epoch's secrets and its own sender generation to restore the group
without replaying commits. A commit also carries its leaf secret HPKE-sealed
to the author's own leaf key, so a second device of the same identity follows
the rotation (§D.9).

A member who never announces is not in the group. Changing membership means
forking (§9).

---

## 3. Message

```
Message {
  version:    u8            // = 1
  group_id:   [u8; 32]
  author_idx: u8
  seq:        u64           // per-author, strictly increasing within this group
  parents:    Vec<[u8;32]>  // 1..=max_parents; first message from an author: [group_id]
  ts:         u64           // unix ms, advisory only
  kind:       u8            // 0 chat, 1 control, 2 republish (§9.4)
  payload:    Vec<u8>       // MLS PrivateMessage ciphertext; ≤ max_payload
}
msg_hash = H("convo/msg" ‖ borsh(Message))
msg_sig  = Ed25519.sign(gk[author], msg_hash)
```

### 3.1 Payload framing

`payload` is always an MLS application message. Its plaintext, by `kind`:

| `kind` | Plaintext |
|---|---|
| 0 chat | the UTF-8 text; `"react:" ‖ hex(borsh(Reaction))` and `"attach:" ‖ hex(borsh(Attachment))` for reactions and attachments (§3.2) |
| 1 control | `"host-add:" ‖ hex(node_pk)` (§13.1 in-band addition); `"mls-commit:" ‖ hex(commit bytes)` for an Update commit (§2), **not** sealed, since it is what advances the epoch; other control messages are reserved |
| 2 republish | `"republish:" ‖ hex(borsh(Republish))` (§9.4) |

The sealed message is carried as
`0x00 ‖ epoch:u64 ‖ sender:String ‖ generation:u32 ‖ Vec<u8> ciphertext` (the
reference implementation's compact PrivateMessage); a full RFC 9420
PrivateMessage may replace it later, the tag byte distinguishing them.

- Append-only. Retractions and edits are `kind = 1` control messages
  referencing the target `msg_hash` inside the encrypted payload.
- Duplicate `seq` from one author is equivocation; both are kept and shown as
  such.
- Mailboxes store `(msg_hash, borsh(Message), msg_sig)` and never see
  plaintext.
- Attachments are not in the payload. It carries a content hash and a key;
  the sealed blob lives in mailbox blob storage (§13, §3.2).

### 3.2 Reactions and attachments

```
Reaction   { target: [u8;32], emoji: String, remove: bool }
Attachment { blob: [u8;32], key: [u8;32], mime: String, width: u32, height: u32, size: u64, caption: String }
```

A reaction folds per `(target, author, emoji)` in canonical order (§4); a
later `remove` takes an earlier one back. An attachment names sealed bytes
(ChaCha20-Poly1305, `nonce ‖ ciphertext ‖ tag`, a fresh key per attachment)
that the sender put at the group's home nodes as a blob (§19); `blob` is the
SHA-256 of the sealed bytes. Both are sealed like chat, so nodes see only the
`kind` byte.

---

## 4. DAG, linearization, content root, validity

Messages form a DAG via `parents`. A **head** is a message with no known
children.

**Canonical order** under a head: Kahn topological sort where, whenever
several messages are ready, the one with the lexicographically smallest
`msg_hash` is emitted first. `ts` never affects order.

**`content_root(head)`** is the Merkle root over the canonical order
(Appendix A.3), leaf `H("convo/leaf" ‖ borsh(Message) ‖ msg_sig)`. It is not
computable from `head` alone; it supports inclusion proofs.

**There is no locked prefix.** History is the DAG. Concurrent branches merge
by construction; no message is ever rebased except across a fork (§9.6). A
message's durability comes from being **committed** (§6), its agreement from
being **attested** (§5); neither changes its position.

**DAG validity rules.** A head is valid only if every message under it
satisfies:
- `msg_sig` verifies against `members[author_idx]`; `group_id` matches;
- `1 ≤ |parents| ≤ max_parents`; all parents resolvable; acyclic;
- `len(payload) ≤ max_payload`;
- **republish cap:** per author, the count of `kind = 2` messages under the
  head that are not yet committed is ≤ `max_uncommitted_republish`.

Clients never attest an invalid head and never build on one. Nodes do not
check these rules (§9.8).

---

## 5. Head attestation

```
Attestation {
  group_id:      [u8; 32]
  head:          [u8; 32]
  content_root:  [u8; 32]    // content_root(head), §4
  msg_count:     u64
  signer_idx:    u8
}
att_sig = Ed25519.sign(gk[signer], H("convo/att" ‖ borsh(Attestation)))
```

- An attestation is an **item**: it is sent to home nodes, receipted and
  committed (§6) like a message. Its commitment is what makes a group's
  `content_root` provable, the basis for republish proofs (§9.4) and fork
  points (§9.3).
- Signing a head transitively attests every ancestor. A newer attestation by
  the same signer on a descendant supersedes it.
- A head is **`attested`** (client state) once ≥ `quorum` distinct members'
  attestations cover it. Nothing waits for it.
- A client that has not fully synced and validated a head must not sign it.
- Clients attest after `ATTEST_MSGS` new messages or `ATTEST_INTERVAL`,
  whichever comes first (Appendix B).

---

## 6. Commitment

A **commitment batch** is a node's signed, sorted Merkle tree over the hashes
of every item it receipted since its previous batch. Items are messages,
attestations, republishes, KeyPackages, identity records and blobs: anything
§14 receipts.

```
CommitmentBatch {
  node_pk:    [u8;32]
  seq:        u64
  prev_root:  [u8;32]
  leaves:     Vec<[u8;32]>     // item hashes, strictly ascending, ≤ BATCH_MAX (Appendix B)
  sig:        [u8;64]          // over H("convo/cbatch" ‖ node_pk ‖ seq ‖ prev_root ‖ root)
}
root = SortedMerkleRoot(leaves)   // gap-leaf tree, Appendix A.5
```

**The node's log.** Every node keeps an append-only accumulator (an MMR,
Appendix A.4) over its batches, leaf `i` =
`H("convo/cbatch-leaf" ‖ root_i ‖ time_i ‖ count_i)` for batch `seq = i`. After
closing a batch the node signs a **checkpoint** of its log and has it
cosigned by witnesses (§11):

```
Checkpoint {
  node_pk:    [u8;32]
  seq:        u64                 // the newest batch; the log holds seq + 1 batches
  root:       [u8;32]             // that batch's root
  count:      u64                 // that batch's item count
  time:       u64                 // unix ms when the node closed it
  mmr_peaks:  Vec<[u8;32]>        // the log's peaks after appending it (Appendix A.4)
  sig:        [u8;64]             // over H("convo/ckpt" ‖ borsh(fields above))
}

Cosignature {
  witness_pk: [u8;32]
  time:       u64                 // the witness's clock when it cosigned
  sig:        [u8;64]             // over H("convo/cosign" ‖ H("convo/ckpt" ‖ borsh(Checkpoint without sig)) ‖ time)
}

WitnessedCheckpoint { checkpoint: Checkpoint, cosigs: Vec<Cosignature> }
```

A batch is **published** when a checkpoint naming it, or any later checkpoint
of the same log, carries cosignatures from at least `WITNESS_QUORUM` distinct
witnesses other than the node (§11). The node keeps every batch body and
pushes it to the home nodes of every group with an item in it (§13).

**The rule.** A receipt names the batch the node is currently assembling,
`batch_seq = s` (§14). **The item must be a leaf of batch `s`.** Not `s+1`,
not later: a receipt is a promise about a specific batch, and the node
controls both the receipt and the batch, so it has no excuse. A node that
publishes batch `s` without the item is caught by F4 (§17); a node that never
publishes batch `s` is silent (§17).

**`CommitmentRef`**, how an item's commitment is cited:
```
CommitmentRef {
  node_pk:     [u8;32]
  batch_seq:   u64
  batch_root:  [u8;32]              // the batch's root
  count:       u64                  // the batch's item count
  time:        u64                  // the batch's time, as its checkpoint has it
  item_hash:   [u8;32]
  neighbor:    [u8;32]              // the gap leaf's other bound, Appendix A.5
  item_proof:  GapProof             // gap-leaf inclusion path to batch_root (Appendix A.5)
  batch_proof: MmrProof             // batch leaf → the log's peaks at `checkpoint` (Appendix A.4)
  checkpoint:  WitnessedCheckpoint  // of this log, with seq ≥ batch_seq
}
```
Resolving a `CommitmentRef`: (1) verify the checkpoint's signature against
`node_pk` and that it carries `WITNESS_QUORUM` valid cosignatures from
distinct witnesses other than `node_pk`; (2) form the batch leaf from
`batch_root, time, count` and verify `batch_proof` against
`checkpoint.mmr_peaks` (size `checkpoint.seq + 1`); (3) form the gap leaf
from `item_hash` and `neighbor` and verify `item_proof` against `batch_root`.
The result: *this item existed, held by this node, no later than the
witnesses' cosigning time.* A `CommitmentRef` stored long term (in a genesis
or a `Republish`) stays verifiable with the checkpoint it carries, because
the checkpoint is self-contained and its cosignatures never expire.

**Message states** (client):

| State | Meaning |
|---|---|
| `sent` | author-signed, receipted by ≥ 1 home node |
| `committed` | a `CommitmentRef` resolves for it (any home node); expected within `COMMIT_INTERVAL` of the receipt |
| `attested` | under a head with ≥ `quorum` attestations (§5); independent of `committed` |
| `abandoned` | committed in a group that was forked away from, past the fork point (§9) |

`committed` is the durability guarantee, and it is universal: every item,
every group, every member, at no cost to the member.

---

## 7. Commitment cadence

- A node closes and checkpoints a batch every `COMMIT_INTERVAL` if it has
  receipted anything since the last one, and immediately when the current
  batch reaches `BATCH_MAX` items. Batch `s` closes when the node stops
  issuing receipts against it; the next receipt names `s+1`.
- A node may close several batches per interval; it may not skip: batch `s+1`
  extends the log that holds batch `s` (`prev_root`).
- Clients expect a receipt's item to be committed within
  `COMMIT_INTERVAL + COMMIT_GRACE`; past that they mark the node unhealthy
  (§13.1), and if batch `s` *has* been published without the item, they
  report F4 (§17).
- **No quorum wait, no window.** Commitment is per item and per node; it
  depends on no one but the node and its witnesses.

---

## 8. Client re-entry

Fetch the DAG since your last known heads from home nodes and members (§12);
verify every message; recompute `content_root` for any attestation you hold
and check the node-served `CommitmentRef`s for what you sent while away;
attest the current head. If the group has an official child (§9.3) and you
are a member of it, migrate.

---

## 9. Forks

### 9.1 Definition
A child group whose genesis has a `ParentRef` naming a fork point `head` in the
parent and a `CommitmentRef` to a committed parent attestation on that head.
Creating and moving to it means leaving the parent. The parent persists for
whoever stays.

| Reason | Child membership | Fork point |
|---|---|---|
| Membership change | parent ± members | the latest attested head |
| Recovery (§9.2) | same identities | the latest committed head the forker holds full data for |
| Key rotation | same identities, new key(s) | the latest attested head |
| Host change (§13.1) | same identities, new `home_nodes` | the latest attested head |

MLS: the child is a new MLS group with `group_id = child.salt`. Added members
join via KeyPackages; removed members are simply not added.

### 9.2 Recovery fork
A **syncing** client (missing data under a committed head; may read and send,
may not attest) issues `SyncRequest`s (§12) to members and home nodes. If they
go unanswered for `RECOVERY_PATIENCE`, the client forks with the same
identities and a `ParentRef` at the latest head it holds and can cite a
commitment for. Parent items committed past that point are the **abandoned
range**.

### 9.3 Official vs. splinter
- Let `carry` be the identities in both parent and child. Carry members sign
  `H("convo/fork" ‖ parent_group_id ‖ child_group_id)`. A child is
  **official** when valid carry signatures ≥ `min(parent.quorum, |carry|)`
  (min 1). Clients verify this from the signatures gossiped at handshake (§2).
- An official child **binds only child members**: they auto-migrate and stop
  attesting to the parent. Parent members not in the child ignore it and
  continue.
- Fewer signatures make a splinter: a fully valid group, not official; other
  clients surface it as "X moved to a new conversation."
- **Parent verification.** Every client joining the child resolves the
  `ParentRef`'s `CommitmentRef` (§6) and checks the cited attestation is over
  `head` and signed by a parent member. A `ParentRef` that does not resolve
  makes the genesis invalid; members refuse to announce.

### 9.4 Republishing an abandoned range
The abandoned range is what the parent **committed** past the fork point:
every message that appears in a commitment batch (§6) and is not under the
fork point's head. A holder of it who joins the child may republish it as
`kind = 2` messages (messages that were never committed are not history and
are rebased instead, §9.6):

```
Republish {
  parent_group_id:   [u8; 32]
  source:            CommitmentRef        // §6: a committed ATTESTATION of the parent
  attestation:       Attestation          // the cited attestation itself (carries content_root), with
  att_sig:           [u8; 64]             //   its signature, so a child member need not reach the parent's nodes
  original:          Message
  original_sig:      [u8; 64]
  inclusion_proof:   Vec<([u8;32], u8)>   // (sibling, side 0=left/1=right), message leaf → content_root
}
```
carried as the (MLS-encrypted) payload of an ordinary child message authored
by the republisher.

Verification: `H("convo/att" ‖ borsh(attestation))` equals
`source.item_hash`; `att_sig` verifies against the parent's
`members[attestation.signer_idx]`; the `CommitmentRef` resolves (§6), so the
attestation is provably in a witnessed batch; its `content_root` is the root;
`original_sig` verifies against the parent's `members[original.author_idx]`;
`inclusion_proof` verifies the message under that root. Failing any check, it
is displayed as an ordinary message from the republisher, never as history.
Clients note in the side branch how many distinct parent members'
attestations cover the range (one committed attestation proves existence;
≥ `parent.quorum` proves agreement).

**Forcing:** republished messages are real DAG nodes under the child's head,
so every attesting member must hold them, mailboxes deliver them, and home
nodes commit them. **Dedup:** by inner `msg_hash`, first committed wins.
Partial republish is fine; each proof stands alone. Rate-limited by
`max_uncommitted_republish`.

**Display (normative minimum).** Verified republished messages are legitimate
history and **must be viewable**: an implementation may collapse,
de-emphasize, or move them out of the main line, but may not hide them with
no way to reach them. They must be rendered distinguishably from the child's
canonical line (a side branch rooted at the fork point, ordered by the
parent's canonical rule, attributed to the original author, and labeled with
who republished them). The reference CLI shows them as an indented branch
with a `[republished by X]` marker.

### 9.5 Add / remove semantics
- Added member: holds only the child's MLS state; sees the child from the fork
  point plus a marker that history exists. Republished parent messages are
  readable only if the parent's MLS secrets are deliberately exported to them
  (an app decision; default no).
- Removed member: keeps the parent's MLS state and can read and post there
  forever. Removal is everyone else leaving.
- Key rotation: fork with a new `gk` and MLS leaf for the rotating member.

### 9.6 Messages in flight at fork time
Not in the child. Authors rebase: each of their own not-yet-committed chat
messages is re-sent as a new child message (new `seq`, parents on the child's
head, the same plaintext).

### 9.7 Competing forks
Two official children of one parent can exist under partition; both are valid
and nothing ranks them. Clients show both, and members decide which to follow.

### 9.8 Unsound committed head
Commitment is not validity: a node commits whatever it receipts. A committed
head that fails §4 is simply not built on or attested by honest clients;
nothing else is needed.

---

## 10. Wire flow summary

```
send:     author signs Message → WebRTC to online peers → every healthy home node (receipt names batch s, §14)
commit:   each home node closes batch s, checkpoints its log, gets WITNESS_QUORUM cosignatures (§11), within COMMIT_INTERVAL
attest:   member syncs + validates → signs (head, content_root) → sent as an item → committed like any other
fork:     new genesis with ParentRef{head, CommitmentRef} + carry sigs → gossip
recover:  SyncRequest unanswered → recovery fork; holders stay, or join + republish (proofs via CommitmentRef)
catch:    receipt(X, s) + witnessed batch s without X → F4 → every client drops the node (§17)
```

---

## 11. The witnessed log

Every node is a **log** (its batches, §6) and a **witness** for other nodes'
logs. Witnessing makes a node's history append-only and pins it in time, as
certificate transparency logs are kept honest, so the node cannot later
present a different past to different people.

**Witnessing a checkpoint.** After checkpointing batch `s`, the node sends
`POST /v1/witness` to witnesses of its choice (§24: healthy nodes, preferring
other operators and sites) with
`WitnessRequest { checkpoint: Checkpoint, from_seq: u64, leaves: Vec<([u8;32] root, u64 time, u64 count)> }`:
the batch leaves appended since the witness last saw this log (`from_seq` is
the first one sent; `0` for a witness new to the log). The witness:
1. verifies `checkpoint.sig` against `node_pk`;
2. appends the leaves to the copy of the node's log it keeps (only the leaf
   triples, about 48 bytes per batch) and requires the result's peaks to equal
   `checkpoint.mmr_peaks` and its last leaf to equal
   `(checkpoint.root, checkpoint.time, checkpoint.count)`;
3. requires `checkpoint.seq` to be greater than the last it cosigned for this
   log, and `checkpoint.time` to be within `WITNESS_SKEW` of its own clock and
   not earlier than the previous checkpoint's;
4. answers with its `Cosignature`, and stores the checkpoint as this log's
   latest.

A witness that already holds a different checkpoint for the same
`(node_pk, seq)`, or whose stored leaves conflict with the request, refuses
(409, with the size of the log it holds and its latest checkpoint, so the node
can resend from the right `from_seq`). Two conflicting checkpoints signed by one node are F6
(§17): the witness publishes them. A witness that does not know enough of the
log answers 409 with the size it knows, and the node resends from there.

**Independence.** Clients accept cosignatures from witnesses they hold as
independent of the node: a different `node_pk`, and a different operator key
and site in its descriptor (§24). `WITNESS_QUORUM` (Appendix B) is the
minimum; a node gathers more when it can. A client may require more, or
particular witnesses, for its own groups.

**Gossip.** Nodes serve each log's latest witnessed checkpoint they hold
(`GET /v1/notary/<node_pk>/checkpoint`, their own or one they witnessed). A
client that sees two checkpoints of one log with the same `seq` and different
contents, or one whose peaks don't extend another's, holds F6.

---

## 12. Sync protocol

```
SyncRequest {
  group_id:   [u8;32]
  have_head:  [u8;32]           // latest head the requester holds full data for (all zeros if none)
  want_head:  [u8;32]
  missing:    Option<Vec<[u8;32]>>
  nonce:      [u8;16]
  time:       u64
  requester_idx: u8
  sig:        [u8;64]           // over H("convo/sync" ‖ borsh(fields))
}
```
Sent over signaling to online members (prefer recent attestation signers) and
to home nodes and archives. Responders stream `(borsh(Message), msg_sig)` items
over a WebRTC data channel or from the mailbox; the requester verifies each
and finally `content_root`. Batching, ordering and resumption are
implementation choices; each item is independently verifiable.

---

## 13. Mailbox / relay / archive responsibilities

**Storage is implementation-defined.** This document does not say how a node
stores items. It defines the obligation: from the moment a node signs a
receipt (§14) until that receipt's `retain_until`, the node must serve the
item to any authorized requester, and the item must be a leaf of the batch the
receipt names (§6). Losing an item after receipting it is F1 if the node signs
a non-serving response and F4 if the node publishes the batch without it.
Persist before you sign.

- Store messages, attestations, republishes, KeyPackages, identity records and
  blobs by `group_id` or identity; index by `msg_hash`, `(author_idx, seq)`,
  and batch. Hold the genesis bytes and carry signatures of every group hosted
  (§2). The endpoints are §19.
- Run STUN and TURN, or hand out credentials for a TURN service (§21).
- Serve `SyncRequest`s, blob fetches and `CommitmentRef` construction
  (`/items/<hash>/commitment`) to group members only.
- Commit every receipted item in the batch its receipt names (§6–7); persist
  every batch body; push each body to the home nodes of the groups it covers
  so proofs are available from any of them; serve the log (§19).
- Witness other nodes' logs (§11); keep and serve fraud proofs (§17).

**Retention (hot):** keep everything until its batch is published (an item is
never dropped before the batch its receipt names is witnessed) **and** every
member has attested above it, or an archive has acknowledged it and
`T_ARCHIVE` has passed; after a re-upload hold for `T_REUPLOAD`; never below
any outstanding receipt's `retain_until`.

**Archive (optional):** keeps everything for hosted groups; can produce any
`CommitmentRef` on request and prove completeness against `content_root`.

### 13.1 Host selection

**Working set.** A group's hosts are `genesis.home_nodes`. Senders publish
every message and attestation to **every healthy host** in the set; blobs to
`R_BLOB` healthy hosts. Readers subscribe to every host in the set. Because the
set is in genesis, every member, including one who has never read a message,
knows where to write and read. Every home node commits what it receipts (§6),
so a message sent to three home nodes appears in three batches; that
redundancy is intended.

**Health (per client, local).** A host is *unhealthy* if any of:
- a valid fraud proof against it is known (§17): permanently;
- no receipt, or an unsigned or invalid response, for `HOST_UNHEALTHY_AFTER`
  of sustained attempts (longer than a routine restart or deploy, so a rolling
  upgrade does not look like an outage);
- it fails a receipted-item fetch after `deadline` twice in a row;
- a receipted item is not committed within `COMMIT_INTERVAL + COMMIT_GRACE`.
Health recovers automatically, except after a fraud proof, once the host
responds correctly again. Health scores are the client's own; nothing about
them is shared or agreed.

**Client bounds (configuration, not spec constants).**

| Bound | Constraint | Purpose |
|---|---|---|
| `MIN_HEALTHY_HOSTS` | ≥ 2 | Below this the client forks. At least 2, so the fork can be coordinated through a still-healthy host before the last one disappears. |
| `MIN_TOTAL_HOSTS` | > `MIN_HEALTHY_HOSTS` | A client will not join or create a genesis with fewer hosts than this; otherwise the group would sit at the fork threshold and fork repeatedly. |
| `MAX_TOTAL_HOSTS` | ≥ `MIN_TOTAL_HOSTS`, ≤ 16 | A client will not join a genesis with more hosts than this; it bounds the write cost a creator can impose. |

Clients enforce their bounds at handshake time (§2 step 3) and when creating a
fork.

**Host-change fork.** When a client's count of healthy hosts falls below
`MIN_HEALTHY_HOSTS`, it creates a fork with `reason = 5`: same identities,
same parameters, `home_nodes` = the still-healthy hosts plus enough new healthy
candidates to reach `TARGET_TOTAL_HOSTS` (never below `MIN_TOTAL_HOSTS`),
drawn in order from `RV(group_id, 16)` skipping unhealthy ones. To reduce
competing forks, a client waits `member_idx × FORK_STAGGER` after crossing the
threshold; if a qualifying host-change fork appears meanwhile, it joins that
instead. Competing forks resolve per §9.7.

**Rendezvous fallback.** `RV(key, k)` is the top `k` nodes of the client's
directory (§24) that are healthy and not proven faulty, ranked by
`H("convo/rv" ‖ key ‖ node_pk)` ascending. Directories differ between clients,
so `RV` is a best-effort meeting point, not a guarantee; rendezvous hashing
keeps it stable as nodes come and go. A client that finds **zero** healthy
hosts in `home_nodes` publishes and reads at `RV(group_id, k_rv)` until a
host-change fork lands. Forking clients draw new host candidates from
`RV(group_id, ·)`.

**In-band additions.** A member may announce an additional host in a
`kind = 1` control message; recipients add it to their read set (and may write
to it). Additions do not change genesis; removals and the authoritative set
change only by fork.

### 13.2 Identity records

An identity names the nodes that hold its KeyPackages and receive its
invitations, as a signed record:

```
IdentityRecord {
  version:   u8                      // = 1
  id_pk:     [u8;32]
  nodes:     Vec<NodeRef>            // 1..=8, in order of preference
  updated:   u64                     // unix ms; the newest record wins
  sig:       [u8;64]                 // Ed25519(id_sk, H("convo/idrec" ‖ borsh(fields)))
}
NodeRef { node_pk: [u8;32], url: String }
```

An identity publishes its record to every node it names and to
`RV(id_pk, k_rv)`, and its KeyPackages to the nodes it names. A record is
public: it reveals which nodes an identity uses, as a profile's relay list
does elsewhere. Clients learn records from invitation links and QR codes
(which carry the record), from contacts, and from `RV(id_pk, ·)`. A client
keeps the newest valid record per identity.

---

# Part II — Node accountability

## 14. Receipts

Issued by a node on accepting any item (message, attestation, republish,
KeyPackage, identity record, blob):

```
Receipt {
  node_pk:        [u8;32]
  group_id:       [u8;32]
  item_hash:      [u8;32]
  content_digest: [u8;32]   // SHA-256(bytes as received), untagged, for every item kind
  batch_seq:      u64       // the batch this item WILL be a leaf of (§6)
  batch_prev:     [u8;32]   // the root of batch_seq − 1 in the node's log (zeros for the first)
  received:       u64       // unix ms
  deadline:       u64       // received + DELIVERY_WINDOW
  retain_until:   u64       // ≥ deadline + MIN_RETENTION
  sig:            [u8;64]   // over H("convo/rcpt" ‖ borsh(fields))
}
```
The sender verifies `content_digest` equals the digest of what it sent and
**rejects the receipt otherwise** (treated as no receipt). Ed25519 signatures
are not assumed deterministic, so the digest is over the exact bytes sent.
Clients treat no receipt within `RECEIPT_TIMEOUT` as not delivered and retry
another node. Clients keep receipts until the item is `committed` and
`retain_until` has passed. A node that already holds identical bytes returns
its existing receipt, including the original `batch_seq`.

`batch_prev` pins the receipt in the node's log: batch `batch_seq − 1` with
that root is in the log (a witnessed checkpoint proves it), so batch
`batch_seq` is the next one, and a node cannot later claim the receipt meant
some other batch.

## 15. Fetch requests and signed responses

```
FetchRequest {
  requester_pk:  [u8;32]       // gk of a member
  group_id:      [u8;32]
  want:          enum { Item([u8;32]), Range([u8;32] since_head, [u8;32] head), Blob([u8;32]) }
  nonce:         [u8;16]
  time:          u64
  sig:           [u8;64]       // over H("convo/fetch" ‖ borsh(fields))
}

FetchResponse {
  node_pk:        [u8;32]
  request_hash:   [u8;32]      // H("convo/fetch" ‖ borsh(FetchRequest))
  status:         u8           // 0 found, 1 not_found, 2 partial, 3 unauthorized, 4 expired
  served:         Vec<([u8;32] item_hash, [u8;32] content_digest)>   // content_digest = H(bytes as sent)
  time:           u64
  sig:            [u8;64]      // over H("convo/resp" ‖ borsh(fields))
}
```
**Authorization.** A node serves a group's items only to its members:
`requester_pk` must be in the group's member list (from the genesis bytes the
node holds, §2) and the request signature must verify. Otherwise the node
answers `unauthorized` (signed). Receipts (§14) need no membership: a node
receipts anything it can parse for a group it hosts, and authorship is
checked by members. This keeps a group's ciphertext, sizes, author indices
and timing from anyone who merely knows its `group_id`.

**Time.** `response.time = max(node's clock, request.time)`, so it is never
below the request's; a requester treats a response with
`time < request.time` as **no response** (does not ack, does not count it as
delivery, demotes the node as for silence). Every response is signed,
including `not_found`. The requester verifies `H(bytes) == content_digest`
and item validity. `expired` is the correct status after `retain_until`; a
request more than `REQUEST_MAX_AGE` old or `REQUEST_MAX_AHEAD` in the future
is answered `expired` too. `Range(since_head, head)` asks for everything the
node holds for the group not under `since_head`; the node answers `found` when
it holds `head` (or `head` is all zeros), `partial` otherwise, `not_found`
when it holds nothing, and serves messages and attestations alike (the
requester tells them apart by parsing). A fetch reply is
`FetchResponse ‖ Vec<Vec<u8>>` (the items in `served` order, each
length-prefixed).

## 16. Delivery acknowledgements

```
Ack {
  recipient_pk:  [u8;32]       // gk
  node_pk:       [u8;32]
  group_id:      [u8;32]
  item_hash:     [u8;32]
  time:          u64
  sig:           [u8;64]       // over H("convo/ack" ‖ borsh(fields))
}
```
Emitted automatically on verified fetch. Acks let a node tell what has been
delivered (for retention, §13) and let anyone measure a node's delivery.

## 17. Fraud proofs

A fraud proof is a set of objects the accused node signed that together show
it broke a promise. It is checked from signatures and Merkle paths alone, by
anyone, with no trusted party.

| # | Proof | Check |
|---|---|---|
| F1 | `Receipt(X)` + `FetchRequest(want Item X)` + `FetchResponse` whose `served` does not include `X` | same `node_pk`, `response.request_hash` matches, `receipt.received ≤ response.time ≤ receipt.retain_until`, request signature valid, both node sigs valid. Any status qualifies except `unauthorized`, which qualifies only with the group's genesis bytes supplied so the verifier can see the requester in `members`. |
| F2 | Two `FetchResponse`s | same `node_pk` and `request_hash`, differing `status` or `served`, both sigs valid |
| F3 | `Receipt(X, digest d₀)` + `FetchResponse{served: (X, d₁)}` | same `node_pk`, `d₁ ≠ d₀`, both node sigs valid |
| **F4** | `Receipt(X, batch_seq = s, batch_prev = p)` + a `WitnessedCheckpoint` of the node's log with `seq ≥ s` + `MmrProof`s of batch `s` `(root R, time, count)` and batch `s−1` `(root p, time, count)` against it + `GapProof` (Appendix A.5) | the checkpoint verifies (§6); both MMR proofs verify against its peaks; the gap leaf `(lo, hi)` with `lo < X < hi` (or the boundary sentinels) verifies under `R` at the stated `(index, leaf_count)`. The node promised `X` in batch `s` and published `s` without it. |
| **F5** | a `WitnessedCheckpoint` + an `MmrProof` of batch `s` `(root, time, count)` + a `GapProof` whose `index ≥ count + 1` | the tree has a gap leaf beyond the `count + 1` the stated count implies: the node misstated its batch. |
| **F6** | two `Checkpoint`s signed by the same `node_pk` | the same `seq` with different contents, or the later one's peaks do not extend the earlier one's (given the leaves between): the node showed two different histories. |

**Wire form.** `tag:u8 ‖ parts`, each part the object's wire bytes:
1 = F1 `(receipt, request, response)`, 2 = F2 `(first, second)`,
3 = F3 `(receipt, response)`,
4 = F4 `(receipt, witnessed_checkpoint, batch_s{root,time,count}, mmr_proof_s, batch_s_minus_1{root,time,count}, mmr_proof_s_minus_1, gap_proof)`,
5 = F5 `(witnessed_checkpoint, batch_s{root,time,count}, mmr_proof_s, gap_proof)`,
6 = F6 `(checkpoint_a, checkpoint_b, Vec<leaf>)`.

**What happens.** Whoever holds a proof `POST`s it to `/v1/fraud` on the
nodes it knows (§19). A node verifies it, stores it, and passes it on to the
nodes it knows once; nodes serve the proofs they hold
(`GET /v1/fraud?node=<pk>`). A client that learns a valid proof against a node
treats the node as unhealthy for good (§13.1), stops choosing it for new
groups and as a witness, and forks its groups away from it when that brings
them below `MIN_HEALTHY_HOSTS`. Nothing else is needed: a node's value is the
trust of the people who use it, and a proof ends it everywhere at once.

**Why F4 needs `batch_prev`.** Without it a node could issue a receipt naming a
batch number it has already published, or one it will never publish, and
argue about which batch was meant. `batch_prev` ties the receipt to a specific
point in the node's log.

**Why F1 has a lower bound.** Without `received ≤ response.time`, a requester
could fetch before sending and frame an honest node.

**Silence.** A node that stops checkpointing or responding cannot be proven
against. Every client that observes it marks it unhealthy (§13.1), and groups
fork away from it. A node that lost data and goes quiet is unreliable; one
that publishes a batch without what it promised is fraudulent.

## 18. Measuring nodes

Anyone may run shopper clients against a set of nodes (real identities, real
groups, real MLS) to measure receipt latency, delivery by deadline,
checkpoint punctuality and response correctness, and to catch F1–F6 in the
act. Reports are signed by whoever runs them and carry no protocol weight; a
client or app may use them to choose default nodes. The reference
implementation's measurements are left to a later version.

---

# Part III — Transport

Clients of different implementations must reach the same nodes and each
other, so the node's HTTP surface, rendezvous, signaling frames, data-channel
framing and the STUN and TURN obligation are normative. The wire objects are
Parts I and II; this part says where they travel.

## 19. Node HTTP API

A node serves HTTP (TLS at the operator's discretion; a public URL is
`https://…`). Bodies are the wire objects unless stated;
`application/octet-stream` for binary, `application/json` for JSON. `<hex>` is
lowercase hex of 32 bytes.

| Method and path | Body → response |
|---|---|
| `GET /health` (alias `/healthcheck`) | → JSON `{ok, id, kind:"node", version, site?, turn, now}` |
| `GET /v1/node` | → JSON `NodeDescriptor` (§24) |
| `GET /servers` | → JSON `{servers:[{url, id?, site?, turn}]}`: this node (first, when it has a public URL) and the healthy nodes it knows |
| `POST /servers` | JSON `{known_signaling_servers:[url]}` → 202 `{accepted}`: nodes advertise themselves to each other |
| `GET /ice?for=<client>` | → JSON `{iceServers:[{urls:[…], username?, credential?}], ttl}` (§21) |
| `POST /rendezvous/<box>` | text (base64 of a frame, ≤ 16 KiB) → 200; `GET /rendezvous/<box>` → the oldest waiting frame (200 text) or 404 when empty (§20) |
| `POST /v1/groups/<group_id>/messages` | `borsh(Message) ‖ msg_sig` → `Receipt` wire (§14); 400 if unparsable or the group in the body differs |
| `POST /v1/groups/<group_id>/attestations` | `borsh(Attestation) ‖ att_sig` → `Receipt` wire |
| `POST /v1/groups/<group_id>/republishes` | a `kind = 2` message, as `/messages` → `Receipt` wire |
| `POST /v1/groups/<group_id>/fetch` | `FetchRequest` wire → `FetchResponse` wire ‖ `Vec<Vec<u8>>` items (§15) |
| `GET /v1/groups/<group_id>/attestations` | → JSON `[{head, contentRoot, msgCount, signerIdx, committed?: CommitmentRef}]` (members only) |
| `POST /v1/groups/<group_id>/acks` | `Ack` wire → 204; 400 unless `node_pk` is this node and the signature verifies |
| `POST /v1/groups/<group_id>/blobs/<sha256>` | bytes → `Receipt` wire (`item_hash = content_digest = sha256`); `GET` → the bytes or 404 |
| `POST /v1/groups/<group_id>/genesis` | `vec(borsh(Genesis)) ‖ vec(carry sigs)` → 204; 403 if the genesis does not list this node in `home_nodes`; 400 if `H(genesis) ≠ group_id`. Any member may re-post with more carry signatures (union). |
| `GET /v1/groups/<group_id>/genesis` | → the record above (members only) |
| `POST /v1/groups/<group_id>/wake` | `WakeRegistration` wire → 204 (§19.1) |
| `GET /v1/items/<item_hash>/commitment` | → `CommitmentRef` wire (§6) for an item this node committed, or 404 (members of the item's group only) |
| `POST /v1/keypackages/<id_pk>` | `KeyPackage` wire → `Receipt` wire (`group_id` all zeros for identity-scoped items); `GET` → the wire or 404 |
| `POST /v1/identities/<id_pk>` | `IdentityRecord` wire (§13.2) → `Receipt` wire; `GET` → the newest record or 404 |
| `GET /v1/notary/<node_pk>/checkpoint` | → the newest `WitnessedCheckpoint` this node holds for that log (its own, or one it witnessed) |
| `GET /v1/notary/<node_pk>/batches` | → JSON `[{seq, root, time, count}]` for every batch of the log this node holds, oldest first: enough to rebuild the log at any size (Appendix A.4) |
| `GET /v1/notary/<node_pk>/batches/<seq>` | → `CommitmentBatch` wire (§6) or 404 |
| `GET /v1/notary/<node_pk>/batches/<seq>/proof` | → `MmrProof` of that batch's leaf against the newest witnessed checkpoint |
| `POST /v1/notary/<node_pk>/batches` | `CommitmentBatch` wire → 204 (a committing node pushing a body to a home node; verified against its signature and the log) |
| `POST /v1/witness` | `WitnessRequest` wire (§11) → `Cosignature` wire, or 409 with `u64 size ‖ Option<WitnessedCheckpoint>`: how many batches of the log the witness holds and its newest checkpoint of it |
| `POST /v1/fraud` | `tag:u8 ‖ parts` (§17) → 202 if the node verifies and keeps the proof, 400 otherwise |
| `GET /v1/fraud?node=<node_pk>` | → JSON `[hex of proof wire]`: the proofs this node holds against that node |

**Member-only `GET`s** carry
`X-Convo-Auth: <hex pubkey> <hex time> <hex sig>` where
`sig = Ed25519(sk, H("convo/get" ‖ method ‖ path-and-query ‖ time))` and
`time` is within `REQUEST_MAX_AHEAD` of the node's clock; the pubkey must be a
`gk` in the group's genesis. Endpoints so marked: `/genesis` (GET),
`/attestations` (GET), `/items/<hash>/commitment`.

Rate limits are per client address and answered with 429 and a retry hint; a
node's limits are its own but must admit at least the reference values (600
items and 600 fetches per minute per address). A node returns its existing
receipt for bytes it already holds.

### 19.1 Wakes

A closed app cannot poll, so a member may leave a standing request with each
host of a group:
`WakeRegistration { member_pk, node_pk, group_id, url: String, handle: bytes, expires: u64 }`
signed by the member's group key (`H("convo/wake" ‖ borsh(fields))`), posted
to `/v1/groups/<g>/wake` (members of a held genesis only; `expires` at most
`WAKE_LIFETIME` ahead; an empty `handle` withdraws). When a message or
republish lands, the host POSTs a `WakeCall` JSON
`{ node, time, handle, item, body?, sig }` to `url` for every live
registration but the author's: `body` is the item's own bytes (base64) when
under 4 KiB, `sig = Ed25519_node(H("convo/wakecall" ‖ node ‖ handle ‖ item ‖ time))`.
The relay behind `url` is the client's affair (a push gateway, an ntfy topic,
anything that answers HTTP).

## 20. Rendezvous boxes

A box is a FIFO queue of text frames on a node, named by an id of 8…64
characters from `[A-Za-z0-9_-]`. Frames live `RV_BOX_LIFETIME` (Appendix B)
or until taken; a box holds at most 32 frames; `GET` takes the oldest. Frames
are base64 of the borsh frame bytes.

Box names for the protocol's own traffic:
`box(key, recipient) = hex(H("convo/hs" ‖ key ‖ recipient_id_pk))`, where
`key` is the salt during the genesis handshake (§2) and the `group_id` for
signaling between members of a group (§22). A frame for `recipient` is
dropped at the nodes of the recipient's identity record (§13.2), or
`RV(recipient, k_rv)` when none is known; the recipient polls the same set.
Anything a box carries is either MLS-sealed (announce, genesis) or public and
unforgeable at the next step (invite: KeyPackages are signed; SDP: the data
channel is DTLS, and the peer proves membership in the sync request it sends
over it).

## 21. STUN and TURN (required)

Members behind NATs need TURN to reach each other. A node offers it in one of
two ways, and says which in `/health` and `/v1/node` (`turn`):

- **Its own.** A STUN server (RFC 5389) and a TURN server (RFC 5766) on one
  port for UDP and TCP (default 3478), with relayed addresses on a range of
  UDP ports, and short-lived credentials (RFC 8489 long-term credential
  mechanism with a shared secret; `username = expiry ":" client`,
  `credential = base64(HMAC-SHA1(secret, username))`, `realm = "convo"`)
  through `GET /ice`, valid `ttl` seconds.
- **A TURN service.** `GET /ice` hands out credentials the node mints from a
  third-party TURN service, such as Cloudflare's, as long as the credentials it
  hands out work.

A node that offers neither is a valid mailbox, but clients rank it last as a
host and never as the only host, because two members behind NATs cannot open
a data channel through it.

## 22. Signaling frames

Between two members of a group, through `box(group_id, recipient)`: borsh
frames with a tag byte.

| Tag | Frame |
|---|---|
| 0 | `offer(sdp: String)` |
| 1 | `answer(sdp: String)` |
| 2 | `candidate(sdp: String, sdp_m_line_index: u32, sdp_mid: Option<String>)` |

The caller opens the data channel (§23), creates the offer, drops it, and
relays every local candidate as it is discovered; the callee answers and
relays its candidates; both apply candidates as they arrive. ICE servers are
the node's `/ice` answer. A side gives up after `RECEIPT_TIMEOUT × 6` (30 s)
without the expected description.

## 23. Data-channel framing

One ordered, reliable data channel labelled `convo`, binary messages, one
frame per message. Frames are a tag byte followed by wire bytes:

| Tag | Frame |
|---|---|
| 0 | `SyncRequest` wire (§12) |
| 1 | `borsh(Message) ‖ msg_sig` |
| 2 | `borsh(Attestation) ‖ att_sig` |
| 3 | end: one byte, `0 complete`, `1 unknown_head`, `2 unauthorized` |
| 4 | call offer: `video:u8 ‖ sdp:String` (§25) |
| 5 | call answer: `sdp:String` (§25) |
| 6 | call end (§25) |

A responder answers a request with the messages it holds that the requester
lacks, in canonical order (parents before children), then the attestations
for the wanted head, then `end`. A requester verifies every item (§4) as it
arrives and retries orphans after `end`. Handshake frames (§2) may travel on
the same channel between members who already have one.

## 24. Discovery

**Node descriptors.** Each node describes itself, signed by its key:
```
NodeDescriptor {
  node_pk:      [u8;32]
  operator_pk:  [u8;32]      // who runs it; one operator may run several nodes
  url:          String       // its public URL
  site:         String       // where it runs (a region or a name), advisory
  turn:         bool         // §21
  version:      String
  time:         u64          // unix ms
  sig:          [u8;64]      // Ed25519(node_sk, H("convo/nodedesc" ‖ borsh(fields)))
}
```
served as JSON at `GET /v1/node` (fields in camelCase, byte fields in hex).

**Directory.** A node learns other nodes from its seeds and from every node's
`/servers`, confirms each by its descriptor, health-checks it with `/health`
on a backoff (10 min when healthy, 10 min → 7 d after failures, evicted after
a week of failures), advertises its own public URL to the nodes it knows every
30 minutes, and persists the directory. A client learns nodes the same way:
from the nodes in its app's defaults and in identity records and invitations,
then `/servers`, confirming each node's key with `/v1/node`. There is no
registry and no admission: a node exists when it serves a valid descriptor,
and it is used when clients choose it.

## 25. Calls

A call is audio (and optionally video) between two members, carried by the
peer connection that already carries their `convo` data channel (§23).
Signaling for the call is three frames on that channel (tags 4–6); media is
renegotiated onto the same connection, so a call shares the channel's ICE and
DTLS and needs no second rendezvous.

**25.1 Caller.** Adds a microphone track, and a camera track when
`video = 1`, to the connection; creates an offer that receives audio, and video
when `video = 1` (the offer's audio and video lines are `sendrecv`); sets it
locally; waits for ICE gathering to complete (or `RECEIPT_TIMEOUT`, whichever
first) and sends `offer(video, sdp)` with the candidates in the SDP. Call
frames are not trickled.

**25.2 Callee.** On `offer`, the app decides. To accept: set the remote offer;
put its own microphone (and camera, when it wants to send one) **on the
offer's transceivers** (§25.3); create an answer that receives audio and video;
set it locally; gather; send `answer(sdp)`. To decline: send `end`.

**25.3 Transceivers.** Media lines are reused, never multiplied: a side that
adds a track first looks for a transceiver of that kind whose direction is
`recvonly` or `inactive` and whose sender has no track, attaches the track
there and sets the direction to `sendrecv`; only if there is none does it add a
new track (and thereby a new line). One audio line and at most one video line
per call.

**25.4 End.** Either side sends `end` and removes its tracks. The other side
removes its tracks on receipt. The data channel is unaffected. A side that
receives `end` while ringing treats it as a decline.

**25.5 Codecs.** Audio: Opus (48 kHz, in-band FEC allowed) must be offered;
PCMU and PCMA may be. Video: VP8 must be offered and accepted; H.264
constrained baseline and VP9 may be. These are WebRTC's mandatory-to-implement
codecs, so a browser client conforms without configuration.

**25.6 Interoperability.** Nothing in a call is implementation-specific: a
client that implements §22–§23 and §25 with any WebRTC stack can call any
other. Capture, rendering and ringing UI are the client's own.

---

# Part IV — Operating a node

Nothing in this part is normative. It is how a person or a community runs a
node, for themselves or for others, as people run mail servers, Nostr relays
or AT Protocol servers: because its operator wants the network to work for
the people they care about. An app chooses default nodes for its users, and
users may add any node.

## 26. On free allowances

The aim is that anyone can run a node at no cost. A node is a small amount of
code, durable storage, outbound HTTP and a timer, plus TURN; a free Cloudflare
account has all of them (Cloudflare's Workers, Durable Objects and Realtime
pricing pages, read 2026-11-23). Free allowances change; check them before
relying on one.

- **A Durable Object per node.** The reference node's core, compiled to
  WebAssembly, runs in a Cloudflare Durable Object (`Worker/` in the
  reference implementation). A Durable Object is one instance per ID, so the
  node key's log has exactly one writer (§28) with nothing to coordinate. Its
  SQLite storage keeps the node's files, written before each response
  leaves (§13), and its alarm closes batches and gathers witnesses'
  cosignatures (§7, §11). The free plan allows SQLite-backed Durable Objects,
  with, per account and per day, 100,000 requests, 100,000 rows written,
  5 million rows read and 13,000 GB-s, and 5 GB stored. A node writes about a
  row per item it receipts, so three nodes of one account serve thousands of
  messages a day. Measured 2026-11-23: 1.8 ms of CPU per request at the
  median and 30 ms at the most (a cold start, or a commit), with no requests
  refused.
- **TURN.** Cloudflare Realtime gives the first 1,000 GB a month free (shared
  with its SFU), then $0.05 per GB. The node mints short-lived credentials in
  `/ice` (§21); STUN is free. TURN carries only the traffic of members who
  can't reach each other directly, so messaging costs nothing and relayed
  calls the most.
- **A name.** The account's `workers.dev` subdomain, or the operator's own
  domain on Cloudflare at no cost.

One account may run several nodes, each its own Worker, witnessing each
other; witnesses of other operators make a log's checkpoints worth more
(§11).

## 27. Self-hosting

The same container runs anywhere with a persistent volume for its data
directory and a public URL: a home server, a VPS, a Raspberry Pi behind a
tunnel. It can run its own STUN and TURN (§21; the reference node includes a
TURN server, or use coturn) when the host has a public IP and open UDP ports,
or use a TURN service as above.

## 28. Being a good node

- **Persist before you sign** (§13): a receipt is a promise.
- **Witness others.** A node's log is only as credible as its witnesses; a
  node that witnesses others helps the network and is helped back.
- **One key per log.** Never run two instances on one key at once.
- **Upgrade one host at a time**, and keep restarts under
  `HOST_UNHEALTHY_AFTER`, so a deploy never looks like an outage.

---

# Appendix A — Wire encoding

## A.1 borsh conventions
- Integers little-endian, fixed width. `bool` = 1 byte. `Option<T>` = `0x00`
  or `0x01 ‖ T`. `Vec<T>` = `u32 len ‖ items`. Fixed arrays raw. Enums =
  `u8` tag ‖ payload.
- Struct fields in the order written in this document.
- Canonical bytes are the borsh encoding; there is exactly one valid encoding
  per value.

## A.2 Domain tags (ASCII, no length prefix, prepended to the borsh bytes before hashing)

| Object | Tag |
|---|---|
| group_id | `convo/genesis` |
| msg_hash | `convo/msg` |
| content leaf / inner node | `convo/leaf` / `convo/node` |
| attestation preimage | `convo/att` |
| fork authorization | `convo/fork` |
| sync request | `convo/sync` |
| receipt / fetch / response / ack | `convo/rcpt` / `convo/fetch` / `convo/resp` / `convo/ack` |
| commitment batch sig / gap leaf / gap node | `convo/cbatch` / `convo/gap` / `convo/gnode` |
| log leaf / MMR node | `convo/cbatch-leaf` / `convo/mmr-node` |
| checkpoint / cosignature | `convo/ckpt` / `convo/cosign` |
| KeyPackage | `convo/kp` |
| identity record / node descriptor | `convo/idrec` / `convo/nodedesc` |
| signed GET | `convo/get` |
| wake registration / wake call | `convo/wake` / `convo/wakecall` |
| rendezvous rank / box | `convo/rv` / `convo/hs` |
| identity derivation (HKDF info) | `convo/identity/v1` |
| gk derivation (HKDF info) | `convo/gk/v1` |
| hpke derivation (HKDF info) | `convo/hpke/v1` |

## A.3 Merkle tree
Binary tree over leaves in order. Leaf = `H(tag ‖ bytes)`. Inner =
`H("convo/node" ‖ left ‖ right)`. If a level has an odd count, the last node is
promoted unchanged (no duplication). Empty set: root = `H("convo/leaf")`.
Inclusion proof = list of `(sibling_hash, side)` from leaf to root; the
verifier recomputes and compares.

## A.4 The log's accumulator (Merkle Mountain Range)

An append-only accumulator over a node's batches, leaf `i` =
`H("convo/cbatch-leaf" ‖ root_i ‖ time_i ‖ count_i)` for batch seq `i`. A
standard MMR:

- **Leaf hash:** the batch leaf above. **Node hash:**
  `H("convo/mmr-node" ‖ left ‖ right)`.
- **Append:** push the leaf as a new peak; while the two rightmost peaks have
  equal height, replace them with their node hash. After `n` leaves the peaks
  are the perfect binary trees corresponding to the set bits of `n`, so there
  are at most `popcount(n) ≤ 64` of them.
- **Proof for leaf `i` in an MMR of size `n`:**
  `MmrProof { size: u64, leaf_index: u64, siblings: Vec<([u8;32], u8)>, peak_index: u8 }`,
  the sibling hashes from the leaf up to its peak (with sides) in the MMR of
  `size` leaves.
- **Verify against peaks of size `n`:** require `proof.size == n` and
  `leaf_index < n`; recompute the peak from the leaf and siblings; require it
  equals `peaks[peak_index]`. The peaks are a witnessed checkpoint's
  (`size = checkpoint.seq + 1`). A proof of an earlier size is verified against
  the accumulator rebuilt from the log's batch list
  (`GET /v1/notary/<pk>/batches`) truncated to that size, valid only if the full
  rebuild reproduces a witnessed checkpoint's peaks.

A proof is `~32 × log2(n)` bytes, under 400 bytes for a log of a thousand
batches.

## A.5 Sorted commitment tree (gap leaves)

A commitment batch is a Merkle tree whose leaves make **non-membership**
provable with a single path.

- Sort the item hashes ascending: `h_0 < h_1 < … < h_{n−1}` (duplicates
  removed).
- Gap leaves: `g_i = H("convo/gap" ‖ lo_i ‖ hi_i)` for `i = 0..n`, with
  `lo_0 = 0x00…00`, `hi_n = 0xff…ff`, and `(lo_i, hi_i) = (h_{i−1}, h_i)`
  otherwise. So `n` items give `n + 1` leaves; leaf `i` asserts "no item lies
  strictly between `lo_i` and `hi_i`."
- Inner nodes: `H("convo/gnode" ‖ left ‖ right)`; odd node promoted unchanged
  (as A.3). Root over the gap leaves.
- **Membership of `X`:** an inclusion proof of any gap leaf with `lo = X` or
  `hi = X`.
- **Non-membership of `X`:** an inclusion proof of the gap leaf with
  `lo < X < hi`. The verifier checks the strict inequalities and the path.
- **`GapProof { lo: [u8;32], hi: [u8;32], index: u64, leaf_count: u64, path: Vec<([u8;32], u8)> }`.**
  Because odd nodes are promoted (A.3), a path's sides alone do not pin a leaf's
  position; the verifier derives the expected sequence of sides and the levels
  at which no sibling exists from `(index, leaf_count)`, requires the path to
  match that shape, and recomputes the root. `leaf_count` must equal
  `count + 1` for the batch (or, for F5, exceed it).
- Proof size: `32 × ⌈log2(n+1)⌉` bytes plus sides; ≤ 13 levels at
  `BATCH_MAX = 4096`.

## A.6 Test vectors
Generated by the reference implementation from fixed seeds into
`Tests/Vectors/`, one JSON file per object type; any conforming
implementation reproduces them byte for byte (signatures excepted where a
platform randomizes Ed25519: the files carry them, and they must verify).

| File | Contents |
|---|---|
| `identity.json` | a mnemonic, the derived `id_pk`, `gk` for a salt, `hpke_pk[0..2]` |
| `genesis.json` | a 3-member genesis and `group_id`; a child genesis with `ParentRef` and `carry`; fork-auth preimage and signatures |
| `messages.json` | three messages (two concurrent), bytes, `msg_hash`, `msg_sig` |
| `order.json` | canonical order; `content_root`; per-leaf inclusion proofs |
| `attestation.json` | one attestation and its item bytes and hash |
| `cbatch.json` | 5 item hashes → sorted gap tree: leaves, root, a membership `GapProof`, a non-membership `GapProof`, a boundary case, a wrong-shape negative; batch signature |
| `mmr.json` | peaks after 1, 2, 3, 7, 8 appends; `MmrProof`s for leaf 2 of size 7 and 5 of size 8; leaf 2 re-proved at size 8; a negative case |
| `commitment_ref.json` | a witnessed checkpoint and a full `CommitmentRef` against it that resolves; one with a tampered `item_proof`; one whose checkpoint has a single cosignature |
| `republish.json` | a `Republish` with a `CommitmentRef` source and a verifying inclusion proof |
| `relay.json` | receipt, fetch, response, ack; F1–F6 proofs, each with a negative |
| `witness.json` | a log's entries and leaves, a checkpoint's and a cosignature's preimages, a `WitnessRequest`'s entries, an identity record's and a node descriptor's preimages |
| `rv.json` | 20 node pubkeys, `RV(group_id, 3)` and `RV(id_pk, 2)` |
| `borsh.json` | edge cases |

---

# Appendix B — Default parameters (all tunable)

## B.1 Genesis parameters by group size

| Members | `quorum` | `max_parents` | `max_payload` | `max_uncommitted_republish` |
|---|---|---|---|---|
| 2 | 2 | 8 | 65,536 | 10 |
| 3–8 | all − 1 (min 2) | 8 | 65,536 | 10 |
| 9–64 | ⌈½·N⌉ + 1 | 8 | 65,536 | 10 |

## B.2 Client policy

| Parameter | Default | Note |
|---|---|---|
| `ATTEST_MSGS` / `ATTEST_INTERVAL` | 20 / 5 min | attest the current head after this many new messages or this long |
| `COMMIT_GRACE` | 2 min | past `COMMIT_INTERVAL` before an uncommitted receipt is a health failure, or F4 when the batch is published without it |
| `RECOVERY_PATIENCE` | 14 d | before a recovery fork |
| `RECEIPT_TIMEOUT` | 5 s | per node, then retry |
| `MIN_HEALTHY_HOSTS` / `MIN_TOTAL_HOSTS` / `MAX_TOTAL_HOSTS` | 2 / 3 / 10 | client bounds (§13.1) |
| `TARGET_TOTAL_HOSTS` | `MIN_TOTAL_HOSTS` + 1 | |
| `HOST_UNHEALTHY_AFTER` | 10 min of sustained failure | must exceed a routine restart |
| `FORK_STAGGER` | 30 s | per-member wait before a host-change fork |
| `k_rv` | 2 | rendezvous set size |
| `R_BLOB` | 2 | hosts that receive each attachment blob |
| `HPKE_ROTATION` / `KP_LIFETIME` | 30 d / 60 d | |
| `MLS_UPDATE_INTERVAL` | 7 d of own activity, or 500 own messages | |
| `WITNESS_QUORUM` | 2 | independent cosignatures that publish a checkpoint (§6, §11) |
| local health decay | half-life 24 h | |

## B.3 Node parameters

| Parameter | Default |
|---|---|
| `COMMIT_INTERVAL` | 5 min |
| `BATCH_MAX` | 4,096 items (close another batch when reached) |
| `DELIVERY_WINDOW` | 2 min |
| `MIN_RETENTION` | 30 d |
| `T_ARCHIVE` / `T_REUPLOAD` | 7 d / 7 d |
| `WITNESS_SKEW` | 5 min |
| `REQUEST_MAX_AGE` / `REQUEST_MAX_AHEAD` | 60 min / 6 min |
| `WAKE_LIFETIME` | 30 d |
| `RV_BOX_LIFETIME` | 600 s |

---

# Appendix C — Reference implementation layout (non-normative)

A Swift package targeting iOS 17 and macOS 14 for the client and Linux for the
node, consumed by apps through SwiftPM.

| Target | Depends on | Contains |
|---|---|---|
| `ConvoCore` | swift-crypto | borsh, domain-tagged hashing, Merkle tree and proofs, DAG store, canonical ordering, `content_root`, validity rules, attestations, sorted commitment trees and the log's MMR (A.4, A.5), checkpoints and cosignatures, `CommitmentRef` resolution, fork and carry logic, rendezvous ranking, identity records and node descriptors, message states, Part II formats and fraud-proof verification (F1–F6), parameters. All vectors are produced here. |
| `ConvoMLS` | swift-crypto | TreeKEM, key schedule, HPKE, group state, application-message sealing on `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. |
| `ConvoNet` | `ConvoCore` | Sync over a `DataChannel`, node API paths and client, fetch replies, §13.1 host health, the node directory. |
| `ConvoNode` | `ConvoCore`, `ConvoNet` | The node: mailbox with receipts and signed responses, acks, KeyPackages, identity records, blobs, discovery, rendezvous boxes, STUN and TURN and ICE credentials, the log and its checkpoints, witnessing, fraud-proof gossip, wakes, its own HTTP server. |
| `ConvoSession` | `ConvoCore`, `ConvoMLS`, `ConvoNet` | A group's state machine for synchronous clients (the browser build). |
| `ConvoClient` | `ConvoCore`, `ConvoMLS`, `ConvoNet` | Identities and KeyPackages, the genesis handshake, group sessions, host policy, node directory, on-disk store, and the client loop (publish, fetch, ack, check commitments, report fraud, attest, peer sync, forks, republish, rebase). |
| `ConvoWebRTC` / `ConvoCalling` | `ConvoNet`, Communication | Part III over a Communication peer connection: the data channel, rendezvous signaling, and §25 calls. |
| `ConvoCLI` / `convo` | all of the above | The reference CLI, as a library so the end-to-end tests drive it in process, and its binary. |
| `ConvoNodeMain` / `convo_node` | `ConvoNode` | Node options and runtime, and the binary the OCI image runs. |

---

# Appendix D — Implementation notes (non-normative)

## D.1 Build order
`ConvoCore` with vectors (identity, DAG, canonical order, `content_root`,
attestations, gap tree, MMR, checkpoints, `CommitmentRef`, fraud-proof
verification) → `ConvoNet` over a loopback data channel → `ConvoNode`
(receipts, batches, checkpoints and witnessing, member-only fetch) →
`ConvoMLS` integration → `ConvoCLI` end to end → forks and republish. Each
layer has tests that do not depend on the next.

## D.3 Node operation
- **Persist before you sign.** In-memory storage loses what was receipted on a
  restart, which F1 or F4 then proves. Keep the data directory on a durable
  volume: a disk when self-hosting, a mounted Cloud Storage bucket on Cloud
  Run.
- **One key per log, one writer per key.** On Cloud Run set the maximum
  instances to 1, and don't rely on it alone: a platform may briefly run two
  instances of one service (observed on Cloud Run, 2026-11-18). The reference
  node writes an `owner` claim to its data directory, waits
  `CONVO_TAKEOVER_SECONDS` (15) before reading its state, re-reads the claim
  before every write, and exits once a newer instance has claimed it.
- **Cloudflare:** `Worker/README.md` deploys a node as a Worker with its
  Durable Object; the TURN key and token are Worker secrets. An idle object
  is evicted and starts again from its SQLite storage on the next request,
  which the health rules allow (a cold start blows `RECEIPT_TIMEOUT`, the
  client retries elsewhere).
- **A container platform** (the Dockerfile): keep the data directory on a
  durable volume, and if the platform may run two instances of one service,
  hold the directory with the reference node's lease; on Cloud Storage FUSE,
  mount it with `metadata-cache-ttl-secs=0` and set
  `CONVO_STATE_OBJECT_STORE=1`.
- **Batch timing.** Close batch `s` the moment you decide to checkpoint it;
  every receipt issued after that names `s+1`. Never issue a receipt against a
  batch you might not publish.
- **Witnesses.** Ask more witnesses than `WITNESS_QUORUM`, from different
  operators and sites, so one being down doesn't delay publication.

## D.4 MLS conformance (RFC 9420), required before publishing the MLS target
1. Run the official vectors from `github.com/mlswg/mls-implementations` for
   ciphersuite 1 as data-driven tests: `tree-math`, `crypto-basics`,
   `secret-tree`, `key-schedule`, `transcript-hashes`, `message-protection`,
   `welcome`, `tree-operations`, `treekem`, `messages`, `psk_secret`. A failing
   category is a blocker.
2. Produce RFC-shaped objects: `MLSMessage` and `PrivateMessage` framing for
   payloads, RFC `KeyPackage`, `Welcome`, `GroupInfo` and `Commit`; the Convo
   `KeyPackage` wraps or carries the RFC one; `hpke_index` and `not_after` map
   onto `Lifetime`. Keep the leading tag byte so framings coexist during the
   switch.
3. Self-`Update` commits with a path (§2), epoch advance, per-epoch secret
   trees, and deletion of old epoch secrets after a grace period.
4. Per-index HPKE keys and rotation (§1).
5. One interop round trip against OpenMLS before open-sourcing.
6. Constant-time secret comparison, zeroization on drop where Swift allows, no
   secrets in logs.

## D.5 Tests beyond the vectors
- Two clients, three nodes: 50 messages; every receipt's item in the named
  batch within one interval, each batch witnessed by the other two nodes;
  `committed` on both clients.
- A node omits an item (test hook): a client builds F4, every node it reaches
  keeps it, and both clients drop the node. A node signs two checkpoints for
  one `seq`: a witness refuses and holds F6.
- A receipt with a stale `batch_prev`: the client rejects it.
- A recovery fork citing a `CommitmentRef` on an attestation; republish
  through it; the side branch renders and is viewable.
- Boundary cases: `BATCH_MAX` reached mid-interval; a batch of one item;
  sentinel gap leaves; MMR merges at 2^k appends; a witness new to a long log.

## D.6 Known soft spots
- **Witness choice** is each node's; a client that distrusts a node's
  witnesses can ask other nodes for the log's newest checkpoint and compare.
- **Directory convergence.** `RV` differs between clients with different
  directories; identity records (§13.2) and the nodes in invitations are the
  primary paths, and `RV` is the fallback.
- **Spam.** A node receipts anything for groups it hosts; rate limits (§19)
  bound it. Computational puzzles or invitation codes for new identities are left to
  a later version.

## D.7 Reference implementation status
Recorded in `Docs/deviations.md`.

## D.8 App-side notes (outside the protocol)
- Show the recovery phrase once at identity creation; keep the key in the
  platform keychain.
- Republished ranges must be viewable (§9.4); how they look is the app's
  decision.
- Default nodes are an app decision: an app may run its own and list
  community nodes, and users may add any node.

## D.9 One identity on several devices
A second device takes the identity's seed and group records through a
rendezvous box (sealed under a fresh key carried in a QR code or link), and
both devices are the same MLS leaf. The protocol only has to stop them sealing
at the same ratchet generation: reading a message from its own index advances
a device's generation past it, and a commit carries its leaf secret
HPKE-sealed to the author's own leaf key so the other device follows the
rotation.

---

# Appendix E — How the design got here (non-normative)

1. **Why a DAG with attestations rather than a single ordered log.** Messages
   reference what their author had seen; concurrent sends merge by
   construction; members sign heads, and a signature over a head transitively
   covers everything beneath it. No proposal, no leader, no ordering vote.
2. **Why per-node commitment.** A node commits everything it receipts in one
   batch per interval, flat-cost at any group count; proofs against the node's
   log replace any per-group state.
3. **Why immutable groups and forks.** Membership never changes inside a group;
   every change is a child with fresh MLS keys and a verifiable parent pointer.
   Removal is everyone else leaving. Unrecoverable history is a fork with a
   republishable, visibly marked side branch.
4. **Why witnesses, descriptors and fraud proofs.** A node's history needs
   to be pinned in time, the network needs to know its nodes, and a node that
   lies needs to stop being used. Witnesses pin history as transparency logs
   do; signed descriptors and gossip list nodes, as relays and personal data
   servers do elsewhere; and a fraud proof every client acts on removes a
   lying node, because its only asset is the trust of the people who use it.
   None of it asks a user or an operator to pay into the protocol, so anyone
   can run a node for what its hosting costs (§26), and the protocol stands
   next to Nostr and the AT Protocol as an
   open network, with end-to-end encryption and verifiable delivery as what it
   adds.
