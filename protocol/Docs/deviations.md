# The reference implementation against spec v2.0

The implementation follows `convo-protocol-spec-v2.0.md` as of 2026-11-18.
Where it falls short of the text, or goes beyond it, it says so here. When
code and spec disagree, fix one and record it below; never let one silently
win.

## Short of the spec

- **Witness independence (§11).** A client counts cosignatures from distinct
  keys other than the node's own (`WitnessedCheckpoint.witnesses`). It does
  not yet compare the witnesses' descriptors for a different operator and
  site; a node that runs its own witnesses under other keys can reach the
  quorum alone.
- **Gossip of checkpoints (§11).** Nodes serve the newest checkpoint they
  hold for each log, and clients compare the checkpoints carried in the refs
  they resolve (F6 on a conflict). Nodes don't yet fetch each other's
  checkpoints to compare on their own.
- **F6 from a client** covers two checkpoints with the same `seq`; the
  non-extending case is built only by witnesses, which hold the entries.
- **Directory (§24).** Nodes learn and health-check each other by URL;
  descriptors are served and verified by clients (`NodeDirectory`), not yet
  by nodes, and the 30-minute advertisement carries URLs only.
- **Identity records (§13.2).** Clients publish and read them; invitations
  and QR codes don't carry them yet (the app's handshake links name the
  identity only).
- **MLS** is the compact implementation; not yet run against RFC 9420's
  vectors (D.4). Self-Update commits travel as unsealed `mls-commit:`
  control messages.
- **`hpke_index` rotation** is derived and published; clients use index 0.
- **Acks** are recorded by nodes and not used for anything else yet.

## Beyond the spec

- **`Committer.witnessSizes`**: a node remembers how much of its log each
  witness holds and sends only the entries it lacks, retrying once from the
  size a 409 reports.
- **`StateFiles`**: each state directory is made once per process, and with
  `CONVO_STATE_OBJECT_STORE=1` objects are written in place (no temporary
  file and rename), since a Cloud Storage upload replaces an object whole.
- **`StateLease`**: one writer per key through an `owner` claim in the data
  directory (D.3), after Cloud Run ran two instances of one node despite
  `--max-instances 1`.
- **The built-in relay stays off when the environment names a TURN service**
  (Cloudflare's, or coturn's shared secret), since a Cloud Run container
  cannot take UDP.
