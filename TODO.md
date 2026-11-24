# TODO

The ordered short list is `docs/milestones.md`; the protocol-side gaps are
`protocol/TODO.md` and `protocol/Docs/deviations.md`.

## The app on spec v2.0

- Drive the native apps (the iOS simulator, the Mac app, the Android
  emulator) against the nodes: pair, message, call. The web client has been
  run against them through TURN (tools/e2e/run_pair.sh, each release's proof).
- Onboarding's recovery phrase isn't kept until Continue: a page reload
  shows a different one. Keep the previewed phrase in the secret store until
  Continue or Cancel.
- Identity records (§13.2): publish one naming the person's nodes, and put
  it in invite links and QR codes, so contacts find their KeyPackages
  without `RV`.
- Fraud proofs: the app builds none yet; take F1/F3 from fetches and F4 from
  overdue receipts as `ConvoClient` does, and gossip them to the nodes.
- Forks in the UI beyond recovery: membership change, host change; the
  "X moved to a new conversation" splinter case (§9.3); republished
  branches rendered per §9.4 (indented, attributed, labeled); the
  archived thread marked as such in the UI (today it only stops growing).
- A fork in flight is not persisted: a restart mid-handshake restarts it
  with a new salt.

## Conversations

- Groups larger than two: invite several identities, the handshake with N
  announces, group chat UI in convo_ui.
- Attachments: images and files as blobs through the hosts.
- Message states and delivery feedback (receipts from hosts, acks from
  the peer) in the thread; retry on `noReceipt`.
- Offline queue: messages composed with no host reachable are kept and
  published when one is.
- Blocking and removing a contact (leave the group; a membership fork
  when more than two).

## Identity and pairing

- Seed export/import between devices (QR from a signed-in device), so a
  phone and a Mac share one identity; today each device is its own.
- Contact discovery by identity key without a QR (the identity record or
  `RV(·)` gives the nodes holding its KeyPackage; start the handshake);
  invite links keep working.
- The Mac app has no URL-scheme handler or camera scanner; add a
  `convo://` (or the site's) link handler so it can join from a link.

## Calls

- Peer channel over `ConvoWebRTC`'s `PeerChannel` in the native hosts
  (the app still has its own host-side WebRTC plumbing; converge).
- Trickle ICE and ICE restart when the network changes mid-call.
- Call UI: mute, camera toggle, speaker, incoming-call screen on iOS via
  CallKit, ringing on the Mac; the video window on macOS as a proper
  panel with end/mute.
- Push notifications for calls and messages: the nodes' wakes (§19.1) to a
  push gateway, APNs/FCM with encrypted payloads (`docs/milestones.md`).

## Nodes from the app's side

- Show node health in Settings with the §13.1 status (healthy, failing
  since, ejected); host-change fork when hosts fall below the bound.
- Verify each node's signed descriptor (§24) before using it, and prefer
  hosts and witnesses of different operators.
- Pick home nodes for a new group by rendezvous over the directory.

## Platforms

- iOS: privacy manifest, background modes for calls, TestFlight build.
- macOS: notarization, the Liquid Glass chrome checked on a physical
  Mac (the VM cannot render it).
- Android: audio and camera permissions flow, Play internal testing.
- Web: the new domain; PWA manifest; service worker for offline; a
  camera-based scanner (`BarcodeDetector`) instead of file upload.

## CI

- **The proof's native screens.** A release's proof is the web client paired
  in two iOS simulators. Add the iPhone, Mac and Android apps paired, driven
  the way tools/e2e drives the web (debug hooks), held still.

## Housekeeping

- The web and Android clients' WebRTC moves from `ConvoHost` onto
  communication once it runs on those platforms.
- Internal names still say Convo (the Swift modules `ConvoApp`, `ConvoUI`,
  `ConvoServices`; `libraries/convo_*`; the protocol's `Convo*` modules and
  the Convo Protocol's name): rename the app's to P2PRC in one change; the
  protocol keeps its name.
- Move the app onto `ConvoClient` for native platforms once wasm's
  concurrency story is settled, or keep `ConvoSession` and document why.
- Default nodes: node-1..3.p2prc.org (custom domains on the Workers;
  node-<n>.p2prc.workers.dev still answers), and community nodes as they
  appear.
