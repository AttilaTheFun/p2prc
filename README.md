# P2PRC

End-to-end encrypted group messaging, with calls, on an open protocol that
anyone can run a node for, for free.

- **One SwiftUI source, four clients.** The iPhone/iPad and Mac apps use
  Apple's SwiftUI. The web and Android clients run the same Swift through
  [Isomer](https://github.com/AttilaTheFun/isomer): compiled to WebAssembly
  in the browser, cross-compiled for Android and drawn with Jetpack Compose.
- **The protocol and its node, in Swift too** (`protocol/`): messages are
  MLS-encrypted, author-signed and agreed in a DAG; nodes store and forward
  for offline members and commit what they accept to logs other nodes
  witness, so a node that drops or rewrites a message is caught by a proof
  anyone can check.
- **Free nodes.** The node compiles to WebAssembly and runs as a Cloudflare
  Durable Object on the free plan, with Cloudflare's TURN for calls
  (`protocol/Worker`). The apps start with three: `node-1.p2prc.org`,
  `node-2.p2prc.org` and `node-3.p2prc.org`. A Dockerfile covers
  self-hosting.

The web client is at [p2prc.org](https://p2prc.org).

## Layout

- `applications/p2prc_ios`, `applications/p2prc_macos`: the Apple apps.
  Each embeds the web client and serves it, so any native peer can also
  hand the app to someone with nothing.
- `applications/p2prc_web`: the web client. `index.html` is the host half
  (WebRTC, storage, QR codes); the rest is Swift.
- `applications/p2prc_android`: the Android app, with its services in Kotlin.
- `libraries/convo_app`: the client model (pairing, conversations, calls,
  persistence, node discovery). `libraries/convo_ui`: the screens, on
  [AgentUI](https://github.com/AttilaTheFun/agent_ui).
  `libraries/convo_services`: what each host provides.
- `protocol/`: the protocol's spec (`Docs/`), its Swift package (core, MLS,
  networking, client, node), the `convo` CLI and `convo_node`, and the
  Cloudflare Worker (`Worker/`). Its README says more.
- `tools/e2e`: the end-to-end checks (two clients pair and message through
  the nodes, their link relayed by TURN).

Dependencies, all public: Isomer, [communication](https://github.com/AttilaTheFun/communication)
(WebRTC for the Apple apps), AgentUI, ShakeKit and UpdateKit, through Bazel
and rules_swift_package_manager (`third_party/swift_packages`).

## Building

With Bazel (Bazelisk):

```sh
bazel build //applications/p2prc_web:p2prc_web          # the web client
bazel build //applications/p2prc_android:p2prc_android  # the Android app
bazel build //applications/p2prc_ios:p2prc_ios          # on a Mac, with Xcode
bazel build //applications/p2prc_macos:p2prc_macos
```

The protocol package builds and tests with SwiftPM:

```sh
cd protocol && swift test
```

## How it works

**Groups, not servers.** A conversation is a group, and a direct message is a
group of two. Nobody owns a group, and it survives all of its members being
offline.

**Every member holds the history,** and events form a graph rather than a
list: each names the events its author had already seen, so fragmented
histories merge and every member reads them in the same order.

**Nodes are accountable, not trusted.** A node signs a receipt for each item
it accepts and commits it to its log, which other nodes witness. A node that
loses or alters a message it promised is caught by a fraud proof that any
client or node can check (`protocol/Docs/convo-protocol-spec-v2.0.md`).

**Pairing needs no account.** Two people pair by a QR code or a link that
carries a one-time secret; the handshake runs through the nodes' rendezvous
boxes, and WebRTC connects the devices directly where it can, through TURN
where it can't.

## License

Apache License 2.0 (`LICENSE`).
