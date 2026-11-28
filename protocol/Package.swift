// swift-tools-version: 6.0

// ConvoProtocol: the Convo Protocol specification (Docs/) and its reference
// implementation. Libraries for the client and the node, a CLI client and
// a node binary, tests with swift Testing, and the vectors that define
// conformance (Tests/Vectors). Consumed as a SwiftPM package; no Bazel here.
import PackageDescription

let package = Package(
    name: "convo_protocol",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "ConvoCore", targets: ["ConvoCore"]),
        .library(name: "ConvoMLS", targets: ["ConvoMLS"]),
        .library(name: "ConvoNet", targets: ["ConvoNet"]),
        .library(name: "ConvoNodeCore", targets: ["ConvoNodeCore"]),
        .library(name: "ConvoNode", targets: ["ConvoNode"]),
        .library(name: "ConvoSession", targets: ["ConvoSession"]),
        .library(name: "ConvoClient", targets: ["ConvoClient"]),
        .library(name: "ConvoCLI", targets: ["ConvoCLI"]),
        // apple-only-begin
        .library(name: "ConvoWebRTC", targets: ["ConvoWebRTC"]),
        .library(name: "ConvoCalling", targets: ["ConvoCalling"]),
        // apple-only-end
        .library(name: "ConvoNodeMain", targets: ["ConvoNodeMain"]),
        .executable(name: "convo", targets: ["convo"]),
        .executable(name: "convo_node", targets: ["convo_node"]),
    ],
    dependencies: [
        // 4.0 and later build on FoundationEssentials where it exists (the
        // Worker needs that); the Convo app is on 3.x for now.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"6.0.0"),
        // The WebRTC API the app's transport is built on (Part III). Apple
        // platforms only; the node and the CLI never link it, and the
        // Dockerfile strips the apple-only blocks (private repo).
        // apple-only-begin
        .package(url: "https://github.com/AttilaTheFun/communication.git", exact: "0.2.1"),
        // apple-only-end
    ],
    targets: [
        // Part I as pure functions: borsh, hashing, Merkle, the DAG,
        // attestations, commitment batches and the witnessed log, forks, and
        // the Part II formats. Nothing but swift-crypto.
        // Foundation for the node's modules: FoundationEssentials on WebAssembly.
        .target(name: "ConvoFoundation"),
        .target(name: "ConvoCore", dependencies: ["ConvoFoundation", .product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "ConvoCoreTests", dependencies: ["ConvoCore"]),
        // §1's MLS: TreeKEM, the key schedule, HPKE, group state and
        // application-message sealing, on the spec's ciphersuite. A compact
        // implementation of RFC 9420's core, not a conformance-tested one.
        .target(name: "ConvoMLS", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "ConvoMLSTests", dependencies: ["ConvoMLS"]),
        // §12–16 for a client: sync over a data channel, the node's HTTP API
        // and its client, health scoring, receipts and acks.
        .target(name: "ConvoNet", dependencies: ["ConvoFoundation", "ConvoCore"]),
        .testTarget(name: "ConvoNetTests", dependencies: ["ConvoNet"]),
        .testTarget(name: "ConvoCallingTests", dependencies: ["ConvoNet"]),
        // The reference node (§13–16, Part II): mailbox with receipts and
        // signed responses, acks, key packages, blobs, discovery and
        // rendezvous, an RFC 5389/5766 STUN/TURN server, ICE credentials,
        // its log with checkpoints, and witnessing for other nodes (§11).
        // Its own HTTP server, so it runs on Linux with nothing but
        // Foundation and swift-crypto.
        // The node's portable core: the request handler, the mailbox, the log
        // and its witnessing (LogKeeper), wakes and rate limits. No sockets,
        // threads of its own or URLSession, so it also builds for WebAssembly
        // (a Cloudflare Durable Object hosts it there).
        .target(name: "ConvoNodeCore", dependencies: ["ConvoFoundation", "ConvoCore", "ConvoNet", .product(name: "Crypto", package: "swift-crypto")]),
        .target(name: "ConvoNode", dependencies: ["ConvoNodeCore", "ConvoCore", "ConvoNet", .product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "ConvoNodeTests", dependencies: ["ConvoNode"]),
        // The client: identities and KeyPackages, the MLS genesis handshake,
        // group sessions (DAG, MLS, receipts), host selection (§13.1), node
        // directory, on-disk store, and the client loop that publishes to
        // hosts, fetches, acks, attests, checks commitments, reports fraud,
        // syncs with peers over a data channel, forks and republishes.
        // The synchronous core of a client: identities and KeyPackages, the
        // genesis handshake, and `GroupState` (DAG, MLS, receipts).
        // No concurrency, no networking, so a host without either (the
        // browser build) can drive it.
        .target(name: "ConvoSession", dependencies: ["ConvoCore", "ConvoMLS", "ConvoNet", .product(name: "Crypto", package: "swift-crypto")]),
        .target(name: "ConvoClient", dependencies: ["ConvoSession", "ConvoCore", "ConvoMLS", "ConvoNet", .product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "ConvoClientTests", dependencies: ["ConvoClient", "ConvoNode"]),
        // The reference CLI client (§0) as a library, so the end-to-end
        // tests drive it in process, and the `convo` binary around it.
        .target(name: "ConvoCLI", dependencies: ["ConvoClient"]),
        .testTarget(name: "ConvoCLITests", dependencies: ["ConvoCLI", "ConvoNode"]),
        .executableTarget(name: "convo", dependencies: ["ConvoCLI"]),
        // The node binary's options and runtime, and `convo-node` around it
        // (the OCI image's entrypoint, see Dockerfile).
        .target(name: "ConvoNodeMain", dependencies: ["ConvoNode"]),
        .testTarget(name: "ConvoNodeMainTests", dependencies: ["ConvoNodeMain"]),
        .executableTarget(name: "convo_node", dependencies: ["ConvoNodeMain"]),
        // Part III on Apple platforms: a DataChannel over a Communication
        // peer connection, signaled through a node's rendezvous boxes with
        // the node's ICE servers.
        // apple-only-begin
        .target(name: "ConvoWebRTC", dependencies: [
            "ConvoCore", "ConvoNet",
            .product(name: "Communication", package: "communication", condition: .when(platforms: [.iOS, .macOS])),
        ]),
        // Part III §25 on Apple platforms: a call on the connection that
        // carries the data channel, with capture and video views from the
        // Communication backend. The frames themselves are in ConvoNet.
        .target(name: "ConvoCalling", dependencies: [
            "ConvoCore", "ConvoNet",
            .product(name: "Communication", package: "communication", condition: .when(platforms: [.iOS, .macOS])),
            .product(name: "CommunicationWebRTC", package: "communication", condition: .when(platforms: [.iOS, .macOS])),
        ]),
        // apple-only-end
        .executableTarget(name: "LoopbackChat", dependencies: ["ConvoClient", "ConvoNode"], path: "Examples/LoopbackChat"),
    ]
)
