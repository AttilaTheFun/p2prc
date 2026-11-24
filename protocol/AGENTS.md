# The protocol package, for agents

- The spec is normative: `Docs/convo-protocol-spec-v2.0.md`. When code and
  spec disagree, fix one and record it in `Docs/deviations.md`. Never let one
  silently win.
- Layout is fixed: `protocol/` holds `README.md`, `AGENTS.md`,
  `Package.swift`, `Package.resolved`, `.gitignore`, `Dockerfile` and
  `TODO.md`; everything else lives under `Docs/`, `Sources/`, `Tests/`,
  `Examples/` and `Worker/`. The apps consume the package from this
  repository through rules_swift_package_manager (`.package(path:)` in
  `third_party/swift_packages`).
- `swift build` and `swift test` run on Linux (`swift:6.4.2-noble`, with
  the `apple-only` blocks of `Package.swift` stripped as the Dockerfile
  does) and on a Mac for the Apple targets.
- Tests use swift Testing (`swift test`). Vectors under `Tests/Vectors` are
  generated on first run and checked afterwards; delete the directory to
  regenerate when a preimage changes, and bump the protocol version.
- Ed25519 signatures are randomized on Apple platforms: never assert a
  signature's bytes, only that it verifies.
- The node must build on Linux: `ConvoNode`, `ConvoNodeMain`, `convo_node`
  import nothing Apple-only. `ConvoWebRTC` and `ConvoCalling` are Apple-only
  by design.
- Node tests and client tests run nodes in process through `NodeTransport`,
  witnessing one another; do not open sockets in tests.
- Nodes are held to account by witnesses and fraud proofs alone (§11, §17),
  so anyone can run one for free; keep it that way.
