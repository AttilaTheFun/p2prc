// swift-tools-version: 6.0

// The Convo node as a WebAssembly reactor for a Cloudflare Durable Object
// (README.md here). Built for WASI only:
//   swift build --swift-sdk <wasm sdk> -c release --product convo_node_worker
import PackageDescription

let package = Package(
    name: "convo_node_worker",
    dependencies: [
        .package(path: ".."),
        // 4.0 and later build on FoundationEssentials, so no ICU in the module.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "convo_node_worker",
            dependencies: [
                .product(name: "ConvoNodeCore", package: "protocol"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            linkerSettings: [.unsafeFlags([
                // A reactor: no main, `_initialize` once, then calls.
                "-Xclang-linker", "-mexec-model=reactor",
                // Only what the Durable Object calls, so the rest is dead-stripped.
                "-Xlinker", "--export=convo_alloc", "-Xlinker", "--export=convo_free",
                "-Xlinker", "--export=convo_result_ptr", "-Xlinker", "--export=convo_result_len",
                "-Xlinker", "--export=convo_node_init", "-Xlinker", "--export=convo_node_handle",
                "-Xlinker", "--export=convo_node_alarm", "-Xlinker", "--export=convo_node_answers",
                "-Xlinker", "--export=convo_node_logs",
                "-Xlinker", "--gc-sections", "-Xlinker", "--strip-all",
                // Swift's generic metadata recursion outgrows wasm-ld's 1 MiB default stack.
                "-Xlinker", "-z", "-Xlinker", "stack-size=8388608",
            ])]
        ),
    ]
)
