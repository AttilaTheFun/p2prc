// swift-tools-version: 6.0

// The SwiftPM manifest rules_swift_package_manager consumes: isomer's Swift
// (its frameworks off Apple, SwiftUI) by the release's tag, the protocol
// (this repository's protocol/), Communication (the async,
// strict-concurrency Swift WebRTC API, with its Apple WebRTC backend), the
// chat interface and the team's kits. rspm reads Package.resolved for the
// pinned graph and generates one `@swiftpkg_<name>` repo per package.
import PackageDescription

let package = Package(
    name: "convo_swift_packages",
    platforms: [.iOS(.v18), .macOS(.v15)],
    dependencies: [
        // Isomer, by the tag of the release MODULE.bazel asks for.
        .package(url: "https://github.com/AttilaTheFun/isomer.git", revision: "v0.61.1"),
        // AgentUI (InboxUI, MessagesUI, NavigationUI over MessagesCore): the
        // chat interface.
        .package(
            url: "https://github.com/AttilaTheFun/agent_ui.git",
            revision: "d8f92f52c1bf8d1011b5ec006a91fa7889520489"
        ),
        .package(
            url: "https://github.com/AttilaTheFun/communication.git",
            revision: "029de5185bf1b9dbcbac59ea06d3484a305c3505"
        ),
        // Shireworks Kit: crash and bug reports (shake, or Help › Report a
        // Bug… on a Mac) and the update sheet; the Apple apps only.
        // A crash in this public repository is filed without its reason or
        // breadcrumbs (since 0.1.0).
        .package(url: "https://github.com/AttilaTheFun/shireworks_kit.git", exact: "0.2.0"),
        // Arguments for the repo's own tools (tools/convo_ci).
        .package(url: "https://github.com/apple/swift-argument-parser", exact: "1.8.2"),
        // build_tools: CI's shared tools (`sign`, for the Apple and Android
        // apps), built here and run by the alpha and release jobs.
        .package(url: "https://github.com/AttilaTheFun/build_tools.git", exact: "0.7.0"),
        // The protocol, its node and clients: this repository's protocol/
        // (its package identity "protocol", from the folder's name).
        .package(path: "../../protocol"),
    ]
)
