// swift-tools-version: 5.9
//
// Declares the external Swift packages Convo consumes. rules_swift_package_manager
// reads this (plus Package.resolved) and generates Bazel targets from Apple's
// own manifest — so the WASI excludes, OPENSSL_NO_ASM and pthread-disabling
// defines come from upstream rather than being reproduced by hand.
import PackageDescription

let package = Package(
    name: "convo_deps",
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    ]
)
