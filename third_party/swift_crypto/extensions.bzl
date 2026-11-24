"""Fetches Apple's swift-crypto.

Ideally this would go through rules_swift_package_manager so the build settings
came straight from Apple's Package.swift. That is currently blocked: isomer
declares its own `swift_deps.from_package`, and the extension names generated
repos after package identity, so two declarations that share any transitive
dependency (swift-asn1, here) collide. See the note in the isomer handoff.

So the BUILD file alongside this reproduces the three settings that matter for
WASI, taken from Apple's manifest. The *cryptography* is still entirely theirs —
only the build metadata is ours.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _swift_crypto_impl(_module_ctx):
    http_archive(
        name = "swift_crypto",
        build_file = "//third_party/swift_crypto:swift_crypto.BUILD",
        strip_prefix = "swift-crypto-4.5.1",
        url = "https://github.com/apple/swift-crypto/archive/refs/tags/4.5.1.tar.gz",
    )

swift_crypto = module_extension(implementation = _swift_crypto_impl)
