"""swift-crypto, built for every platform we target including wasm32-wasip1.

Apple's swift-crypto explicitly supports WASI. Its Package.swift excludes the
BoringSSL sources that need <netdb.h>, disables assembly, and turns off pthread
use; those three settings are reproduced below so the same library compiles for
wasm through rules_swift's Swift SDK.

Only the build metadata is ours — every line of cryptography is Apple's.
"""

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_swift//swift:swift.bzl", "swift_library")

package(default_visibility = ["//visibility:public"])

# From Package.swift: required on Wasm/WASI, which has no pthreads and no
# hand-written assembly.
_C_COPTS = [
    "-Wno-everything",
    # Keep toolchain header paths relative so Bazel's hermeticity check
    # accepts them when cross-compiling to wasm.
    "-no-canonical-prefixes",
    # BoringSSL is built without C++ exceptions or RTTI upstream, and has to be
    # here too: with them on, the .cc translation units emit landing pads
    # referencing __cxa_begin_catch, which wasm-ld cannot resolve when linking a
    # reactor (there is no libc++abi on the wasip1 link line).
    "-fno-exceptions",
    "-fno-rtti",
]

# BoringSSL's hand-written assembly comes in a per-OS/per-architecture matrix
# that wasm has no member of. Rather than maintain that matrix for one target
# that must opt out anyway, every platform uses the pure-C fallbacks: one code
# path, correct everywhere, at some speed cost on native builds. Key agreement
# and AES-GCM over chat-sized messages are nowhere near hot enough to notice.
_DEFINES = ["OPENSSL_NO_ASM"] + select({
    "@platforms//os:wasi": [
        # WASI preview1 has no pthreads.
        "OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
    ],
    "//conditions:default": [],
})

cc_library(
    name = "CCryptoBoringSSL",
    srcs = glob(
        [
            "Sources/CCryptoBoringSSL/crypto/**/*.cc",
            "Sources/CCryptoBoringSSL/crypto/**/*.h",
            "Sources/CCryptoBoringSSL/crypto/**/*.inc",
            "Sources/CCryptoBoringSSL/third_party/**/*.cc",
            "Sources/CCryptoBoringSSL/third_party/**/*.h",
            "Sources/CCryptoBoringSSL/third_party/**/*.inc",
            # Generated tables (error strings, curve data) live apart from the
            # hand-written sources.
            "Sources/CCryptoBoringSSL/gen/**/*.cc",
            "Sources/CCryptoBoringSSL/gen/**/*.h",
            "Sources/CCryptoBoringSSL/gen/**/*.inc",
        ],
        allow_empty = True,
        exclude = [
            # Excluded upstream too: WASI libc has no <netdb.h>, and nothing
            # here uses networking.
            "Sources/CCryptoBoringSSL/crypto/bio/connect.cc",
            "Sources/CCryptoBoringSSL/crypto/bio/socket_helper.cc",
            "Sources/CCryptoBoringSSL/crypto/bio/socket.cc",
            "Sources/CCryptoBoringSSL/**/*_test.*",
        ],
    ),
    hdrs = glob(["Sources/CCryptoBoringSSL/include/**/*.h"], allow_empty = True),
    copts = _C_COPTS,
    defines = _DEFINES,
    includes = ["Sources/CCryptoBoringSSL/include"],
    local_defines = _DEFINES,
)

cc_library(
    name = "CCryptoBoringSSLShims",
    srcs = glob(["Sources/CCryptoBoringSSLShims/*.c"], allow_empty = True),
    hdrs = glob(["Sources/CCryptoBoringSSLShims/include/**/*.h"], allow_empty = True),
    copts = _C_COPTS,
    includes = ["Sources/CCryptoBoringSSLShims/include"],
    deps = [":CCryptoBoringSSL"],
)

_PACKAGE_NAME = ["-package-name", "swift_crypto"]

swift_library(
    name = "CryptoBoringWrapper",
    srcs = glob(["Sources/CryptoBoringWrapper/**/*.swift"], allow_empty = True),
    copts = _PACKAGE_NAME,
    module_name = "CryptoBoringWrapper",
    deps = [
        ":CCryptoBoringSSL",
        ":CCryptoBoringSSLShims",
        # Isomer's Foundation on the web and Android (Apple's elsewhere); the
        # Swift SDK's would link beside it.
        "@@isomer+//:foundation",
    ],
)

# XKCP provides the Keccak/SHA-3 permutation. Header search paths mirror the
# ones Apple's manifest declares.
cc_library(
    name = "CXKCP",
    srcs = glob(
        [
            "Sources/CXKCP/**/*.c",
            "Sources/CXKCP/**/*.h",
            "Sources/CXKCP/**/*.inc",
        ],
        allow_empty = True,
    ),
    # .macros files are #included like headers, so they belong in hdrs —
    # cc_library rejects unknown extensions in srcs.
    hdrs = glob(
        ["Sources/CXKCP/include/**/*.h", "Sources/CXKCP/**/*.macros"],
        allow_empty = True,
    ),
    copts = _C_COPTS,
    local_defines = ["XKCP_has_KeccakP1600"],
    includes = [
        "Sources/CXKCP",
        "Sources/CXKCP/FIPS202-opt64",
        "Sources/CXKCP/include",
    ],
)

cc_library(
    name = "CXKCPShims",
    srcs = glob(["Sources/CXKCPShims/*.c"], allow_empty = True),
    hdrs = glob(["Sources/CXKCPShims/include/**/*.h"], allow_empty = True),
    copts = _C_COPTS,
    includes = ["Sources/CXKCPShims/include"],
    deps = [":CXKCP"],
)

# CRYPTO_IN_SWIFTPM selects the open-source BoringSSL backend rather than
# Apple's CryptoKit — required on wasm, and it keeps one code path everywhere.
swift_library(
    name = "Crypto",
    srcs = glob(["Sources/Crypto/**/*.swift"], allow_empty = True),
    copts = _PACKAGE_NAME,
    # CRYPTO_IN_SWIFTPM alone lets swift-crypto use CryptoKit on Apple
    # platforms and its own BoringSSL backend elsewhere — including wasm.
    # Forcing the BoringSSL path everywhere also forces the pure-C fallbacks
    # onto native builds, which is both slower and a needless divergence from
    # how Apple ships it.
    defines = ["CRYPTO_IN_SWIFTPM"] + select({
        # wasm, Android and Linux have no CryptoKit, so they take the open-source
        # BoringSSL path. Apple platforms keep CryptoKit, which is both faster
        # and the configuration Apple actually ships.
        "@platforms//os:wasi": ["CRYPTO_IN_SWIFTPM_FORCE_BUILD_API"],
        "@platforms//os:android": ["CRYPTO_IN_SWIFTPM_FORCE_BUILD_API"],
        "@platforms//os:linux": ["CRYPTO_IN_SWIFTPM_FORCE_BUILD_API"],
        "//conditions:default": [],
    }),
    module_name = "Crypto",
    deps = [
        ":CCryptoBoringSSL",
        ":CCryptoBoringSSLShims",
        ":CryptoBoringWrapper",
        ":CXKCP",
        ":CXKCPShims",
        "@@isomer+//:foundation",
    ],
)
