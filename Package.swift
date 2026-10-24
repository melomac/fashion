// swift-tools-version: 6.2

import PackageDescription

// --exact ends a Mach-O where codesign's strict validation does; SECURITY_STRICT_VALIDATION=NO in the environment builds
// the other ending, past every byte the load commands reference (see MachO.logicalEnd()). Xcode reads this, not
// fashion.xcconfig, when it opens the package.
let strictValidation: [SwiftSetting] = Context.environment["SECURITY_STRICT_VALIDATION"] == "NO" ? [] : [.define("SECURITY_STRICT_VALIDATION")]

let package = Package(
    name: "fashion",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.8.0"),
    ],
    targets: [
        // CSSDeep, CTLSH, CUCL and CLZMA, in Bridges/ apart from fashion's own sources, compile the submodules' sources
        // through one-line includes, so the headers SwiftPM needs are tracked there: it runs neither ssdeep's autotools
        // nor TLSH's CMake. CTLSH also holds the C interface Swift calls TLSH's C++ through. CUCL and CLZMA are the
        // decompressors UPX unpacks with, from its own vendor branches of UCL and of the LZMA SDK.
        .target(
            name: "CSSDeep",
            path: "Bridges/CSSDeep",
            cSettings: [
                .disableWarning("shorten-64-to-32"),
            ],
        ),
        .target(
            name: "CTLSH",
            path: "Bridges/CTLSH",
            cxxSettings: [
                .headerSearchPath("../../submodules/tlsh/include"),
                // TLSH's layout depends on these defines, and its digests on the layout (see tlsh_version.h).
                .define("BUCKETS_128"),
                .define("CHECKSUM_1B"),
            ],
        ),
        .target(
            name: "CUCL",
            path: "Bridges/CUCL",
            cSettings: [
                .headerSearchPath("../../submodules/ucl/include"),
                .headerSearchPath("../../submodules/ucl"),
            ],
        ),
        .target(
            name: "CLZMA",
            path: "Bridges/CLZMA",
        ),
        .target(
            name: "CMachOCompat",
        ),
        .executableTarget(
            name: "fashion",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "CLZMA",
                "CMachOCompat",
                "CSSDeep",
                "CTLSH",
                "CUCL",
            ],
            swiftSettings: strictValidation,
        ),
        .testTarget(
            name: "fashionTests",
            dependencies: ["fashion"],
            swiftSettings: strictValidation,
        ),
    ],
)
