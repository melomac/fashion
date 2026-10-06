// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "fashion",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
    ],
    targets: [
        // CSSDeep and CTLSH compile the submodules' sources through one-line includes, so the headers SwiftPM needs
        // are tracked here: it runs neither ssdeep's autotools nor TLSH's CMake. CTLSH also holds the C interface Swift
        // calls TLSH's C++ through.
        .target(
            name: "CSSDeep",
        ),
        .target(
            name: "CTLSH",
            cxxSettings: [
                .headerSearchPath("../../submodules/tlsh/include"),
                // TLSH's layout depends on these defines, and its digests on the layout (see tlsh_version.h).
                .define("BUCKETS_128"),
                .define("CHECKSUM_1B"),
            ],
        ),
        .target(
            name: "CMachOCompat",
        ),
        .executableTarget(
            name: "fashion",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "CMachOCompat",
                "CSSDeep",
                "CTLSH",
            ],
        ),
        .testTarget(
            name: "fashionTests",
            dependencies: ["fashion"],
        ),
    ],
)
