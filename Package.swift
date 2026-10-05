// swift-tools-version: 6.1

import PackageDescription

// TLSH's layout depends on these defines, so its library and the wrapper that includes its headers must share them.
let tlshSettings: [CXXSetting] = [
    .headerSearchPath("../../submodules/tlsh/include"),
    .define("BUCKETS_128"),
    .define("CHECKSUM_1B"),
]

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
        // are tracked here: it runs neither ssdeep's autotools nor TLSH's CMake.
        .target(
            name: "CSSDeep",
        ),
        .target(
            name: "CTLSH",
            cxxSettings: tlshSettings,
        ),
        .target(
            name: "CTLSHWrapper",
            dependencies: ["CTLSH"],
            cxxSettings: tlshSettings,
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
                "CTLSHWrapper",
            ],
        ),
        .testTarget(
            name: "fashionTests",
            dependencies: ["fashion"],
        ),
    ],
)
