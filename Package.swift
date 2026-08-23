// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "swift-blake2",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "BLAKE2", targets: ["BLAKE2"]),
    ],
    targets: [
        .target(name: "BLAKE2"),
        .testTarget(
            name: "BLAKE2Tests",
            dependencies: ["BLAKE2"],
            resources: [.copy("TestVectors")]
        ),
    ]
)
