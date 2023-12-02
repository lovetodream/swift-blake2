// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "swift-blake2",
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
