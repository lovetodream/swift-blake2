// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "swift-blake2",
    products: [
        .library(name: "Blake2", targets: ["Blake2"]),
    ],
    targets: [
        .target(name: "Blake2"),
        .testTarget(
            name: "Blake2Tests",
            dependencies: ["Blake2"],
            resources: [.copy("TestVectors")]
        ),
    ]
)
