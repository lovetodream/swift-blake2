// swift-tools-version: 6.2
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

if Context.environment["ENABLE_BLAKE2_BENCHMARKS"] != nil {
    package.platforms = [.macOS(.v26)]
    package.dependencies.append(
        .package(url: "https://github.com/ordo-one/benchmark", from: "1.0.0")
    )
    package.targets.append(
        .executableTarget(
            name: "BLAKE2Benchmarks",
            dependencies: [
                .product(name: "Benchmark", package: "benchmark"),
                "BLAKE2",
            ],
            path: "Benchmarks/BLAKE2Benchmarks",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "benchmark")
            ]
        )
    )
}
