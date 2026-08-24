//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-blake2 open source project
//
// Copyright (c) 2026 Timo Zacherl
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Benchmark
import BLAKE2

let benchmarks: @Sendable () -> Void = {
    Benchmark.defaultConfiguration = .init(
        metrics: [
            .wallClock,
            .mallocCountTotal,
            .throughput
        ],
        warmupIterations: 10,
        maxDuration: .seconds(2),
        maxIterations: 10_000
    )

    Benchmark("BLAKE2b-Hash-1KB") { benchmark in
        let message = [UInt8](repeating: 0x42, count: 1024)

        benchmark.startMeasurement()

        let result = try! BLAKE2b.hash(data: message)
        blackHole(result)

        benchmark.stopMeasurement()
    }

    Benchmark("TD-Lockstep-State (128 Bytes)") { benchmark in
        let gameState = [UInt8](repeating: 0x01, count: 128)

        benchmark.startMeasurement()

        let hash = try! BLAKE2b.hash(data: gameState)
        blackHole(hash)

        benchmark.stopMeasurement()
    }

    Benchmark("TD-Savegame-AntiCheat (50 KB + Key)") { benchmark in
        let saveGameData = [UInt8](repeating: 0x42, count: 50_000)
        let secretServerKey = [UInt8]("my_super_secret_td_key_123".utf8)

        benchmark.startMeasurement()

        let signature = try! BLAKE2b.hash(data: saveGameData, key: secretServerKey)
        blackHole(signature)

        benchmark.stopMeasurement()
    }

    Benchmark("TD-Asset-Streaming (5 MB in 4 KB Chunks)") { benchmark in
        let chunkSize = 4096
        let totalSize = 5 * 1024 * 1024 // 5 MB
        let simulatedChunk = [UInt8](repeating: 0x99, count: chunkSize)

        benchmark.startMeasurement()

        var hasher = try! BLAKE2b()

        var bytesProcessed = 0
        while bytesProcessed < totalSize {
            hasher.update(data: simulatedChunk)
            bytesProcessed += chunkSize
        }

        let finalHash = hasher.finalize()
        blackHole(finalHash)

        benchmark.stopMeasurement()
    }
}
