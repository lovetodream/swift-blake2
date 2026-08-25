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

extension BLAKE2b {
    public struct Digest: RandomAccessCollection, Equatable {
        public typealias Index = Int
        public typealias Element = UInt8

        @usableFromInline
        var buffer = [64 of UInt8](repeating: 0)

        public let count: Int

        public var startIndex: Int { 0 }
        public var endIndex: Int { count }

        @inlinable
        public subscript(position: Int) -> UInt8 {
            precondition(position >= 0 && position < count, "Index out of bounds")
            return buffer[position]
        }

        @usableFromInline
        init(length: Int) {
            self.count = length
        }

        public static func == (lhs: Digest, rhs: Digest) -> Bool {
            guard lhs.count == rhs.count else { return false }

            var difference: UInt8 = 0

            // constant time comparison to combat timing attacks
            for i in 0..<lhs.count {
                difference |= lhs.buffer[i] ^ rhs.buffer[i]
            }

            return difference == 0
        }
    }
}
