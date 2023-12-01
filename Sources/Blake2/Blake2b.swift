public struct Blake2b: Sendable {
    public static let OUTBYTES = 64

    enum Constants {
        static let BLOCKBYTES = 128
        static let KEYBYTES = 64
        static let SALTBYTES = 16
        static let PERSONALBYTES = 16
    }

    struct State {
        var buf: [UInt8]
        var h: [UInt64]
        var t: [UInt64]
        var f: [UInt64]
        /// Pointer in ``buf``.
        var c: Int
        var outLength: Int

        init() {
            self.buf = .init(repeating: 0, count: Constants.BLOCKBYTES)
            self.h = .init(repeating: 0, count: 8)
            self.t = .init(repeating: 0, count: 2)
            self.f = .init(repeating: 0, count: 2)
            self.c = 0
            self.outLength = 0
        }
    }

    static let parameterBlock: [UInt8] = [
        0, 0, 0, 0, //  0: outlen, keylen, fanout, depth
        0, 0, 0, 0, //  4: leaf length, sequential mode
        0, 0, 0, 0, //  8: node offset
        0, 0, 0, 0, // 12: node offset
        0, 0, 0, 0, // 16: node depth, inner length, rfu
        0, 0, 0, 0, // 20: rfu
        0, 0, 0, 0, // 24: rfu
        0, 0, 0, 0, // 28: rfu
        0, 0, 0, 0, // 32: salt
        0, 0, 0, 0, // 36: salt
        0, 0, 0, 0, // 40: salt
        0, 0, 0, 0, // 44: salt
        0, 0, 0, 0, // 48: personal
        0, 0, 0, 0, // 52: personal
        0, 0, 0, 0, // 56: personal
        0, 0, 0, 0 // 60: personal
    ]

    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]

    private static let sigma: [[UInt8]] = [
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
        [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
        [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
        [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
        [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
        [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
        [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
        [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
        [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
        [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
        [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ]
    ]

    private var state: State! // guaranteed to be initialized in init by call to initialize function

    public init(key: [UInt8]?, outLength: Int = Self.OUTBYTES, salt: [UInt8]? = nil, personal: [UInt8]? = nil) {
        self.initialize(outLength: outLength, key: key, salt: salt, personal: personal)
    }

    private mutating func incrementCounter(by inc: UInt64) {
        self.state.t[0] += inc
        self.state.t[1] += self.state.t[0] < inc ? 1 : 0
    }

    private mutating func compress() {
        @inline(__always)
        func g(
            _ r: Int, _ i: Int,
            _ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64
        ) {
            a = a &+ b &+ m[Int(Blake2b.sigma[r][2 * i + 0])]
            d = rotr64(d ^ a, 32)
            c = c &+ d
            b = rotr64(b ^ c, 24)
            a = a &+ b &+ m[Int(Blake2b.sigma[r][2 * i + 1])]
            d = rotr64(d ^ a, 16)
            c = c &+ d
            b = rotr64(b ^ c, 63)
        }

        @inline(__always)
        func round(_ r: Int) {
            v.withUnsafeMutableBufferPointer { p in
                g(r, 0, &p[0], &p[4], &p[ 8], &p[12])
                g(r, 1, &p[1], &p[5], &p[ 9], &p[13])
                g(r, 2, &p[2], &p[6], &p[10], &p[14])
                g(r, 3, &p[3], &p[7], &p[11], &p[15])
                g(r, 4, &p[0], &p[5], &p[10], &p[15])
                g(r, 5, &p[1], &p[6], &p[11], &p[12])
                g(r, 6, &p[2], &p[7], &p[ 8], &p[13])
                g(r, 7, &p[3], &p[4], &p[ 9], &p[14])
            }
        }


        var m = [UInt64](repeating: 0, count: 16)
        var v = [UInt64](repeating: 0, count: 16)

        for i in 0..<16 {
            m[i] = load64(self.state.buf, i: i * MemoryLayout<UInt64>.size)
        }

        for i in 0..<8 {
            v[i] = self.state.h[i]
        }

        v[8] =  Self.iv[0]
        v[9] =  Self.iv[1]
        v[10] = Self.iv[2]
        v[11] = Self.iv[3]
        v[12] = Self.iv[4] ^ self.state.t[0]
        v[13] = Self.iv[5] ^ self.state.t[1]
        v[14] = Self.iv[6] ^ self.state.f[0]
        v[15] = Self.iv[7] ^ self.state.f[1]

        round( 0)
        round( 1)
        round( 2)
        round( 3)
        round( 4)
        round( 5)
        round( 6)
        round( 7)
        round( 8)
        round( 9)
        round(10)
        round(11)

        for i in 0..<8 {
            self.state.h[i] = self.state.h[i] ^ v[i] ^ v[i + 8]
        }
    }

    private mutating func initialize(outLength: Int, key: [UInt8]?, salt: [UInt8]?, personal: [UInt8]?) {
        assert(
            outLength != 0 && outLength <= Self.OUTBYTES,
            """
            Illegal output length expected length to be within range \
            0...\(Self.OUTBYTES), but actual length is \(outLength).
            """
        )
        assert(
            key?.count ?? 0 <= Constants.KEYBYTES,
            """
            Illegal key length, expected length to be within range \
            0...\(Constants.KEYBYTES), but actual length is \(key?.count ?? 0).
            """
        )
        assert(
            personal?.count ?? Constants.SALTBYTES == Constants.SALTBYTES,
            """
            Illegal salt length, expected length to be within range \
            0...\(Constants.SALTBYTES), but actual length is \
            \(personal?.count ?? Constants.SALTBYTES).
            """
        )
        assert(
            personal?.count ?? Constants.PERSONALBYTES == Constants.SALTBYTES,
            """
            Illegal personal length, expected length to be within range \
            0...\(Constants.PERSONALBYTES), but actual length is \
            \(personal?.count ?? Constants.PERSONALBYTES).
            """
        )

        var ctx = State()
        ctx.outLength = outLength
        var parameterBlock = Self.parameterBlock
        parameterBlock[0] = UInt8(outLength)
        if let key {
            parameterBlock[1] = UInt8(key.count)
        }
        parameterBlock[2] = 1 // fanout
        parameterBlock[3] = 1 // depth
        if let salt {
            parameterBlock[32..<(32 + salt.count)] = ArraySlice(salt)
        }
        if let personal {
            parameterBlock[48..<(48 + personal.count)] = ArraySlice(personal)
        }

        // init hash state
        for i in 0..<8 {
            ctx.h[i] = Self.iv[i] ^ load64(parameterBlock, i: i * MemoryLayout<UInt64>.size)
        }

        self.state = ctx

        // key hash, if needed
        if let key, !key.isEmpty {
            self.update(input: key)
            self.state.c = Constants.BLOCKBYTES
        }
    }

    public mutating func update(input: [UInt8]) {
        for i in 0..<input.count {
            if self.state.c == Constants.BLOCKBYTES {
                // buffer full?
                self.incrementCounter(by: UInt64(Constants.BLOCKBYTES))
                self.compress()
                self.state.c = 0
            }
            self.state.buf[self.state.c] = input[i]
            self.state.c += 1
        }
    }

    public mutating func finalize() -> [UInt8] {
        self.incrementCounter(by: UInt64(self.state.c)) // mark last block offset

        while self.state.c < Constants.BLOCKBYTES {
            self.state.buf[self.state.c] = 0
            self.state.c += 1
        }

        // indicate last block
        self.state.f[0] = UInt64.max
        self.compress()

        var out = [UInt8](repeating: 0, count: self.state.outLength)
        for i in 0..<self.state.outLength {
            out[i] = UInt8((self.state.h[i >> 3] >> (8 * (i & 7))) & 0xFF)
        }
        return out
    }

    public static func hash(
        input: [UInt8],
        key: [UInt8]?,
        outLength: Int = Self.OUTBYTES,
        salt: [UInt8]? = nil,
        personal: [UInt8]? = nil
    ) -> [UInt8] {
        var hasher = Blake2b(key: key, outLength: outLength, salt: salt, personal: personal)
        hasher.update(input: input)
        return hasher.finalize()
    }
}

@inline(__always)
private func load64(_ src: [UInt8], i: Int) -> UInt64 {
    let p = src[i..<(i + 8)]
    // had to split one out so the compiler can type check in time
    let p1 = UInt64(p[i + 0]) << 0
    return p1 |
    (UInt64(p[i + 1]) << 8) |
    (UInt64(p[i + 2]) << 16) |
    (UInt64(p[i + 3]) << 24) |
    (UInt64(p[i + 4]) << 32) |
    (UInt64(p[i + 5]) << 40) |
    (UInt64(p[i + 6]) << 48) |
    (UInt64(p[i + 7]) << 56)
}

@inline(__always)
private func rotr64(_ w: UInt64, _ c: UInt8) -> UInt64 {
    (w >> c) | (w << (64 - c))
}
