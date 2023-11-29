import XCTest
@testable import Blake2

final class Blake2bTests: XCTestCase {
    let tests = Resources.inst.blake2testCases().blake2b

    func testSimpleApi() {
        for test in self.tests {
            let computed = Blake2b.hash(input: Array(test.in), key: Array(test.key))
            XCTAssertEqual(Array(test.out), computed)
        }
    }

    func testStreamingApi() {
        let tests = self.tests.keyed
        var buf = [UInt8](repeating: 0, count: tests.count)
        for i in 0..<buf.count {
            buf[i] = UInt8(i)
        }
        for step in 1..<Blake2b.Constants.BLOCKBYTES {
            for i in 0..<tests.count {
                let test = tests[i]
                var blake2 = Blake2b(key: Array(test.key))

                var mlen = i, start = 0

                while mlen >= step {
                    blake2.update(input: Array(buf[start..<start+step]))
                    start += step
                    mlen -= step
                }
                blake2.update(input: Array(buf[start..<start+mlen]))
                let hash = blake2.finalize()
                XCTAssertEqual(Array(test.out), hash)
            }
        }
    }
}
