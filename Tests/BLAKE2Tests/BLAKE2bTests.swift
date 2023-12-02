import XCTest
@testable import BLAKE2

final class BlAKE2bTests: XCTestCase {
    let tests = Resources.inst.blake2testCases().blake2b

    func testSimpleApi() throws {
        for test in self.tests {
            let computed = try BLAKE2b.hash(data: test.in, key: test.key)
            XCTAssertEqual(test.out, computed)
        }
    }

    func testStreamingApi() throws {
        let tests = self.tests.keyed
        var buf = [UInt8](repeating: 0, count: tests.count)
        for i in 0..<buf.count {
            buf[i] = UInt8(i)
        }
        for step in 1..<BLAKE2b.Constants.BLOCKBYTES {
            for i in 0..<tests.count {
                let test = tests[i]
                var blake2 = try BLAKE2b(key: test.key)

                var mlen = i, start = 0

                while mlen >= step {
                    blake2.update(data: buf[start..<start+step])
                    start += step
                    mlen -= step
                }
                blake2.update(data: buf[start..<start+mlen])
                let hash = blake2.finalize()
                XCTAssertEqual(test.out, hash)
            }
        }
    }
}
