import Testing
@testable import BLAKE2

@Suite
struct BlAKE2bTests {
    let tests = Resources.inst.blake2testCases().blake2b

    @Test
    func simpleApi() throws {
        for test in self.tests {
            let computed = try BLAKE2b.hash(data: test.in.span, key: test.key.span)
            #expect(test.out == computed)
        }
    }

    @Test
    func streamingApi() throws {
        let tests = self.tests.keyed
        var buf = [UInt8](repeating: 0, count: tests.count)
        for i in 0..<buf.count {
            buf[i] = UInt8(i)
        }
        for step in 1..<BLAKE2b.Constants.BLOCKBYTES {
            for i in 0..<tests.count {
                let test = tests[i]
                var blake2 = try BLAKE2b(key: test.key.span)

                var mlen = i, start = 0

                while mlen >= step {
                    blake2.update(data: buf[start..<start+step].span)
                    start += step
                    mlen -= step
                }
                blake2.update(data: buf[start..<start+mlen].span)
                let hash = blake2.finalize()
                #expect(test.out == hash)
            }
        }
    }
}
