import XCTest
@testable import Blake2

final class Blake2bTests: XCTestCase {
    let tests = Resources.inst.blake2testCases().blake2b

    func testSimpleApi() {
        for test in self.tests {
            print(test)
            let computed = Blake2b.hash(input: Array(test.in), key: Array(test.key))
            print(computed)
            XCTAssertEqual(Array(test.out), computed)
        }
    }
}
