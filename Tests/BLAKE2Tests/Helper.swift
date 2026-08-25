import Foundation

@testable import BLAKE2
import Synchronization

struct BLAKE2TestCase: Decodable {
    let hash: String
    let `in`: [UInt8]
    let key: [UInt8]
    let out: [UInt8]

    enum CodingKeys: CodingKey {
        case hash
        case `in`
        case key
        case out
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.hash = try container.decode(String.self, forKey: .hash)
        self.in = try Array(container.decode(Data.self, forKey: .in))
        self.key = try Array(container.decode(Data.self, forKey: .key))
        self.out = try Array(container.decode(Data.self, forKey: .out))
    }
}

struct BLAKE2bTestCase {
    let hash: String
    let `in`: [UInt8]
    let key: [UInt8]
    let out: BLAKE2b.Digest

    init(_ tc: BLAKE2TestCase) {
        self.hash = tc.hash
        self.in = tc.in
        self.key = tc.key
        self.out = BLAKE2b.Digest(bytes: tc.out)
    }
}


extension BLAKE2b.Digest {
    init(bytes: [UInt8]) {
        self.init(length: bytes.count) // Nutzt den init, den wir vorher gebaut haben
        for i in 0..<bytes.count {
            self.buffer[i] = bytes[i]
        }
    }
}

extension JSONDecoder.DataDecodingStrategy {
    static let hex: Self = .custom { decoder in
        var container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        guard let data = string.data(using: .ascii), data.count % 2 == 0 else {
            throw DecodingError.dataCorrupted(DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Not a hex value: \(string)"
            ))
        }
        let prefix = string.hasPrefix("0x") ? 2 : 0
        let parsed = try data.withUnsafeBytes { hex in
            var result = Data()
            result.reserveCapacity((hex.count - prefix) / 2)
            var current: UInt8? = nil
            for idx in prefix ..< hex.count {
                let v: UInt8
                switch hex[idx] {
                case let c where c <= 57: v = c - 48
                case let c where c >= 65 && c <= 70: v = c - 55
                case let c where c >= 97: v = c - 87
                default:
                    throw DecodingError.dataCorrupted(.init(
                        codingPath: decoder.codingPath,
                        debugDescription: "Not a hex value: \(string)"
                    ))
                }
                if let val = current {
                    result.append(val << 4 | v)
                    current = nil
                } else {
                    current = v
                }
            }
            return result
        }
        return parsed
    }
}

extension Array where Element == BLAKE2TestCase {
    var blake2b: [BLAKE2bTestCase] { self.filter { $0.hash == "blake2b" }.map { BLAKE2bTestCase($0) } }
    var blake2s: Self { self.filter { $0.hash == "blake2s" } }
    var blake2bp: Self { self.filter { $0.hash == "blake2bp" } }
    var blake2sp: Self { self.filter { $0.hash == "blake2sp" } }
    var blake2xb: Self { self.filter { $0.hash == "blake2xb" } }
    var blake2xs: Self { self.filter { $0.hash == "blake2xs" } }
}

extension Array where Element == BLAKE2bTestCase {
    var unkeyed: Self { self.filter { $0.key.count == 0 } }
    var keyed: Self { self.filter { $0.key.count > 0 } }
}

final class Resources: Sendable {
    private let blake2kat: Mutex<[BLAKE2TestCase]?> = Mutex(nil)

    func fileUrl(name: String) -> URL {
        Bundle.module.url(forResource: name, withExtension: nil, subdirectory: nil)!
    }

    func blake2testCases() -> [BLAKE2TestCase] {
        self.blake2kat.withLock { blake2kat in
            guard let b2k = blake2kat else {
                let data = try! Data(contentsOf: self.fileUrl(name: "TestVectors/blake2-kat.json"))
                let decoder = JSONDecoder()
                decoder.dataDecodingStrategy = .hex
                let decoded = try! decoder.decode([BLAKE2TestCase].self, from: data)
                blake2kat = decoded
                return decoded
            }
            return b2k
        }
    }
    static let inst = Resources()
}
