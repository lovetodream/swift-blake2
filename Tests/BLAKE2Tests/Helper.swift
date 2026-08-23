#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Synchronization

struct Blake2TestCase: Decodable {
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

extension Array where Element == Blake2TestCase {
    var blake2b: Self { self.filter { $0.hash == "blake2b" } }
    var blake2s: Self { self.filter { $0.hash == "blake2s" } }
    var blake2bp: Self { self.filter { $0.hash == "blake2bp" } }
    var blake2sp: Self { self.filter { $0.hash == "blake2sp" } }
    var blake2xb: Self { self.filter { $0.hash == "blake2xb" } }
    var blake2xs: Self { self.filter { $0.hash == "blake2xs" } }

    var unkeyed: Self { self.filter { $0.key.count == 0 } }
    var keyed: Self { self.filter { $0.key.count > 0 } }
}

final class Resources: Sendable {
    private let blake2kat: Mutex<[Blake2TestCase]?> = Mutex(nil)

    func fileUrl(name: String) -> URL {
        Bundle.module.url(forResource: name, withExtension: nil, subdirectory: nil)!
    }

    func blake2testCases() -> [Blake2TestCase] {
        self.blake2kat.withLock { blake2kat in
            guard let b2k = blake2kat else {
                let data = try! Data(contentsOf: self.fileUrl(name: "TestVectors/blake2-kat.json"))
                let decoder = JSONDecoder()
                decoder.dataDecodingStrategy = .hex
                let decoded = try! decoder.decode([Blake2TestCase].self, from: data)
                blake2kat = decoded
                return decoded
            }
            return b2k
        }
    }

    static let inst = Resources()
}
