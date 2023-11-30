import Foundation

struct Blake2TestCase: Decodable {
    let hash: String
    let `in`: Data
    let key: Data
    let out: Data
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

final class Resources {
    private var blake2kat: [Blake2TestCase]? = nil

    func fileUrl(name: String) -> URL {
        Bundle.module.url(forResource: name, withExtension: nil, subdirectory: nil)!
    }

    func blake2testCases() -> [Blake2TestCase] {
        guard let b2k = self.blake2kat else {
            let data = try! Data(contentsOf: self.fileUrl(name: "blake2-kat.json"))
            let decoder = JSONDecoder()
            decoder.dataDecodingStrategy = .hex
            self.blake2kat = try! decoder.decode([Blake2TestCase].self, from: data)
            return self.blake2kat!
        }
        return b2k
    }

    static let inst = Resources()
}
