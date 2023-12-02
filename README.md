# swift-blake2

A pure Swift implementation of BLAKE2.

[RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://datatracker.ietf.org/doc/html/rfc7693)

If you don't want to add yet another dependency to your project, you can copy the file
[`BLAKE2b.swift`](https://github.com/lovetodream/swift-blake2/blob/main/Sources/BLAKE2/BLAKE2b.swift)
(Do not remove the license header!).

## Usage

You can compute digest in a single step using the static 
`hash(data:key:outLength:salt:)` method.

```swift
let digest = try BLAKE2b.hash(data: "hello, world!".data(using: .utf8)!)
```

If you want to compute the digest of a large amount of data, you can initialize
an instance of `BLAKE2b` and call `update(data:)` as often as you need to.
To finalize and return the digest, call `finalize()`.

```swift
var hasher = try BLAKE2b()
hasher.update(data: "hello, ".data(using: .utf8)!)
hasher.update(data: "world!".data(using: .utf8)!)
let digest = hasher.finalize()
```
