# swift-blake2

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Flovetodream%2Fswift-blake2%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/lovetodream/swift-blake2)
 [![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Flovetodream%2Fswift-blake2%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/lovetodream/swift-blake2)
[![codecov](https://codecov.io/gh/lovetodream/swift-blake2/graph/badge.svg?token=OCL780HP60)](https://codecov.io/gh/lovetodream/swift-blake2)

A pure Swift implementation of BLAKE2.

[RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)](https://datatracker.ietf.org/doc/html/rfc7693)

## Usage

You can compute digest in a single step using the static 
`hash(data:key:digestLength:salt:)` method.

```swift
let digest = try BLAKE2b.hash(data: "hello, world!".utf8.span)
```

If you want to compute the digest of a large amount of data, you can initialize
an instance of `BLAKE2b` and call `update(data:)` as often as you need to.
To finalize and return the digest, call `finalize()`.

```swift
var hasher = try BLAKE2b()
hasher.update(data: "hello, ".utf8.span)
hasher.update(data: "world!".utf8.span)
let digest = hasher.finalize()
```
