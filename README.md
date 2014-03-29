Named-Data Network (NDN)
========================
This package provides elegant and simple ndn library for research and testing purpose.
NDN evolves quickly, and the latest format that the current implementation follows is on [ndn doc](http://named-data.net/doc/ndn-tlv/)
This package is intended to work with nfd, the new NDN forwarding daemon.

The author is taylorchu (Tai-Lin Chu). This package is released under GPL2 license.

To use this packege, you should do `import "github.com/taylorchu/ndn"`.
Detailed Documentation is on [godoc](https://godoc.org/github.com/taylorchu/ndn).
Use *_test.go as examples.

The current test coverage is about 70%. I hope someone can help me reach 100%.

What is it?
===========
1. TLV (tlv.go)
2. Raw NDN TLV encoder/decoder (encoding.go)
3. NDN packet management in go (ndn.go)
4. NDN server/client abstraction (WIP)
5. NFD forward daemon client api (nfd.go)

![Imgur](http://i.imgur.com/68hMHZu.png?1)

Benchmark
=========
```
BenchmarkDataSHA256Encode     100000         22272 ns/op
BenchmarkDataSHA256Decode     100000         27381 ns/op
BenchmarkDataRSAEncode       100      23419913 ns/op
BenchmarkDataRSADecode     50000         68238 ns/op
BenchmarkInterestEncode   200000          9064 ns/op
BenchmarkInterestDecode   100000         17223 ns/op
```
Note: RSA key is 2048 bits. 

In general, creating Interests is quick, creating sha256 data is 2x slower, and creating rsa data is 4000x slower.
Except for RSA encoding, encoding is faster than decoding.
