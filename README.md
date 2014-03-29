Named-Data Network (NDN)
========================
This package provides elegant and simple ndn library for research and testing purpose.
NDN evolves quickly, and the latest format that the current implementation follows is on [ndn doc](http://named-data.net/doc/ndn-tlv/)
This package is intended to work with nfd, the new NDN forwarding daemon.

The author is taylorchu (Tai-Lin Chu). This package is released under GPL2 license.

To use this packege, you should do `import "github.com/taylorchu/ndn"`.
Detailed Documentation is on [godoc](https://godoc.org/github.com/taylorchu/ndn).

The current test coverage is about half (52.5%), so I hope someone can help me reach 100%.

What is it?
===========
1. TLV (tlv.go)
2. Raw NDN TLV encoder/decoder (encoding.go)
3. NDN packet management in go (ndn.go)
4. NDN server/client abstraction (WIP)

![Imgur](http://i.imgur.com/68hMHZu.png?1)

Benchmark
=========
```
BenchmarkDataSHA256Encode      50000         33806 ns/op
BenchmarkDataSHA256Decode      50000         41343 ns/op
BenchmarkDataRSAEncode        50      37952106 ns/op
BenchmarkDataRSADecode     20000        100177 ns/op
BenchmarkInterestEncode   200000         13261 ns/op
BenchmarkInterestDecode   100000         25194 ns/op
```
Note: RSA key is 2048 bits. 

In general, creating Interests is quick, creating sha256 data is 2x slower, and creating rsa data is 4000x slower.
Except for RSA encoding, encoding is faster than decoding.
