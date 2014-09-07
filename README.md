Named-Data Network (NDN)
========================
This package provides elegant and simple ndn library for research and testing purpose.
NDN evolves quickly, and the latest format that the current implementation follows is on [ndn doc](http://named-data.net/doc/ndn-tlv/)
This package is intended to work with nfd, the new NDN forwarding daemon.

The author is taylorchu (Tai-Lin Chu). This package is released under GPL2 license.

Get started
===========
1. [install and run nfd](http://named-data.net/doc/NFD/current/INSTALL.html)
2. [set up go work environment](https://golang.org/doc/install)
3. get this package by running `go get "github.com/taylorchu/ndn"`
4. read nice and detailed documentation with examples on __[godoc](https://godoc.org/github.com/taylorchu/ndn)__
	(Testcases in *_test.go are extra examples.)


![Imgur](http://i.imgur.com/68hMHZu.png?1)

Changelog
=========

```
2014-01: first release with go reflection
2014-04: update ecdsa key implementation
2014-08: refactor with interface
2014-09: support [naming convention](http://named-data.net/doc/tech-memos/naming-conventions.pdf)
```

Benchmark
=========

2014-08
```
BenchmarkDataEncodeRsa	     100	  10602984 ns/op
BenchmarkDataEncodeEcdsa	    1000	   2331976 ns/op
BenchmarkDataEncode	   50000	     34764 ns/op
BenchmarkDataDecode	   50000	     71636 ns/op
BenchmarkInterestEncode	  200000	     11575 ns/op
BenchmarkInterestDecode	  100000	     33929 ns/op
```

2014-01

```
BenchmarkDataSHA256Encode     100000         22272 ns/op
BenchmarkDataSHA256Decode     100000         27381 ns/op
BenchmarkDataRSAEncode       100      23419913 ns/op
BenchmarkDataRSADecode     50000         68238 ns/op
BenchmarkInterestEncode   200000          9064 ns/op
BenchmarkInterestDecode   100000         17223 ns/op
```
Note: RSA key is 2048 bits. ECDSA uses P224.
