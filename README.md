# Named-Data Network (NDN)

This package provides elegant and simple ndn library for research and testing purpose.
NDN evolves quickly, and the latest format that the current implementation follows is on [ndn doc](http://named-data.net/doc/ndn-tlv/)

The author is taylorchu (Tai-Lin Chu). This package is released under GPL2 license.

[![GoDoc](https://godoc.org/github.com/go-ndn/ndn?status.svg)](https://godoc.org/github.com/go-ndn/ndn)

## Get started

1. [Install and run nfd](http://named-data.net/doc/NFD/current/INSTALL.html)
2. [Set up go work environment](https://golang.org/doc/install)
3. Get this package by running `go get "github.com/go-ndn/ndn"`

![Imgur](http://i.imgur.com/mWMese2.jpg)

## Benchmark

2015-03
```
BenchmarkDataEncodeRSA	     100	  11268142 ns/op
BenchmarkDataEncodeECDSA	    1000	   2305271 ns/op
BenchmarkDataEncode	  100000	     13603 ns/op
BenchmarkDataDecode	  100000	     18023 ns/op
BenchmarkInterestEncode	  200000	      8303 ns/op
BenchmarkInterestDecode	  200000	     11306 ns/op
```

2014-08
```
BenchmarkDataEncodeRSA	     100	  10602984 ns/op
BenchmarkDataEncodeECDSA	    1000	   2331976 ns/op
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
