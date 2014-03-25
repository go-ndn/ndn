named-data network
==================
provide elegant and simple ndn library for research and testing purpose

library
=======
1. TLV (tlv.go)
2. Raw NDN TLV encoder/decoder (encoding.go)
3. NDN packet (ndn.go)
4. NDN server (on top of tcp)


import
======
```
import "github.com/taylorchu/ndn"

```

packet format
=============
the current implementation follows [ndn packet format specification 0.1](http://named-data.net/wp-content/uploads/2013/11/packetformat.pdf)
