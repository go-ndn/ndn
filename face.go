package ndn

import (
	"fmt"
	"net"
	"time"
)

/*
   Define ndn face
*/

type Face struct {
	Host string
}

func NewFace(name string) *Face {
	return &Face{
		Host: name,
	}
}

// user should listen to channel for returned data
// not blocking
func (this *Face) Dial(i *Interest) (d *Data, err error) {
	// interest encode
	ib, err := i.Encode()
	if err != nil {
		return
	}

	// dial
	conn, err := net.Dial("tcp", this.Host+":6363")
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	// write interest
	conn.Write(ib)
	r := &Data{}

	db := make([]byte, 4096)
	for {
		var n int
		n, err = conn.Read(db)
		if err != nil {
			return
		}

		err = r.Decode(db[:n])
		if err == nil {
			break
		} else {
			fmt.Println(err)
		}
	}
	d = r
	return
}
