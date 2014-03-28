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
	// write interest
	conn.Write(ib)
	if i.InterestLifeTime == 0 {
		// default timeout 10s
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	} else {
		// use interestLifeTime
		conn.SetDeadline(time.Now().Add(time.Duration(i.InterestLifeTime) * time.Millisecond))
	}

	d = &Data{}
	fixed := make([]byte, 1024)
	db := []byte{}
	for {
		var n int
		n, err = conn.Read(fixed)
		if err != nil {
			return
		}
		db = append(db, fixed[:n]...)
		if n < len(fixed) {
			break
		}
	}
	err = d.Decode(db)
	if err != nil {
		fmt.Println(err)
	}
	return
}
