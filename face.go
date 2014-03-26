package ndn

import (
	"fmt"
	//"io/ioutil"
	"net"
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
func (this *Face) Dial(i *Interest) chan *Data {
	promise := make(chan *Data)
	go func(p chan *Data) {
		// recv
		ib, err := i.Encode()
		if err != nil {
			p <- nil
			fmt.Println(err)
			return
		}
		conn, err := net.Dial("tcp", this.Host+":6363")
		if err != nil {
			p <- nil
			fmt.Println(err)
			return
		}
		defer conn.Close()
		conn.Write(ib)

		db := make([]byte, 4096)
		n, err := conn.Read(db)
		if err != nil {
			p <- nil
			fmt.Println(err)
			return
		}
		d := &Data{}
		err = d.Decode(db[:n])
		if err != nil {
			p <- nil
			i2 := &Interest{}
			i2.Decode(db[:n])
			fmt.Printf("%v %#v\n", err, i2)
			return
		}
		p <- d
	}(promise)
	return promise
}
