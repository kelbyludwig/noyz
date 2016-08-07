package main

import (
	"github.com/kelbyludwig/noyz/noise"
	"io"
	"log"
	"net"
)

func main() {

	l, err := noise.Listen("tcp", ":6667", nil)

	if err != nil {
		log.Printf("listen: %v\n", err)
		return
	}

	log.Printf("looping...")
	for {
		conn, err := l.Accept()

		if err != nil {
			log.Printf("accept: %v\n", err)
		}

		go func(c net.Conn) {
			defer c.Close()
			defer log.Printf("closing...")
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				if err != nil && err != io.EOF {
					log.Printf("read: error %v\n", err)
				}
				if n > 0 {
					log.Printf("success!: %s\n", buf[:n])
				}
			}
		}(conn)
	}

}
