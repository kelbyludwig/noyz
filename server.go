package main

import (
	"github.com/kelbyludwig/noyz/noise"
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
			continue
		}

		go func(c net.Conn) {

			defer c.Close()
			defer log.Printf("closing...")

			buf := make([]byte, 256)
			n, err := c.Read(buf)
			if err != nil {
				log.Printf("read: %v\n", err)
			}
			log.Printf("success! %v\n", buf[:n])
		}(conn)
	}

}
