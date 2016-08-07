package main

import (
	"github.com/kelbyludwig/noyz/noise"
	"log"
)

func main() {

	conn, err := noise.Dial("tcp", "127.0.0.1:6667", nil)

	if err != nil {
		log.Printf("dial: %v\n", err)
		return
	}

	n, err := conn.Write([]byte("hello!"))

	if err != nil {
		log.Printf("write: %v\n", err)
		return
	}

	log.Printf("wrote %v bytes\n", n)

	n, err = conn.Write([]byte("testing again!"))

	if err != nil {
		log.Printf("write: %v\n", err)
		return
	}

	log.Printf("wrote %v bytes\n", n)

}
