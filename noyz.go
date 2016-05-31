package main

import (
	_ "github.com/kelbyludwig/noyz/cipher"
	dh "github.com/kelbyludwig/noyz/diffiehellman"
	_ "github.com/kelbyludwig/noyz/hash"
	"github.com/kelbyludwig/noyz/pattern"
	"github.com/kelbyludwig/noyz/state"
	"log"
)

func main() {
	hp := pattern.NoiseNN()

	emptyPublicKey := dh.PublicKey{}
	emptyKeyPair := dh.KeyPair{}
	initiator := state.HandshakeState{}
	initiator.Initialize(hp, true, []byte{}, emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)

	responder := state.HandshakeState{}
	responder.Initialize(hp, false, []byte{}, emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)

	//Initiator sends a message to the responder. In NoiseNN, the first
	//message will be the ephemeral public key.
	var messageBuffer []byte
	c1, c2 := initiator.WriteMessage([]byte{}, &messageBuffer)
	log.Printf("messageBuffer %v\n", messageBuffer)
	log.Printf("c1 %v\n", c1)
	log.Printf("c2 %v\n", c2)

	//Responder recieves the Initiator's public key.
	var payloadBuffer []byte
	c3, c4 := responder.ReadMessage(messageBuffer, &payloadBuffer)
	log.Printf("payloadBuffer %v\n", payloadBuffer)
	log.Printf("c3 %v\n", c3)
	log.Printf("c4 %v\n", c4)

	//Responder responds.
	messageBuffer = make([]byte, 0)
	c3, c4 = responder.WriteMessage([]byte{}, &messageBuffer)
	log.Printf("messageBuffer %v\n", messageBuffer)
	log.Printf("c3 %v\n", c3)
	log.Printf("c4 %v\n", c4)

}
