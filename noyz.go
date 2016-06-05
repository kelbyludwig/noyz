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
	log.Println("Initializing the initiator")
	log.Printf("--------------------------------------------\n")
	initiator.Initialize(hp, true, []byte{}, emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)
	log.Printf("--------------------------------------------\n\n")

	responder := state.HandshakeState{}
	log.Println("Initializing the responder")
	log.Printf("--------------------------------------------\n")
	responder.Initialize(hp, false, []byte{}, emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)
	log.Printf("--------------------------------------------\n\n")

	//Initiator sends a message to the responder. In NoiseNN, the first
	//message will be the ephemeral public key.
	var messageBufferInit []byte
	var payloadBufferInit []byte
	log.Println("Initiator sends message to responder.")
	log.Println("--------------------------------------")
	initiator.WriteMessage([]byte{}, &messageBufferInit)
	log.Printf("messageBuffer %v\n", messageBufferInit)
	log.Println("--------------------------------------\n")

	//Responder recieves the Initiator's public key.
	var messageBufferResp []byte
	var payloadBufferResp []byte
	log.Println("Responder recieves initiator's public key.")
	log.Println("--------------------------------------")
	responder.ReadMessage(messageBufferInit, &payloadBufferResp)
	log.Printf("payloadBuffer %v\n", payloadBufferResp)
	log.Println("--------------------------------------\n")

	//Responder responds.
	log.Println("Responder responds with her public key.")
	log.Println("--------------------------------------")
	c3, c4 := responder.WriteMessage([]byte{}, &messageBufferResp)
	log.Printf("messageBuffer %v\n", messageBufferResp)
	log.Printf("c3 %v\n", c3)
	log.Printf("c4 %v\n", c4)
	log.Println("--------------------------------------\n")

	//Initiator will read the response.
	log.Printf("Initiator should recieve the responder's public key.\n")
	c1, c2 := initiator.ReadMessage(messageBufferResp, &payloadBufferInit)
	log.Printf("payloadBuffer %v\n", payloadBufferInit)
	log.Printf("c1 %v\n", c1)
	log.Printf("c2 %v\n", c2)

}
