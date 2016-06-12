package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	dh "github.com/kelbyludwig/noyz/diffiehellman"
	"github.com/kelbyludwig/noyz/pattern"
	"github.com/kelbyludwig/noyz/state"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

type Vectors struct {
	TestVectors []Vector `json:"vectors"`
}

type Vector struct {
	Name             string    `json:"name"`
	Pattern          string    `json:"pattern"`
	DH               string    `json:"dh"`
	Cipher           string    `json:"cipher"`
	Hash             string    `json:"hash"`
	InitPrologue     string    `json:"init_prologue"`
	InitEphemeral    string    `json:"init_ephemeral"`
	InitStatic       string    `json:"init_static"`
	InitRemoteStatic string    `json:"init_remote_static"`
	RespPrologue     string    `json:"resp_prologue"`
	RespEphemeral    string    `json:"resp_ephemeral"`
	RespStatic       string    `json:"resp_static"`
	RespRemoteStatic string    `json:"resp_remote_static"`
	Messages         []Message `json:"messages"`
	HandshakeHash    string    `json:"handshake_hash"`
}

type Message struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

var vectors *Vectors

func init() {
	file, err := os.Open("cacophony.txt")
	if err != nil {
		panic("failed to open test file")
		return
	}
	blob, err := ioutil.ReadAll(file)
	if err != nil {
		panic("failed to read the test file")
		return
	}
	vectors = new(Vectors)
	err = json.Unmarshal(blob, &vectors)
	if err != nil {
		panic("failed to unmarshal input file")
		return
	}
}

func RunTestVector(v Vector) error {

	decode := func(in string) []byte {
		b, _ := hex.DecodeString(in)
		return b
	}

	emptyPublicKey := dh.PublicKey{}
	emptyKeyPair := dh.KeyPair{}

	log.Printf("Initialiizing Noise_%v_%v_%v_%v\n", v.Pattern, v.DH, v.Hash, v.Cipher)
	hp := pattern.Initialize(v.Pattern, v.DH, v.Hash, v.Cipher)

	init := state.HandshakeState{}
	init.Initialize(hp, true, decode(v.InitPrologue), emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)
	init.FixKeysForTesting(v.InitStatic, v.InitEphemeral)

	resp := state.HandshakeState{}
	resp.Initialize(hp, false, decode(v.RespPrologue), emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)
	resp.FixKeysForTesting(v.RespStatic, v.RespEphemeral)

	var messageBufferInit []byte
	var payloadBufferInit []byte

	for i, x := range v.Messages {
		if i%2 == 0 {
			init.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			if result != x.Ciphertext {
				return fmt.Errorf("vector failed on message %v: initiators message did not match expected ciphertext", i)
			}
			resp.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			if result != x.Payload {
				return fmt.Errorf("vector failed on message %v: responders payload did not match expected payload", i)
			}
		} else {
			resp.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			if result != x.Ciphertext {
				return fmt.Errorf("vector failed on message %v: responders message did not match expected ciphertext", i)
			}
			init.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			if result != x.Payload {
				return fmt.Errorf("vector failed on message %v: initiators payload did not match expected payload", i)
			}
		}
	}
	return nil
}

func TestNoiseNN(t *testing.T) {
	nn := vectors.TestVectors[8]
	RunTestVector(nn)
}
