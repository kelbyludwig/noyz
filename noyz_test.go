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

	var iSender, iRecvr, rSender, rRecvr state.CipherState
	for i, x := range v.Messages {
		var messageBufferInit []byte
		var payloadBufferInit []byte

		// If this statement is true, the handshake should be complete.
		if iSender.IsInitialized() && iRecvr.IsInitialized() && rSender.IsInitialized() && rRecvr.IsInitialized() {
			if i%2 == 0 {
				ciphertext := iSender.EncryptWithAD([]byte{}, decode(x.Payload))
				result := fmt.Sprintf("%x", ciphertext)
				log.Printf("initiator result   %v\n", result)
				log.Printf("initiator expected %v\n", x.Ciphertext)
				if result != x.Ciphertext {
					return fmt.Errorf("vector failed on message %v: initiators symmetric encryption did not match expected ciphertext", i)
				}

				payload, err := rRecvr.DecryptWithAD([]byte{}, ciphertext)
				result = fmt.Sprintf("%x", payload)
				log.Printf("responder result   %v\n", result)
				log.Printf("responder expected %v\n", x.Payload)
				if err != nil {
					return fmt.Errorf("vector failed on message %v: responder decryption had an authentication failure", i)
				}
				if result != x.Payload {
					return fmt.Errorf("vector failed on message %v: responders symmetric decryption did not match expected payload", i)
				}

			} else {

				ciphertext := rSender.EncryptWithAD([]byte{}, decode(x.Payload))
				result := fmt.Sprintf("%x", ciphertext)
				log.Printf("responder result   %v\n", result)
				log.Printf("responder expected %v\n", x.Ciphertext)
				if result != x.Ciphertext {
					return fmt.Errorf("vector failed on message %v: responder symmetric encryption did not match expected ciphertext", i)
				}

				payload, err := iRecvr.DecryptWithAD([]byte{}, ciphertext)
				result = fmt.Sprintf("%x", payload)
				log.Printf("initiator result   %v\n", result)
				log.Printf("initiator expected %v\n", x.Payload)
				if err != nil {
					return fmt.Errorf("vector failed on message %v: initiator decryption had an authentication failure", i)
				}
				if result != x.Payload {
					return fmt.Errorf("vector failed on message %v: initiator symmetric decryption did not match expected payload", i)
				}

			}
			continue
		}

		if i%2 == 0 {
			iSender, iRecvr = init.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			log.Printf("iSender %v\n", iSender)
			log.Printf("iRecvr %v\n", iRecvr)
			log.Printf("initiator ciphertext %v\n", result)
			log.Printf("initiator expected   %v\n", x.Ciphertext)
			if result != x.Ciphertext {
				return fmt.Errorf("vector failed on message %v: initiators message did not match expected ciphertext", i)
			}
			rSender, rRecvr = resp.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			log.Printf("rSender %v\n", rSender)
			log.Printf("rRecvr %v\n", rRecvr)
			log.Printf("responder payload    %v\n", result)
			log.Printf("responder expected   %v\n", x.Payload)
			if result != x.Payload {
				return fmt.Errorf("vector failed on message %v: responders payload did not match expected payload", i)
			}
		} else {
			iSender, iRecvr = resp.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			log.Printf("iSender %v\n", iSender)
			log.Printf("iRecvr %v\n", iRecvr)
			log.Printf("responder ciphertext %v\n", result)
			log.Printf("responder expected   %v\n", x.Ciphertext)
			if result != x.Ciphertext {
				return fmt.Errorf("vector failed on message %v: responders message did not match expected ciphertext", i)
			}
			rSender, rRecvr = init.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			log.Printf("rSender %v\n", rSender)
			log.Printf("rRecvr %v\n", rRecvr)
			log.Printf("initiator payload    %v\n", result)
			log.Printf("initiator expected   %v\n", x.Payload)
			if result != x.Payload {
				return fmt.Errorf("vector failed on message %v: initiators payload did not match expected payload", i)
			}
		}
	}
	return nil
}

func TestNoiseNN(t *testing.T) {
	nn := vectors.TestVectors[8]
	if err := RunTestVector(nn); err != nil {
		t.Errorf("test vector 8 failed: %v\n", err)
	}
}
