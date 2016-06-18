package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	dh "github.com/kelbyludwig/noyz/diffiehellman"
	"github.com/kelbyludwig/noyz/hash"
	"github.com/kelbyludwig/noyz/pattern"
	"io/ioutil"
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
	}
	blob, err := ioutil.ReadAll(file)
	if err != nil {
		panic("failed to read the test file")
	}
	vectors = new(Vectors)
	err = json.Unmarshal(blob, &vectors)
	if err != nil {
		panic("failed to unmarshal input file")
	}
}

func decode(in string) []byte {
	b, _ := hex.DecodeString(in)
	return b
}

// createEmptyHandshaker is a test helper that creates either an initiator or
// responder with an hardcoded private DH key.
func createEmptyHandshaker(v Vector, hp pattern.HandshakePattern, initiator bool) (hs HandshakeState) {
	emptyPublicKey := dh.PublicKey{}
	emptyKeyPair := dh.KeyPair{}

	if initiator {
		hs.Initialize(hp, true, decode(v.InitPrologue), emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)
		hs.FixKeysForTesting(v.InitStatic, v.InitEphemeral)
	} else {
		hs.Initialize(hp, false, decode(v.RespPrologue), emptyKeyPair, emptyKeyPair, emptyPublicKey, emptyPublicKey)
		hs.FixKeysForTesting(v.RespStatic, v.RespEphemeral)
	}
	return hs
}

func runHandshake(v Vector) (ic1, ic2, rc1, rc2 CipherState, err error) {

	hp := pattern.Initialize(v.Pattern, v.DH, v.Hash, v.Cipher)

	init := createEmptyHandshaker(v, hp, true)
	resp := createEmptyHandshaker(v, hp, false)

	for i, x := range v.Messages {
		var messageBufferInit []byte
		var payloadBufferInit []byte

		if ic1.HasKey() && ic2.HasKey() && rc1.HasKey() && rc2.HasKey() {
			return
		}
		if i%2 == 0 {
			ic1, ic2 = init.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			if result != x.Ciphertext {
				err = fmt.Errorf("runHandshake: vector failed on message %v: initiators message did not match expected ciphertext", i)
				return
			}

			rc1, rc2 = resp.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			if result != x.Payload {
				err = fmt.Errorf("runHandshake: vector failed on message %v: responders payload did not match expected payload", i)
				return
			}

		} else {
			ic1, ic2 = resp.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			if result != x.Ciphertext {
				err = fmt.Errorf("runHandshake: vector failed on message %v: responders message did not match expected ciphertext", i)
				return
			}

			rc1, rc2 = init.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			if result != x.Payload {
				err = fmt.Errorf("runHandshake: vector failed on message %v: initiators payload did not match expected payload", i)
				return
			}
		}
	}
	err = fmt.Errorf("runHandshake: handshake failed")
	return

}

func runTestVector(v Vector) error {

	hp := pattern.Initialize(v.Pattern, v.DH, v.Hash, v.Cipher)

	init := createEmptyHandshaker(v, hp, true)
	resp := createEmptyHandshaker(v, hp, false)

	var ic1, ic2, rc1, rc2 CipherState
	for i, x := range v.Messages {
		var messageBufferInit []byte
		var payloadBufferInit []byte

		// If this statement is true, the handshake should be complete
		// and we can just use symmetric state.
		if ic1.HasKey() && ic2.HasKey() && rc1.HasKey() && rc2.HasKey() {
			if i%2 == 0 {
				// It is the initiators turn
				ciphertext := ic1.EncryptWithAD([]byte{}, decode(x.Payload))
				result := fmt.Sprintf("%x", ciphertext)
				if result != x.Ciphertext {
					return fmt.Errorf("runTestVector: vector failed on message %v: initiators symmetric encryption did not match expected ciphertext", i)
				}

				payload, err := rc1.DecryptWithAD([]byte{}, ciphertext)
				result = fmt.Sprintf("%x", payload)
				if err != nil {
					return fmt.Errorf("runTestVector: vector failed on message %v: responder decryption had an authentication failure", i)
				}
				if result != x.Payload {
					return fmt.Errorf("runTestVector: vector failed on message %v: responders symmetric decryption did not match expected payload", i)
				}

			} else {
				// It is the responders turn
				ciphertext := rc2.EncryptWithAD([]byte{}, decode(x.Payload))
				result := fmt.Sprintf("%x", ciphertext)
				if result != x.Ciphertext {
					return fmt.Errorf("runTestVector: vector failed on message %v: responder symmetric encryption did not match expected ciphertext", i)
				}

				payload, err := ic2.DecryptWithAD([]byte{}, ciphertext)
				result = fmt.Sprintf("%x", payload)
				if err != nil {
					return fmt.Errorf("runTestVector: vector failed on message %v: initiator decryption had an authentication failure", i)
				}
				if result != x.Payload {
					return fmt.Errorf("runTestVector: vector failed on message %v: initiator symmetric decryption did not match expected payload", i)
				}

			}
			continue
		}

		if i%2 == 0 {
			ic1, ic2 = init.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			if result != x.Ciphertext {
				return fmt.Errorf("runTestVector: vector failed on message %v: initiators message did not match expected ciphertext", i)
			}

			rc1, rc2 = resp.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			if result != x.Payload {
				return fmt.Errorf("runTestVector: vector failed on message %v: responders payload did not match expected payload", i)
			}

		} else {
			ic1, ic2 = resp.WriteMessage(decode(x.Payload), &messageBufferInit)
			result := fmt.Sprintf("%x", messageBufferInit)
			if result != x.Ciphertext {
				return fmt.Errorf("runTestVector: vector failed on message %v: responders message did not match expected ciphertext", i)
			}

			rc1, rc2 = init.ReadMessage(messageBufferInit, &payloadBufferInit)
			result = fmt.Sprintf("%x", payloadBufferInit)
			if result != x.Payload {
				return fmt.Errorf("runTestVector: vector failed on message %v: initiators payload did not match expected payload", i)
			}
		}
	}
	return nil
}

func TestNoiseNN(t *testing.T) {
	nn := vectors.TestVectors[8]
	if err := runTestVector(nn); err != nil {
		t.Errorf("TestNoiseNN: test vector 8 failed: %v\n", err)
	}
}

func TestMixHashSHA256(t *testing.T) {

	full := []byte("Testing123")
	prefix := []byte("Testing")
	postfix := []byte("123")

	ss := SymmetricState{}
	ss.h = prefix
	ss.cs.hf = hash.SHA256Function{}

	ss.MixHash(postfix)
	h := sha256.Sum256(full)

	if string(h[:]) != string(ss.h) {
		t.Errorf("TestMixHashSHA256: sha256 output did not match intended output")
		return
	}
}

func (cs *CipherState) maximizeNonce() {
	cs.n = NONCEMAX
	return
}
func (cs CipherState) Nonce() uint64 {
	return cs.n
}

func TestNonceMaxEncryption(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("TestNonceMaxEncryption: no panic on nonce max")
			return
		}
	}()

	nn := vectors.TestVectors[8]

	ic1, _, _, _, err := runHandshake(nn)

	if err != nil {
		t.Errorf("TestNonceMaxEncryption: %v\n", err)
		return
	}

	ic1.maximizeNonce()
	ic1.EncryptWithAD([]byte{}, []byte{})
}

func TestNonceMaxDecryption(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("TestNonceMaxDecryption: no panic on nonce max")
			return
		}
	}()

	nn := vectors.TestVectors[8]

	ic1, _, _, _, err := runHandshake(nn)

	if err != nil {
		t.Errorf("TestNonceMaxDecryption: %v\n", err)
		return
	}

	ic1.maximizeNonce()
	ic1.DecryptWithAD([]byte{}, []byte{})
}
