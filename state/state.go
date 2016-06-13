package state

import (
	"encoding/hex"
	"github.com/kelbyludwig/noyz/cipher"
	dh "github.com/kelbyludwig/noyz/diffiehellman"
	"github.com/kelbyludwig/noyz/hash"
	"log"
	"strings"
)

// NONCEMAX is the maximum size for a nonce. If a Noise session lasts long
// enough to reach a nonce of NONCEMAX the session will end.
const NONCEMAX uint64 = 18446744073709551615

// CipherState contains k and n variables, which it uses to encrypt and
// decrypt ciphertexts.  During the handshake phase each party has a single
// CipherState, but during the transport phase each party has two CipherState
// objects: one for sending, and one for receiving.
type CipherState struct {
	// k is the symmetric key used for encryption/decryption.
	k []byte
	// n is the nonce used for encryption/decryption.
	n uint64
	// initialized is used to determine if the CipherState has a itialized K value.
	// In the Noise Protocol specificiation, this is called "empty," however with
	// Golang's zero values this naming scheme makes a bit more sense.
	initialized bool
	// c is the interface that implements the encryption/decryption
	// and authentication methods.
	c cipher.CipherFunction
	// dh is the interface that implements the Diffie-Hellmen methods.
	dh dh.DHFunction
	// hf is the interface that implements the hash-related methods.
	hf hash.HashFunction
}

// IsInitialized will return true if the CipherState has been initialized and
// false otherwise. A CipherState is typically initialized after a handshake is
// complete and Split() is called.
func (cs CipherState) IsInitialized() bool {
	return cs.initialized
}

// InitializeKey initializes a CipherState struct
// and sets the starting nonce and key values.
func (cs *CipherState) InitializeKey(key []byte) {
	cs.k = make([]byte, 32)
	copy(cs.k, key)
	cs.n = uint64(0)
	cs.initialized = true
}

// HasKey return true if the specified CipherState is
// initialized and false otherwise.
func (cs CipherState) HasKey() bool {
	return cs.initialized
}

// EncryptWithAD encrypts and authenticates the input plaintext and
// just authenticates the input ad. If the CipherState is unitialized
// EncryptWithAD will return the plaintext. Otherwise, it will return
// a ciphertext.
func (cs *CipherState) EncryptWithAD(ad, plaintext []byte) []byte {
	if cs.HasKey() {
		if cs.n == NONCEMAX {
			//TODO(kkl): This could be better handled. Instead of a panic, the connection should be killed.
			panic("nonce max hit!")
		}
		ct := cs.c.Encrypt(cs.n, cs.k, ad, plaintext)
		cs.n = cs.n + 1
		return ct
	} else {
		// EncryptWithAD assumes that the CipherState will be
		// initialized as soon as possible (i.e. as soon as there is a shared
		// key between parties). Therefore, returning the plaintext instead
		// of a ciphertext is not an error. It just simplifies the API
		// and state machine. In other words, assuming the implementation is sound
		// the only time this will happen is prior to *any* DH operations.

		// NOTE(kkl): I think this comment is an interesting
		// assumption. Might be worth testing.

		return plaintext
	}
}

// DecryptWithAD decrypts and authenticates the input ciphertext and associated
// data (ad) returning an error if authentication failed. If CipherState is
// unitialized, the ciphertext will be returned.
func (cs *CipherState) DecryptWithAD(ad, ciphertext []byte) ([]byte, error) {
	if cs.HasKey() {
		if cs.n == NONCEMAX {
			//TODO(kkl): This could be better handled. Instead of a panic, the connection should be killed.
			panic("nonce max hit!")
		}
		plaintext, err := cs.c.Decrypt(cs.n, cs.k, ad, ciphertext)
		cs.n = cs.n + 1
		return plaintext, err
	} else {
		return ciphertext, nil
	}
}

// SymmetricState is a struct that encapsulates all "symmetric crypto."
// SymmetricStates are deleted after a handshake is completed.
type SymmetricState struct {
	// cs is responsible for encryption/decryption of data.
	// cs also contains the relevant data structures that perform
	// all crypto-operations (e.g. DH, symmetric encryption, hashing, etc.)
	cs CipherState
	// ck is the chaining key.
	ck []byte
	// h is the handshake hash.
	h []byte
}

// InitializeSymmetric takes a protocol name as input and initializes the
// SymmetricState struct.
func (ss *SymmetricState) InitializeSymmetric(protocolName []byte) {

	ss.cs = CipherState{}

	protocolString := string(protocolName)
	tokens := strings.Split(protocolString, "_")

	if len(tokens) != 5 {
		panic("invalid protocolName passed to InitializeSymmetric")
	}

	DHToken := tokens[2]
	switch DHToken {
	case "25519":
		ss.cs.dh = dh.Curve25519Function{}
	default:
		panic("DiffieHellman function not supported")
	}

	CipherToken := tokens[3]
	switch CipherToken {
	case "AESGCM":
		ss.cs.c = cipher.GCMFunction{}
	default:
		panic("Cipher function not supported")
	}

	HashToken := tokens[4]
	switch HashToken {
	case "SHA256":
		ss.cs.hf = hash.SHA256Function{}
	default:
		panic("Hash function not supported")
	}

	lpn := len(protocolName)
	hl := ss.cs.hf.HashLen()
	if lpn <= hl {
		ss.h = make([]byte, hl)
		copy(ss.h, protocolName)
	} else {
		ss.h = ss.cs.hf.Hash(protocolName)
	}

	ss.ck = make([]byte, ss.cs.hf.HashLen())
	copy(ss.ck, ss.h)
}

// MixKey updates the CipherState keys with the input bytes.
func (ss *SymmetricState) MixKey(inputKeyMaterial []byte) {
	ck, tempK := ss.cs.hf.HKDF(ss.ck, inputKeyMaterial)
	ss.ck = ck

	if ss.cs.hf.HashLen() == 64 {
		tempK = tempK[:32]
	}
	ss.cs.InitializeKey(tempK)
}

// MixHash updates the SymmetricState hash. MixHash is used to maintain
// transcript integrity.
func (ss *SymmetricState) MixHash(data []byte) {
	temp := append(ss.h, data...)
	ss.h = ss.cs.hf.Hash(temp)
}

// EncryptAndHash will encrypt the supplied plaintext and return the
// ciphertext. If the SymmetricState struct is unitialized, it will return the
// input plaintext.
func (ss *SymmetricState) EncryptAndHash(plaintext []byte) (ciphertext []byte) {
	ciphertext = ss.cs.EncryptWithAD(ss.h, plaintext)
	ss.MixHash(ciphertext)
	return ciphertext
}

// DecryptAndHash will decrypt the supplied ciphertext and return the decrypted
// plaintext. If the SymmetricState struct is unitialized, it will return the
// input ciphertext.
func (ss *SymmetricState) DecryptAndHash(ciphertext []byte) (plaintext []byte) {
	plaintext, err := ss.cs.DecryptWithAD(ss.h, ciphertext)
	if err != nil {
		panic("authentication error. this should kill the connection")
	}
	ss.MixHash(ciphertext)
	return plaintext
}

// Split is called once a Noise handshake is completed. It returns sending and
// recieving CipherState structs for sending encrypted messages.
func (ss *SymmetricState) Split() (cs1, cs2 CipherState) {
	tempK1, tempK2 := ss.cs.hf.HKDF(ss.ck, []byte{})

	if ss.cs.hf.HashLen() == 64 {
		tempK1 = tempK1[:32]
		tempK2 = tempK2[:32]
	}
	cs1 = CipherState{}
	cs2 = CipherState{}

	cs1.InitializeKey(tempK1)
	cs2.InitializeKey(tempK2)

	cs1.c = ss.cs.c
	cs2.c = ss.cs.c

	cs1.dh = ss.cs.dh
	cs2.dh = ss.cs.dh

	cs1.hf = ss.cs.hf
	cs2.hf = ss.cs.hf

	return
}

// HandshakePattern describes how an initiator and a responder will negotiate a
// shared secret.
type HandshakePattern struct {
	// initiatorPreMessages are keys that are known to an initiator prior
	// to a handshake. Can be empty.
	initiatorPreMessages []string
	// responderPreMessages are keys that are known to an responder prior
	// to a handshake. Can be empty.
	responderPreMessages []string
	// MessagePattern describes the messages that are exchanged between the
	// initiator and the responder to determine a shared secret.
	MessagePattern []string
	// DiffieHellman is the string representation of the Diffie-Hellman
	// function used.
	DiffieHellman string
	// HashFunction is the string representation of the hash function used.
	HashFunction string
	// SymmetricCipher is the string representation of the symmetric cipher
	// used.
	SymmetricCipher string
	// HandshakePatternName is the string representation of handshake
	// pattern name
	HandshakePatternName string
}

// HandshakeState keeps track of the state during a Noise handshake.
// TODO(kkl): Add a variable to keep track of whos turn it is for the handshake.
type HandshakeState struct {
	// ss maintains the state for encryption and decryption
	ss SymmetricState
	// s is the local static key pair
	s dh.KeyPair
	// e is the local ephemeral key pair
	e dh.KeyPair
	// rs is the remote party's static public key
	rs dh.PublicKey
	// re is the remote party's ephemeral public key
	re dh.PublicKey
	// mp is the remaining portions of the handshake's pattern
	mp []string
	// testing signifies if the current struct is used for testing purposes
	testing bool
	ts      string
	te      string
}

// FixKeysForTesting will fix the inputs as private keys for the
// HandshakeState. This is used for testing purposes and should not be used
// otherwise.
func (hss *HandshakeState) FixKeysForTesting(ts, te string) {
	hss.testing = true
	hss.ts = ts
	hss.te = te
}

// Initialize initializes a HandshakeState struct.
func (hss *HandshakeState) Initialize(handshakePattern HandshakePattern, initiator bool, prologue []byte, s, e dh.KeyPair, rs, re dh.PublicKey) {

	protocolName := "Noise_" + handshakePattern.HandshakePatternName + "_" + handshakePattern.DiffieHellman + "_" + handshakePattern.SymmetricCipher + "_" + handshakePattern.HashFunction
	hss.ss = SymmetricState{}
	hss.ss.InitializeSymmetric([]byte(protocolName))
	hss.ss.MixHash(prologue)
	nullKey := make([]byte, hss.ss.cs.dh.DHLen())

	hss.s = s
	hss.e = e
	hss.rs = rs
	hss.re = re

	for _, ipm := range handshakePattern.initiatorPreMessages {
		switch ipm {
		case "s":
			if !s.Initialized {
				panic("initiator static key not supplied for premessage")
			}
			hss.ss.MixHash(s.Public)
		case "e":
			if !e.Initialized {
				panic("initiator static key not supplied for premessage")
			}
			hss.ss.MixHash(e.Public)
		case "s,e":
			if !e.Initialized || !s.Initialized {
				panic("initiator static or ephemeral key not supplied for premessage")
			}
			hss.ss.MixHash(s.Public)
			hss.ss.MixHash(e.Public)
		case "":
		default:
			panic("invalid initiator premessage")
		}
	}

	for _, rpm := range handshakePattern.responderPreMessages {
		switch rpm {
		case "s":
			if string(rs) == string(nullKey) {
				panic("responder static key not supplied for premessage")
			}
			hss.rs = rs
			hss.ss.MixHash(rs)
		case "e":
			if string(re) == string(nullKey) {
				panic("responder static key not supplied for premessage")
			}
			hss.re = re
			hss.ss.MixHash(re)
		case "s,e":
			if string(re) == string(nullKey) || string(rs) == string(nullKey) {
				panic("responder static or ephemeral key not supplied for premessage")
			}
			hss.rs = rs
			hss.re = re
			hss.ss.MixHash(rs)
			hss.ss.MixHash(re)
		case "":
		default:
			panic("invalid responder premessage")
		}
	}

	hss.mp = handshakePattern.MessagePattern
	return

}

// WriteMessage takes a payload byte sequence which may be zero-length, and a
// messageBuffer to write the output into.
func (hss *HandshakeState) WriteMessage(payload []byte, messageBuffer *[]byte) (c1, c2 CipherState) {

	var tokens []string
	if len(hss.mp) != 0 {
		mp := hss.mp[0]
		hss.mp = hss.mp[1:]
		tokens = strings.Split(mp, ",")
	} else {
		panic("the HandshakeState has no more tokens left in its handshake")
	}

	log.Printf("WriteMessage: HandshakeState's current tokens %v\n", tokens)

	decode := func(in string) []byte {
		b, _ := hex.DecodeString(in)
		return b
	}

	for _, t := range tokens {
		switch t {
		case "s":
			if hss.testing {
				hss.s = hss.ss.cs.dh.FixedKeyPair(decode(hss.ts))
			}
			log.Printf("WriteMessage: token 's' encrypting the static public key %x\n", hss.s.Public)
			ct := hss.ss.EncryptAndHash(hss.s.Public)
			log.Printf("WriteMessage: token 's' appending the encrypted static public key %x\n", ct)
			*messageBuffer = append(*messageBuffer, ct...)
		case "e":
			if hss.testing {
				hss.e = hss.ss.cs.dh.FixedKeyPair(decode(hss.te))
			} else {
				hss.e = hss.ss.cs.dh.GenerateKeyPair()
			}
			*messageBuffer = append(*messageBuffer, hss.e.Public...)
			log.Printf("WriteMessage: token 'e' appending the plaintext public key  %x\n", hss.e.Public)
			hss.ss.MixHash(hss.e.Public)
		case "dhee":
			o := hss.ss.cs.dh.DH(hss.e, hss.re)
			log.Printf("WriteMessage: token 'dhee' mixing in the shared key %x\n", o)
			hss.ss.MixKey(o)
		case "dhes":
			o := hss.ss.cs.dh.DH(hss.e, hss.rs)
			log.Printf("WriteMessage: token 'dhes' mixing in the shared key %x\n", o)
			hss.ss.MixKey(o)
		case "dhse":
			o := hss.ss.cs.dh.DH(hss.s, hss.re)
			log.Printf("WriteMessage: token 'dhse' mixing in the shared key %x\n", o)
			hss.ss.MixKey(o)
		case "dhss":
			o := hss.ss.cs.dh.DH(hss.s, hss.rs)
			log.Printf("WriteMessage: token 'dhss' mixing in the shared key %x\n", o)
			hss.ss.MixKey(o)
		default:
			panic("invalid message pattern token")
		}
	}

	p := hss.ss.EncryptAndHash(payload)
	log.Printf("WriteMessage: encrypting the payload %x\n", payload)
	log.Printf("WriteMessage: appending the encrypted payload %x\n", p)
	*messageBuffer = append(*messageBuffer, p...)
	if len(hss.mp) == 0 {
		return hss.ss.Split()
	}
	return
}

// ReadMessage takes a byte sequence containing a Noise handshake message, and
// a payloadBuffer to write the message's plaintext payload into.
func (hss *HandshakeState) ReadMessage(message []byte, payloadBuffer *[]byte) (c1, c2 CipherState) {

	var tokens []string
	if len(hss.mp) != 0 {
		mp := hss.mp[0]
		hss.mp = hss.mp[1:]
		tokens = strings.Split(mp, ",")
	} else {
		panic("the HandshakeState has no more tokens left in its handshake")
	}
	for _, t := range tokens {
		switch t {
		case "s":
			dhl := hss.ss.cs.dh.DHLen()
			if hss.ss.cs.HasKey() {
				temp := message[:dhl+16]
				hss.rs = hss.ss.DecryptAndHash(temp)
				message = message[dhl+16:]
			} else {
				temp := message[:dhl]
				hss.rs = hss.ss.DecryptAndHash(temp)
				message = message[dhl:]
			}
		case "e":
			dhl := hss.ss.cs.dh.DHLen()
			hss.re = message[:dhl]
			hss.ss.MixHash(hss.re)
			message = message[dhl:]
		case "dhee":
			o := hss.ss.cs.dh.DH(hss.e, hss.re)
			hss.ss.MixKey(o)
		case "dhes":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.s, hss.re))
		case "dhse":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.e, hss.rs))
		case "dhss":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.s, hss.rs))
		default:
			panic("invalid message pattern token")
		}
	}

	*payloadBuffer = append(*payloadBuffer, hss.ss.DecryptAndHash(message)...)
	if len(hss.mp) == 0 {
		return hss.ss.Split()
	}
	return

}
