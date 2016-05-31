package state

import (
	"encoding/binary"
	"github.com/kelbyludwig/noyz/cipher"
	dh "github.com/kelbyludwig/noyz/diffiehellman"
	"github.com/kelbyludwig/noyz/hash"
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

// InitializeKey initializes a CipherState struct
// and sets the starting nonce and key values.
func (cs *CipherState) InitializeKey(key []byte) {
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
			//TODO(kkl): better error handling here.
			panic("nonce max hit!")
		}
		nb := make([]byte, 8)
		binary.PutUvarint(nb, cs.n)
		return cs.c.Encrypt(cs.k, nb, ad, plaintext)
	} else {
		// EncryptWithAD assumes that the CipherState will be
		// initialized as soon as possible (i.e. as soon as there is a shared
		// key between parties). Therefore, returning the plaintext instead
		// of a ciphertext is not an error. It just simplifies the API
		// and state machine. In other words, assuming the implementation is sound
		// the only time this will happen is prior to *any* DH operations.
		// TODO(kkl): I think this comment is an interesting
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
			//TODO(kkl): better error handling here.
			panic("nonce max hit!")
		}
		nb := make([]byte, 8)
		binary.PutUvarint(nb, cs.n)
		return cs.c.Decrypt(cs.k, nb, ad, ciphertext)
	} else {
		//TODO(kkl): This may need to return an error.
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
	// CK is the chaining key.
	ck []byte
	// H is the handshake hash.
	h []byte
}

//TODO(kkl): Document.
func (ss *SymmetricState) InitializeSymmetric(protocolName []byte) {
	lpn := len(protocolName)
	hl := ss.cs.hf.HashLen()
	if lpn <= hl {
		ss.h = make([]byte, hl)
		copy(ss.h, protocolName)
	} else {
		ss.h = ss.cs.hf.Hash(protocolName)
	}
	copy(ss.ck, ss.h)
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
	ss.h = ss.cs.hf.Hash(append(ss.h, data...))
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

//TODO(kkl): Document.
func (ss *SymmetricState) Split() (ss1, ss2 CipherState) {
	tempK1, tempK2 := ss.cs.hf.HKDF(ss.ck, []byte{})

	if ss.cs.hf.HashLen() == 64 {
		tempK1 = tempK1[:32]
		tempK2 = tempK2[:32]
	}
	ss1 = CipherState{}
	ss2 = CipherState{}
	ss1.InitializeKey(tempK1)
	ss2.InitializeKey(tempK2)
	return
}

//TODO(kkl): Document.
type HandshakePattern struct {
	InitiatorPreMessages []string
	ResponderPreMessages []string
	MessagePattern       []string
}

//TODO(kkl): Document.
type HandshakeState struct {
	// ss maintains the state for encryption and decryption.
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
}

//TODO(kkl): Document.
func (hss *HandshakeState) Initialize(handshakePattern HandshakePattern, initiator bool, prologue []byte, s, e dh.KeyPair, rs, re dh.PublicKey) {
	//TODO(kkl): Can premessage patterns have dhxy operations in them? If so, account for them here.
	for _, ipm := range handshakePattern.InitiatorPreMessages {
		switch ipm {
		case "s":
			if !s.Initialized {
				panic("initiator static key not supplied for premessage")
			}
			hss.s = s
		case "e":
			if !e.Initialized {
				panic("initiator static key not supplied for premessage")
			}
			hss.e = s
		case "s,e":
			if !e.Initialized || !s.Initialized {
				panic("initiator static or ephemeral key not supplied for premessage")
			}
			hss.s = s
			hss.e = e
		case "":
		default:
			panic("invalid initiator premessage")
		}
	}

	//TODO(kkl): PublicKey structs need a way to determine if they are
	//intialized or just the zero value. Until then, this case statement
	//wont' work.
	//for _, rpm := range handshakePattern.ResponderPreMessages {
	//	switch rpm {
	//	case "s":
	//		if !rs.Initialized {
	//			panic("responder static key not supplied for premessage")
	//		}
	//		hss.rs = rs
	//	case "e":
	//		if !re.Initialized {
	//			panic("responder static key not supplied for premessage")
	//		}
	//		hss.re = re
	//	case "s,e":
	//		if !re.Initialized || !rs.Initialized {
	//			panic("responder static or ephemeral key not supplied for premessage")
	//		}
	//		hss.rs = rs
	//		hss.re = re
	//	case "":
	//	default:
	//		panic("invalid responder premessage")
	//	}
	//}

	//TODO(kkl): Hardcoding this for now!
	protocolName := []byte("Noise_NN_25519_AESGCM_SHA256")

	hss.ss.InitializeSymmetric(protocolName)
	hss.ss.MixHash(prologue)
	//TODO(kkl): Implment pre-message mixhashing ("Calls MixHash() once for each public key listed..." from section 5.3)
	hss.mp = handshakePattern.MessagePattern
	return

}

//TODO(kkl): Document this!
func (hss *HandshakeState) WriteMessage(payload, messageBuffer []byte) (c1, c2 CipherState) {

	if len(hss.mp) == 0 {
		return hss.ss.Split()
	}

	mp := hss.mp[0]
	hss.mp = hss.mp[1:]

	tokens := strings.Split(mp, ",")

	for _, t := range tokens {
		switch t {
		case "s":
			ct := hss.ss.EncryptAndHash(hss.s.Public)
			_ = append(messageBuffer, ct...)
		case "e":
			e := hss.ss.cs.dh.GenerateKeyPair()
			hss.e = e
			_ = append(messageBuffer, e.Public...)
			hss.ss.MixHash(e.Public)
		case "dhee":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.e, hss.re))
		case "dhes":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.e, hss.rs))
		case "dhse":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.s, hss.re))
		case "dhss":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.s, hss.rs))
		default:
			panic("invalid message pattern token")
		}
	}

	_ = append(messageBuffer, hss.ss.EncryptAndHash(payload)...)
	return
}

//TODO(kkl): Document this!
func (hss *HandshakeState) ReadMessage(message, payloadBuffer []byte) (c1, c2 CipherState) {
	if len(hss.mp) == 0 {
		return hss.ss.Split()
	}

	mp := hss.mp[0]
	hss.mp = hss.mp[1:]

	tokens := strings.Split(mp, ",")

	var temp []byte
	for _, t := range tokens {
		switch t {
		case "s":
			dhl := hss.ss.cs.dh.DHLen()
			if hss.ss.cs.HasKey() {
				temp = message[dhl : dhl+16]
				hss.rs = hss.ss.DecryptAndHash(temp)
				temp = message[dhl+16:]
			} else {
				temp = message[:dhl]
				hss.rs = hss.ss.DecryptAndHash(temp)
				temp = message[dhl:]
			}
		case "e":
			dhl := hss.ss.cs.dh.DHLen()
			hss.re = message[:dhl]
			hss.ss.MixHash(hss.re)
		case "dhee":
			hss.ss.MixKey(hss.ss.cs.dh.DH(hss.e, hss.re))
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

	_ = append(payloadBuffer, hss.ss.DecryptAndHash(temp)...)
	return

}
