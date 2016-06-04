package diffiehellman

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
)

type SharedPoint []byte
type PrivateKey []byte
type PublicKey []byte

type KeyPair struct {
	Private     PrivateKey
	Public      PublicKey
	Initialized bool
}

type DHFunction interface {
	GenerateKeyPair() (keyPair KeyPair)
	DH(keyPair KeyPair, publicKey PublicKey) SharedPoint
	DHLen() int
}

type Curve25519Function struct{}

func (c Curve25519Function) GenerateKeyPair() (keyPair KeyPair) {

	var privateKey, publicKey [32]byte
	_, err := rand.Read(privateKey[:])

	if err != nil {
		panic(err)
	}

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	keyPair.Private = privateKey[:]
	keyPair.Public = publicKey[:]
	keyPair.Initialized = true
	return
}

func (c Curve25519Function) DH(keyPair KeyPair, publicKey PublicKey) SharedPoint {
	if keyPair.Initialized == false {
		panic("cannot perform DH operation on uninitialized keypair")
	}
	var ss, pub, pri [32]byte
	copy(pub[:], publicKey)
	copy(pri[:], keyPair.Private)
	curve25519.ScalarMult(&ss, &pri, &pub)
	return ss[:]
}

func (c Curve25519Function) DHLen() int {
	return 32
}
