package diffiehellman

import (
	"crypto/elliptic"
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
	"math/big"
)

type SharedPoint []byte
type PrivateKey []byte
type PublicKey []byte

type KeyPair struct {
	Private PrivateKey
	Public  PublicKey
}

type DHFunction interface {
	GenerateKeyPair() (keyPair KeyPair)
	DH(keyPair KeyPair, publicKey PublicKey) SharedPoint
	DHLen() int
}

type DHCurve25519 struct{}

func (c DHCurve25519) GenerateKeyPair() (keyPair KeyPair) {

	privateKey := make([]byte, 32)
	_, err = rand.Read(privateKey)

	if err != nil {
		panic(err)
	}

	publicKey := make([]byte, 32)
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	keyPair.Private = privateKey
	keyPair.Public = publicKey
}

func (c DHCurve25519) DH(keyPair KeyPair, publicKey PublicKey) SharedPoint {
	return curve25519.ScalarBaseMult(&publicKey, &keyPair.Private)
}

func (c DHCurve25519) DHLen() int {
	return 32
}
