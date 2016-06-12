package cipher

import (
	"bytes"
	"crypto/aes"
	cipherstdlib "crypto/cipher"
	"encoding/binary"
)

// CipherFunction is an interface that is used for symmetric encryption and
// authentication. All symmetric operations must implement this interface.
type CipherFunction interface {
	Encrypt(nonce uint64, key, ad, plaintext []byte) (ciphertext []byte)
	Decrypt(nonce uint64, key, ad, ciphertext []byte) (plaintext []byte, err error)
}

// GCMFunction implements the CipherFunction interface using the AESGCM AEAD.
type GCMFunction struct{}

// Encrypt encrypts and authenticates the supplied plaintext
// using AES-GCM with the supplied key and nonce. The ad
// parameter is authenticated but not encrypted.
// Encrypt returns the encrypted data and authentication tag.
func (g GCMFunction) Encrypt(nonce uint64, key, ad, plaintext []byte) (ciphertext []byte) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aead, err := cipherstdlib.NewGCM(block)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, nonce)
	return aead.Seal(ciphertext, buf.Bytes(), plaintext, ad)
}

// Decrypt decrypts and authenticates the supplied ciphertext
// using AES-GCM with the supplied key and nonce. The ad
// parameter is just authenticated and not decrypted.
// Decrypt returns the decrypted ciphertext. If there
// was an authentication failure, Decrypt returns a error.
func (g GCMFunction) Decrypt(nonce uint64, key, ad, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aead, err := cipherstdlib.NewGCM(block)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, nonce)
	return aead.Open(plaintext, buf.Bytes(), ciphertext, ad)
}
