package cipher

import (
	"crypto/aes"
	cipherstdlib "crypto/cipher"
)

// CipherFunction is an interface that is used for symmetric encryption and
// authentication. All symmetric operations must implement this interface.
type CipherFunction interface {
	Encrypt(key, nonce, ad, plaintext []byte) (ciphertext []byte)
	Decrypt(key, nonce, ad, ciphertext []byte) (plaintext []byte, err error)
}

// GCMFunction implements the CipherFunction interface using the AESGCM AEAD.
type GCMFunction struct{}

// Encrypt encrypts and authenticates the supplied plaintext
// using AES-GCM with the supplied key and nonce. The ad
// parameter is authenticated but not encrypted.
// Encrypt returns the encrypted data and authentication tag.
func (g GCMFunction) Encrypt(key, nonce, ad, plaintext []byte) (ciphertext []byte) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aead, err := cipherstdlib.NewGCMWithNonceSize(block, 8)
	if err != nil {
		panic(err)
	}

	return aead.Seal(ciphertext, nonce, plaintext, ad)
}

// Decrypt decrypts and authenticates the supplied ciphertext
// using AES-GCM with the supplied key and nonce. The ad
// parameter is just authenticated and not decrypted.
// Decrypt returns the decrypted ciphertext. If there
// was an authentication failure, Decrypt returns a error.
func (g GCMFunction) Decrypt(key, nonce, ad, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aead, err := cipherstdlib.NewGCMWithNonceSize(block, 8)
	if err != nil {
		panic(err)
	}

	return aead.Open(plaintext, nonce, ciphertext, ad)
}
