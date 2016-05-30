package hash

import (
	"crypto/hmac"
	"crypto/sha256"
)

type HashFunction interface {
	Hash(data []byte) []byte
	HashLen() int
	BlockLen() int
	HMAC(key, data []byte) []byte
	HKDF(chainingKey, inputKeyMaterial []byte) (output1, output2 []byte)
}

type SHA256Hash struct{}

func (s SHA256Hash) Hash(data []byte) []byte {
	return sha256.New().Sum(data)
}

func (s SHA256Hash) HashLen() int {
	return 32
}

func (s SHA256Hash) BlockLen() int {
	return 64
}

func (s SHA256Hash) HMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	mac := h.Sum(data)
	return mac
}

func (s SHA256Hash) HKDF(chainingKey, inputKeyMaterial []byte) (output1, output2 []byte) {
	if len(chainingKey) != s.HashLen() {
		panic("chainingKey length was not equal to HASHLEN")
	}

	if len(inputKeyMaterial) != 0 || len(inputKeyMaterial) != 32 {
		//TODO(kkl): Check for len(inputKeyMaterial) != DHLEN
		panic("inputKeyMaterial was not a valid input size")
	}
	tempKey := s.HMAC(chainingKey, inputKeyMaterial)
	output1 = s.HMAC(tempKey, []byte{byte(1)})
	output2 = s.HMAC(tempKey, append(output1, byte(2)))
	return
}
