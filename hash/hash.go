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

type SHA256Function struct{}

func (s SHA256Function) Hash(data []byte) []byte {
	r := sha256.Sum256(data)
	return r[:]
}

func (s SHA256Function) HashLen() int {
	return 32
}

func (s SHA256Function) BlockLen() int {
	return 64
}

func (s SHA256Function) HMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	mac := h.Sum(nil)
	return mac
}

func (s SHA256Function) HKDF(chainingKey, inputKeyMaterial []byte) (output1, output2 []byte) {
	if len(chainingKey) != s.HashLen() {
		panic("chainingKey length was not equal to HASHLEN")
	}

	if len(inputKeyMaterial) != 0 && len(inputKeyMaterial) != 32 {
		//TODO(kkl): Check for len(inputKeyMaterial) != DHLEN
		panic("inputKeyMaterial was not a valid input size")
	}
	tempKey := s.HMAC(chainingKey, inputKeyMaterial)
	output1 = s.HMAC(tempKey, []byte{byte(1)})
	output2 = s.HMAC(tempKey, append(output1, byte(2)))
	return
}
