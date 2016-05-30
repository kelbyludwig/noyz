package session

type NoiseSession struct {
	HandshakePattern string
	DHFunction       DHFunction
	CipherFunction   CipherFunction
	HashFunction     HashFunction
}
