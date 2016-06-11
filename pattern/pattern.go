package pattern

import (
	"github.com/kelbyludwig/noyz/state"
)

func noiseNN() state.HandshakePattern {
	hp := state.HandshakePattern{}
	hp.MessagePattern = []string{"e", "e,dhee"}
	return hp
}

func Initialize(handshakePatternName, diffieHellman, hashFunction, symmetricCipher string) (handshakePattern state.HandshakePattern) {

	switch handshakePatternName {
	case "NN":
		handshakePattern = noiseNN()
		handshakePattern.HandshakePatternName = handshakePatternName
	default:
		panic("supplied handshake pattern not supported")
	}

	handshakePattern.DiffieHellman = diffieHellman
	handshakePattern.HashFunction = hashFunction
	handshakePattern.SymmetricCipher = symmetricCipher
	return handshakePattern
}
