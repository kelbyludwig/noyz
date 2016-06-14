package pattern

// HandshakePattern describes how an initiator and a responder will negotiate a
// shared secret.
type HandshakePattern struct {
	// initiatorPreMessages are keys that are known to an initiator prior
	// to a handshake. Can be empty.
	InitiatorPreMessages []string
	// responderPreMessages are keys that are known to an responder prior
	// to a handshake. Can be empty.
	ResponderPreMessages []string
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

func noiseNN() HandshakePattern {
	hp := HandshakePattern{}
	hp.MessagePattern = []string{"e", "e,dhee"}
	return hp
}

func Initialize(handshakePatternName, diffieHellman, hashFunction, cipher string) (handshakePattern HandshakePattern) {

	switch handshakePatternName {
	case "NN":
		handshakePattern = noiseNN()
		handshakePattern.HandshakePatternName = handshakePatternName
	default:
		panic("supplied handshake pattern not supported")
	}

	handshakePattern.DiffieHellman = diffieHellman
	handshakePattern.HashFunction = hashFunction
	handshakePattern.SymmetricCipher = cipher
	return handshakePattern
}
