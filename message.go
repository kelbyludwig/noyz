package message

type TransportMessage struct {
	//SIV        [16]byte
	//TODO: TransportMessages use either a prepended SIV or an appeneded Tag. Not both.
	Ciphertext []byte
	Tag        [16]byte
}

type HandShakeMessage struct {
	PublicKeys []PublicKey
	Payload    []byte
}
