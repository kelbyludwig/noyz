package state

//TODO(kkl): Document.
type CipherState struct {
	// K is the symmetric key used for encryption/decryption.
	K []byte
	// N is the nonce used for encryption/decryption.
	N []byte
	// initialized is used to determine if the CipherState has a itialized K value.
	// In the Noise Protocol specificiation, this is called "empty," however with
	// Golang's zero values this naming scheme makes a bit more sense.
	initialized bool
}

// InitializeKey initializes a CipherState struct
// and sets the starting nonce and key values.
func (cs *CipherState) InitializeKey(key []byte) {
	copy(cs.K, key)
	cs.N = make([]byte, 8)
	cs.initialized = true
}

// HasKey return true if the specified CipherState is
// initialized and false otherwise.
func (cs CipherState) HasKey() bool {
	return cs.initialized
}

//TODO(kkl): Document.
func (cs *CipherState) EncryptWithAD(ad, plaintext []byte) []byte {
	if cs.HasKey() {
		//ENCRYPT(k, n++, ad, plaintext)
	} else {
		return plaintext //TODO(kkl): If this used to signal an encryption error modify the return type.
	}
}

//TODO(kkl): Document.
func (cs *CipherState) DecryptWithAD(ad, ciphertext []byte) ([]byte, error) {
	if cs.HasKey() {
		return ciphertext
	} else {
		//DECRYPT(k,n++,ad,ciphertext)
	}
}

//TODO(kkl): Document.
type SymmetricState struct {
	CipherState CipherState
	// CK is the chaining key.
	CK []byte
	// H is the handshake hash.
	H []byte //TODO Use the golang interface for a hash?
}

//TODO(kkl): Document.
func (ss *SymmetricState) InitializeSymmetric(protocolName []byte) {
	lpn := len(protocolName)
	if lpn <= HASHLEN {
		difference := HASHLEN - lpn
		ss.H = make([]byte, HASHLEN)
		copy(ss.H, protocolName)
	}
	copy(ss.CK, ss.H)
	ss.CipherState = CipherState{}
}

//TODO(kkl): Document.
func (ss *SymmetricState) MixKey(inputKeyMaterial []byte) {
	ck, tempK := HKDF(ss.CK, inputKeyMaterial)
	if HASHLEN == 64 {
		tempK = tempK[:32]
	}
	ss.CipherState.InitializeKey(tempK)
}

//TODO(kkl): Document.
func (ss *SymmetricState) MixHash(data []byte) {
	ss.H = HASH(append(ss.H, data...))
}

// EncryptAndHash will encrypt the supplied plaintext and return the
// ciphertext. If the SymmetricState struct is unitialized, it will return the
// input plaintext.
func (ss *SymmetricState) EncryptAndHash(plaintext []byte) (ciphertext []byte) {
	ciphertext = EncryptWithAD(ss.H, plaintext)
	ss.MixHash(ciphertext)
	return ciphertext
}

// DecryptAndHash will decrypt the supplied ciphertext and return the decrypted
// plaintext. If the SymmetricState struct is unitialized, it will return the
// input ciphertext.
func (ss *SymmetricState) DecryptAndHash(ciphertext []byte) (plaintext []byte) {
	plaintext = DecryptWithAD(ss.H, ciphertext)
	ss.MixHash(ciphertext)
	return plaintext
}

//TODO(kkl): Document.
func (ss *SymmetricState) Split() (ss1, ss2 SymmetricState) {
	panic("Split() Not implemented")
}

//TODO(kkl): Document.
type HandshakeState struct {
	// SymmetricState maintains the state for encryption and decryption.
	SymmetricState SymmetricState
	// S is the local static key pair
	S KeyPair
	// E is the local ephemeral key pair
	E KeyPair
	// RS is the remote party's static public key
	RS KeyPair //TODO(kkl): Should these be public key structs?
	// RE is the remote party's ephemeral public key
	RE KeyPair
	// MessagePattern is the remaining portions of the handshake's pattern
	MessagePattern []string
}

//TODO(kkl): Document.
func (hss *HandshakeState) Initialize(handshakePattern string, initiator bool, prologue []byte, s, e, rs, re KeyPair) {
	panic("Initialize not implemented")
}
