package state

import (
	"crypto/sha256"
	"github.com/kelbyludwig/noyz/hash"
	"testing"
)

func TestMixHashSHA256(t *testing.T) {

	full := []byte("Testing123")
	prefix := []byte("Testing")
	postfix := []byte("123")

	ss := SymmetricState{}
	ss.h = prefix
	ss.cs.hf = hash.SHA256Function{}

	ss.MixHash(postfix)
	h := sha256.Sum256(full)

	if string(h[:]) != string(ss.h) {
		t.Errorf("sha256 output did not match intended output")
		return
	}
}
