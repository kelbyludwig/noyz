package pattern

import (
	"github.com/kelbyludwig/noyz/state"
)

func NoiseNN() state.HandshakePattern {
	hp := state.HandshakePattern{}
	hp.MessagePattern = []string{"e", "e,dhee"}
	return hp
}
