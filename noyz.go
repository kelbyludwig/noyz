package noyz

import (
	"fmt"
	"github.com/kelbyludwig/patterns"
	"github.com/kelbyludwig/state"
	"net"
)

//FRAMEMAX is the largest noise message minus two bytes for transmitting the length.
const FRAMEMAX int = 65533

type Config struct {
	Rand io.Reader
	//TODO(kkl): Config should include static keys, pre-messages, noise pattern, etc.
}

type Noyz struct {
	conn  net.Conn
	hs    state.HandshakeState
	recvr state.CipherState
	sendr state.CipherState
}

func Listen(network, laddr string, config *Config) (net.Listener, error) {

}

func Dial(network, addr string, config *Config) (*Conn, error) {

	nz := Noyz{}
	nz.hs = state.HandshakeState{}
	conn, err := net.Dial(network, addr)

	if err != nil {
		return conn, err
	}

	hp := pattern.Initialize("NN", "25519", "SHA256", "AESGCM")
	nz.hs.Initialize(hp, true, nil, nil, nil, nil, nil)

	var c1, c2 CipherState
	var messageBuffer, payloadBuffer []byte
	for {
		c1, c2 = nz.hs.WriteMessage(payloadBuffer, &messageBuffer)

		if c1.HasKey() && c2.HasKey() {
			nz.conn = conn
			nz.recvr = c1
			nz.sendr = c2
			return nz, nil
		}

		_, err := conn.Write(messageBuffer)

		if err != nil {
			return conn, fmt.Errof("noise handshake failure: %v\n", err)
		}

		_, err := conn.Read(payloadBuffer)

		if err != nil {
			return conn, fmt.Errof("noise handshake failure: %v\n", err)
		}

		c1, c2 = nz.hs.ReadMessage(messageBuffer, &payloadBuffer)

		if c1.HasKey() && c2.HasKey() {
			nz.conn = conn
			nz.recvr = c1
			nz.sendr = c2
			return nz, nil
		}
	}

}

func (nz *Noyz) Accept() (net.Conn, error) {

}

func (nz *Noyz) Close() error {

}

func (nz *Noyz) Addr() net.Addr {

}

// Read reads data from the connection. Read can be made to time out and
// return a Error with Timeout() == true after a fixed time limit; see
// SetDeadline and SetReadDeadline.
func (nz *Noyz) Read(b []byte) (n int, err error) {

	readBuf := make([]byte, len(b)+2)
	rr, rerr := nz.conn.Read(readBuf)

	if rerr != nil {
		return 0, rerr
	}

	if rr < 2 {
		return 0, fmt.Errorf("could not read message length")
	}

	//read 2 bytes to determine the length of the incoming payload.
	toRead := (int(readBuff[0]) << 8) + int(readBuff[1])

	if toRead > len(b) {
		return 0, fmt.Errorf("buffer size smaller than payload")
	}

	readBuf = readBuf[2:]
	n = rr - 2

	for {
		if n == toRead {

			plaintext, rerr := nz.recvr.DecryptWithAD([]byte{}, readBuf)
			if rerr != nil {
				return 0, rerr
			}

			n = copy(b, plaintext)
			return n, nil

		} else {

			rr, rerr = nz.conn.Read(readBuf[n:])
			n = n + rr

			if rerr != nil {
				return 0, rerr
			}

		}
	}
}

// Write writes data to the connection. Write can be made to time out and
// return a Error with Timeout() == true after a fixed time limit; see
// SetDeadline and SetWriteDeadline.
func (nz *Noyz) Write(b []byte) (n int, err error) {

	l := len(b)

	if l > FRAMEMAX {
		return 0, fmt.Errorf("message too large")
	}

	ciphertext, err := nz.sendr.EncryptWithAD([]byte{}, b)

	if err != nil {
		return 0, err
	}

	lc := len(ciphertext)
	frame := make([]byte, lc+2)
	frame[0] = byte(lc >> 8)
	frame[1] = byte(lc & 0x00ff)
	copy(frame[2:], ciphertext)

	return nz.conn.Write(frame)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (nz *Noyz) Close() error {
	return nz.conn.Close()
}

// LocalAddr returns the local network address.
func (nz *Noyz) LocalAddr() Addr {
	return nz.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (nz *Noyz) RemoteAddr() Addr {
	return nz.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future I/O, not just
// the immediately following call to Read or Write.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (nz *Noyz) SetDeadline(t time.Time) error {
	return nz.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (nz *Noyz) SetReadDeadline(t time.Time) error {
	return nz.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (nz *Noyz) SetWriteDeadline(t time.Time) error {
	return nz.conn.SetWriteDeadline(t)
}
