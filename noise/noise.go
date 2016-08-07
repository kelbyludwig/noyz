package noise

import (
	"fmt"
	"github.com/kelbyludwig/noyz/pattern"
	"github.com/kelbyludwig/noyz/state"
	"io"
	"log"
	"net"
	"time"
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

type listener struct {
	net.Listener
	*Config
}

func (l listener) Accept() (conn net.Conn, err error) {

	conn, err = l.Listener.Accept()
	if err != nil {
		return
	}

	log.Printf("accept: accepted connection\n")
	log.Printf("accept: setting up handshakestate\n")

	nz := Noyz{}
	nz.hs = state.HandshakeState{}
	hp := pattern.Initialize("NN", "25519", "SHA256", "AESGCM")
	nz.hs.Initialize(hp, false, nil, nil, nil, nil, nil)

	log.Printf("accept: should be getting a public key\n")
	payloadBuffer := make([]byte, 128)
	n, err := conn.Read(payloadBuffer)
	log.Printf("accept: read %v bytes %v\n", n, payloadBuffer[:n])
	if err != nil && err != io.EOF {
		return conn, err
	}

	log.Printf("accept: formulating a response\n")
	var readOutputBuffer, writeOutputBuffer []byte
	nz.hs.ReadMessage(payloadBuffer[:n], &readOutputBuffer)
	c1, c2 := nz.hs.WriteMessage(readOutputBuffer, &writeOutputBuffer)
	n, err = conn.Write(writeOutputBuffer)
	log.Printf("accept: wrote %v bytes to connection %v\n", n, writeOutputBuffer[:n])

	if err != nil && err != io.EOF {
		return conn, fmt.Errorf("failed to write responder payload")
	}

	if c1.HasKey() && c2.HasKey() {
		log.Printf("accept: handshake complete\n")
		nz.conn = conn
		nz.recvr = c2
		nz.sendr = c1
		return nz, nil
	} else {
		log.Printf("accept: handshake failed\n")
		return nz, fmt.Errorf("handshake failed\n")
	}

}

func (l listener) Close() error {
	return l.Listener.Close()
}

func (l listener) Addr() net.Addr {
	return l.Listener.Addr()
}

func Listen(network, laddr string, config *Config) (net.Listener, error) {

	inner, err := net.Listen(network, laddr)

	if err != nil {
		return inner, err
	}

	outer := listener{}
	outer.Listener = inner
	outer.Config = config
	return outer, nil

}

func Dial(network, addr string, config *Config) (net.Conn, error) {

	nz := Noyz{}
	nz.hs = state.HandshakeState{}
	log.Printf("dial: dialing")
	conn, err := net.Dial(network, addr)

	if err != nil {
		return conn, err
	}

	log.Printf("dial: initializing handshakestate")
	hp := pattern.Initialize("NN", "25519", "SHA256", "AESGCM")
	nz.hs.Initialize(hp, true, nil, nil, nil, nil, nil)

	log.Printf("dial: sending public key\n")
	var publicKeyBuffer []byte
	nz.hs.WriteMessage([]byte{}, &publicKeyBuffer)
	log.Printf("dial: publicKeyBuffer size %v\n", len(publicKeyBuffer))
	n, err := conn.Write(publicKeyBuffer)
	log.Printf("dial: sent %v bytes from publicKeyBuffer %v\n", n, publicKeyBuffer)

	if err != nil && err != io.EOF {
		return conn, fmt.Errorf("noise handshake failure: %v\n", err)
	}

	log.Printf("dial: reading public key\n")
	publicKeyBuffer = make([]byte, 128)
	n, err = conn.Read(publicKeyBuffer)
	log.Printf("dial: read %v bytes from responder %v\n", n, publicKeyBuffer[:n])

	if err != nil && err != io.EOF {
		return conn, fmt.Errorf("noise handshake failure: %v\n", err)
	}

	log.Printf("dial: readmessage\n")
	var outputBuffer []byte
	c1, c2 := nz.hs.ReadMessage(publicKeyBuffer[:n], &outputBuffer)

	if c1.HasKey() && c2.HasKey() {
		log.Printf("dial: handshake done")
		nz.conn = conn
		nz.recvr = c1
		nz.sendr = c2
		return nz, nil
	} else {
		log.Printf("dial: handshake failed\n")
		return nz, fmt.Errorf("handshake failed")
	}
}

// Read reads data from the connection. Read can be made to time out and
// return a Error with Timeout() == true after a fixed time limit; see
// SetDeadline and SetReadDeadline.
func (nz Noyz) Read(b []byte) (n int, err error) {

	readBuf := make([]byte, len(b)+2)
	rr, rerr := nz.conn.Read(readBuf)

	if rerr != nil {
		return 0, rerr
	}

	if rr < 2 {
		return 0, fmt.Errorf("could not read message length")
	}

	//read 2 bytes to determine the length of the incoming payload.
	toRead := (int(readBuf[0]) << 8) + int(readBuf[1])

	log.Printf("read: i should be reading %v bytes\n", toRead)

	if toRead > len(b) {
		return 0, fmt.Errorf("buffer size smaller than payload")
	}

	readBuf = readBuf[2:]
	n = rr - 2

	for {
		if n == toRead {

			log.Printf("read: decrypting %v\n", readBuf[:toRead])
			plaintext, rerr := nz.recvr.DecryptWithAD([]byte{}, readBuf[:toRead])
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
func (nz Noyz) Write(b []byte) (n int, err error) {

	l := len(b)

	if l > FRAMEMAX {
		return 0, fmt.Errorf("message too large")
	}

	log.Printf("write: encrypting plaintext %v\n", b)

	ciphertext := nz.sendr.EncryptWithAD([]byte{}, b)

	log.Printf("write: ciphertext %v\n", ciphertext)

	if err != nil {
		return 0, err
	}

	lc := len(ciphertext)
	log.Printf("write: length of ciphertext %v\n", lc)
	frame := make([]byte, lc+2)
	frame[0] = byte(lc >> 8)
	frame[1] = byte(lc & 0x00ff)
	copy(frame[2:], ciphertext)
	log.Printf("write: writing frame %v\n", frame)

	return nz.conn.Write(frame)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (nz Noyz) Close() error {
	return nz.conn.Close()
}

// LocalAddr returns the local network address.
func (nz Noyz) LocalAddr() net.Addr {
	return nz.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (nz Noyz) RemoteAddr() net.Addr {
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
func (nz Noyz) SetDeadline(t time.Time) error {
	return nz.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (nz Noyz) SetReadDeadline(t time.Time) error {
	return nz.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (nz Noyz) SetWriteDeadline(t time.Time) error {
	return nz.conn.SetWriteDeadline(t)
}
