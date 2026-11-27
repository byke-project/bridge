// Package protocol is what byke bridge's relay and byke's bridge gateway say to each other.
//
// A relay runs inside a customer's network and dials out to the gateway over a WebSocket (wss://, so it needs no
// inbound port and works through the customer's outbound proxy). The two first shake hands in JSON text messages:
//
//	gateway → relay  Challenge {nonce}
//	relay → gateway  Enroll {one-time token, the relay's new public key, proof}   (the first time)
//	              or Hello {its certificate, proof}                               (every time after)
//	gateway → relay  Welcome {a certificate, new or renewed}  or  Refused {reason}
//
// The proof is the relay's Ed25519 signature over the gateway's nonce: the relay proves it holds its key inside the
// session, so a firewall that inspects TLS (and would break client certificates) doesn't break it. The certificate is
// byke's signature over the relay's identity and public key, short-lived and renewed while connected.
//
// Then the WebSocket carries a yamux session. The gateway opens a stream per connection it wants: a header line
// (Open) naming the target, the relay's answer line (Opened), then the bytes both ways. The relay reaches only what
// its own allow list names, whatever the gateway asks.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Version is this protocol's; the WebSocket subprotocol names it.
const Version = "byke-bridge.v1"

// Path is where the gateway takes relays.
const Path = "/v1/relay"

// MaxLine is the most a handshake message or a stream header may be.
const MaxLine = 64 << 10

// Handshake messages, by Type.
const (
	TypeChallenge = "challenge"
	TypeEnroll    = "enroll"
	TypeHello     = "hello"
	TypeWelcome   = "welcome"
	TypeRefused   = "refused"
)

// Challenge is the gateway's first message: a nonce the relay signs.
type Challenge struct {
	Type    string `json:"type"`
	Nonce   []byte `json:"nonce"`
	Gateway string `json:"gateway,omitempty"`
}

// Relay says what a relay is: its version, its host's name and what its allow list lets it reach.
type Relay struct {
	Version  string   `json:"version"`
	Hostname string   `json:"hostname,omitempty"`
	Allow    []string `json:"allow,omitempty"`
}

// Enroll is a new relay's answer: the one-time token from the Bridges page, its new public key, and its proof.
type Enroll struct {
	Type      string `json:"type"`
	Token     string `json:"token"`
	PublicKey []byte `json:"public_key"`
	Proof     []byte `json:"proof"`
	Relay     Relay  `json:"relay"`
}

// Hello is an enrolled relay's answer: its certificate and its proof.
type Hello struct {
	Type        string      `json:"type"`
	Certificate Certificate `json:"certificate"`
	Proof       []byte      `json:"proof"`
	Relay       Relay       `json:"relay"`
}

// Welcome lets a relay in, with a certificate to keep (new, renewed, or the one it has).
type Welcome struct {
	Type        string      `json:"type"`
	Certificate Certificate `json:"certificate"`
}

// Refused turns a relay away. Retry false: it will be turned away again until it is enrolled anew.
type Refused struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
	Retry  bool   `json:"retry"`
}

// Certificate is byke's word that a public key is a relay of an account's bridge, until it expires.
type Certificate struct {
	RelayID   string    `json:"relay_id"`
	Account   string    `json:"account"`
	Bridge    string    `json:"bridge"`
	PublicKey []byte    `json:"public_key"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Issuer names the key that signed it (byke may hold several while one is rotated out).
	Issuer    string `json:"issuer"`
	Signature []byte `json:"signature,omitempty"`
}

// signed is what a certificate's signature covers: every field but the signature, in this order.
func (c Certificate) signed() []byte {
	c.Signature = nil
	b, _ := json.Marshal(c)
	return append([]byte(Version+" certificate\n"), b...)
}

// Sign signs c as issuer with key.
func (c *Certificate) Sign(issuer string, key ed25519.PrivateKey) {
	c.Issuer = issuer
	c.Signature = ed25519.Sign(key, c.signed())
}

// Verify checks c's signature against the issuers' keys and that it holds at now.
func (c Certificate) Verify(issuers map[string]ed25519.PublicKey, now time.Time) error {
	key, ok := issuers[c.Issuer]
	if !ok {
		return fmt.Errorf("signed by an unknown issuer %q", c.Issuer)
	}
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return errors.New("its public key is not an Ed25519 key")
	}
	if !ed25519.Verify(key, c.signed(), c.Signature) {
		return errors.New("its signature does not verify")
	}
	if now.Before(c.IssuedAt.Add(-time.Minute)) || !now.Before(c.ExpiresAt) {
		return errors.New("it has expired")
	}
	return nil
}

// ProofMessage is what a relay signs to prove its key: the gateway's nonce, named.
func ProofMessage(nonce []byte) []byte {
	return []byte(Version + " proof\n" + base64.StdEncoding.EncodeToString(nonce))
}

// Prove signs nonce with key.
func Prove(key ed25519.PrivateKey, nonce []byte) []byte {
	return ed25519.Sign(key, ProofMessage(nonce))
}

// Proven says whether proof is pub's signature over nonce.
func Proven(pub []byte, nonce, proof []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), ProofMessage(nonce), proof)
}

// Nonce is 32 random bytes.
func Nonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Stream kinds.
const (
	// KindConnect asks the relay to connect to a target and carry the bytes.
	KindConnect = "connect"
	// KindControl carries the gateway's messages to the relay (a renewed certificate).
	KindControl = "control"
)

// Open is the first line the gateway writes on a stream.
type Open struct {
	Kind string `json:"kind"`
	// Target is the name the account registered it under; Host and Port where it is.
	Target string `json:"target,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	// Call is the call's id (the run's event), for both sides' logs.
	Call string `json:"call,omitempty"`
}

// Opened is the relay's answer to a connect: OK, or why not (Code: not_allowed, unreachable, refused).
type Opened struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

// Address is Host:Port as dialled.
func (o Open) Address() string {
	if strings.Contains(o.Host, ":") {
		return fmt.Sprintf("[%s]:%d", o.Host, o.Port)
	}
	return fmt.Sprintf("%s:%d", o.Host, o.Port)
}

// WriteLine writes v as one JSON line.
func WriteLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadLine reads one JSON line into v, at most MaxLine bytes, reading no further than its end (the bytes after it
// are the stream's).
func ReadLine(r io.Reader, v any) error {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
			if len(line) > MaxLine {
				return errors.New("a line longer than allowed")
			}
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				break
			}
			return err
		}
	}
	return json.Unmarshal(line, v)
}

// TypeOf reads a handshake message's type.
func TypeOf(raw []byte) string {
	var t struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(raw, &t)
	return t.Type
}
