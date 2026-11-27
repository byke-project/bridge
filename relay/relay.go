// Package relay is byke bridge: the program a customer runs inside their network so byke's agents can reach the
// services they choose, without opening anything to the internet.
//
// It dials out to byke's bridge gateway over a WebSocket (through the customer's outbound proxy when HTTPS_PROXY says
// so), proves who it is, and then carries the connections the gateway asks for, to the targets its own allow list
// names and no others. Each connection is written to its log, which its owner reads.
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/hashicorp/yamux"

	"gitlab.com/byke-project/com.byke.bridge/protocol"
)

// Config is how a relay runs.
type Config struct {
	// Server is the gateway's address: wss://bridge.byke.dev/v1/relay.
	Server string
	// Token is the one-time enrollment token from the Bridges page; needed only until the relay is enrolled.
	Token string
	// StateDir keeps the relay's key and certificate (keep it on a volume: without it the relay is enrolled anew).
	StateDir string
	// Allow is what the relay may reach: host:port, *.suffix:port, or a network as CIDR:port; a port of * is any.
	Allow []string
	// Version is this relay's.
	Version string
	// Log is where every connection is written.
	Log *slog.Logger
	// DialTimeout bounds a connection to a target.
	DialTimeout time.Duration
	// HTTPClient dials the gateway (its transport honours HTTPS_PROXY); nil: one that does.
	HTTPClient *http.Client
}

// ErrNotEnrolled is a relay with neither a certificate nor a token.
var ErrNotEnrolled = errors.New("not enrolled: start it once with the token the Bridges page gives (BYKE_BRIDGE_TOKEN)")

// Refusal is the gateway turning the relay away for good: it must be enrolled anew.
type Refusal struct{ Reason string }

func (r Refusal) Error() string { return "the gateway refused this relay: " + r.Reason }

// Relay is one running relay.
type Relay struct {
	cfg   Config
	allow protocol.AllowList
	key   ed25519.PrivateKey

	mu   sync.Mutex
	cert *protocol.Certificate

	connected atomic.Bool
}

// New reads (or makes) the relay's key and certificate in cfg.StateDir and checks its allow list.
func New(cfg Config) (*Relay, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	rules, err := protocol.ParseAllow(cfg.Allow)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("its state directory: %w", err)
	}
	key, err := loadOrMakeKey(filepath.Join(cfg.StateDir, "relay.key"))
	if err != nil {
		return nil, err
	}
	r := &Relay{cfg: cfg, allow: rules, key: key}
	if b, err := os.ReadFile(filepath.Join(cfg.StateDir, "certificate.json")); err == nil {
		var c protocol.Certificate
		if json.Unmarshal(b, &c) == nil && string(c.PublicKey) == string(key.Public().(ed25519.PublicKey)) {
			r.cert = &c
		}
	}
	if r.cert == nil && cfg.Token == "" {
		return nil, ErrNotEnrolled
	}
	return r, nil
}

// Connected says whether the relay holds a session with the gateway now.
func (r *Relay) Connected() bool { return r.connected.Load() }

// Run keeps the relay connected until ctx ends, reconnecting with backoff. It returns early on a Refusal.
func (r *Relay) Run(ctx context.Context) error {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := r.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var refused Refusal
		if errors.As(err, &refused) {
			return err
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		wait := backoff + time.Duration(jitter(int64(backoff/2)))
		r.cfg.Log.Warn("disconnected", "error", errString(err), "retry_in", wait.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
	return nil
}

// session is one connection to the gateway: the handshake, then the streams it opens, until it ends.
func (r *Relay) session(ctx context.Context) error {
	c, _, err := websocket.Dial(ctx, r.cfg.Server, &websocket.DialOptions{
		HTTPClient:   r.cfg.HTTPClient,
		Subprotocols: []string{protocol.Version},
	})
	if err != nil {
		return fmt.Errorf("dialling the gateway: %w", err)
	}
	defer c.CloseNow()
	c.SetReadLimit(protocol.MaxLine)
	if err := r.handshake(ctx, c); err != nil {
		return err
	}
	c.SetReadLimit(16 << 20)
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	session, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		return err
	}
	defer session.Close()
	r.connected.Store(true)
	defer r.connected.Store(false)
	r.cfg.Log.Info("connected", "server", r.cfg.Server, "relay", r.cert.RelayID, "bridge", r.cert.Bridge)
	for {
		s, err := session.AcceptStream()
		if err != nil {
			return fmt.Errorf("the session ended: %w", err)
		}
		go r.serve(s)
	}
}

func (r *Relay) handshake(ctx context.Context, c *websocket.Conn) error {
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var ch protocol.Challenge
	if err := wsjson.Read(hctx, c, &ch); err != nil || ch.Type != protocol.TypeChallenge || len(ch.Nonce) < 16 {
		return fmt.Errorf("the gateway's challenge: %v", errOr(err, "not a challenge"))
	}
	proof := protocol.Prove(r.key, ch.Nonce)
	info := protocol.Relay{Version: r.cfg.Version, Hostname: hostname(), Allow: r.cfg.Allow}
	var msg any
	if r.cert != nil {
		msg = protocol.Hello{Type: protocol.TypeHello, Certificate: *r.cert, Proof: proof, Relay: info}
	} else {
		msg = protocol.Enroll{Type: protocol.TypeEnroll, Token: r.cfg.Token, PublicKey: r.key.Public().(ed25519.PublicKey),
			Proof: proof, Relay: info}
	}
	if err := wsjson.Write(hctx, c, msg); err != nil {
		return err
	}
	var raw json.RawMessage
	if err := wsjson.Read(hctx, c, &raw); err != nil {
		return fmt.Errorf("the gateway's answer: %w", err)
	}
	switch protocol.TypeOf(raw) {
	case protocol.TypeWelcome:
		var w protocol.Welcome
		if err := json.Unmarshal(raw, &w); err != nil {
			return err
		}
		return r.keep(w.Certificate)
	case protocol.TypeRefused:
		var f protocol.Refused
		_ = json.Unmarshal(raw, &f)
		if f.Retry {
			return errors.New("the gateway refused for now: " + f.Reason)
		}
		return Refusal{Reason: f.Reason}
	default:
		return errors.New("the gateway's answer is neither welcome nor refused")
	}
}

// keep saves a certificate the gateway gave, if it is for this relay's key.
func (r *Relay) keep(c protocol.Certificate) error {
	if string(c.PublicKey) != string(r.key.Public().(ed25519.PublicKey)) {
		return errors.New("the gateway's certificate is for another key")
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	path := filepath.Join(r.cfg.StateDir, "certificate.json")
	if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	r.mu.Lock()
	r.cert = &c
	r.mu.Unlock()
	return nil
}

// serve is one stream the gateway opened.
func (r *Relay) serve(s net.Conn) {
	defer s.Close()
	_ = s.SetReadDeadline(time.Now().Add(30 * time.Second))
	var open protocol.Open
	if err := protocol.ReadLine(s, &open); err != nil {
		return
	}
	_ = s.SetReadDeadline(time.Time{})
	switch open.Kind {
	case protocol.KindControl:
		r.control(s)
	case protocol.KindConnect:
		r.connect(s, open)
	}
}

// control reads the gateway's messages: renewed certificates.
func (r *Relay) control(s net.Conn) {
	for {
		var w protocol.Welcome
		if err := protocol.ReadLine(s, &w); err != nil {
			return
		}
		if w.Type == protocol.TypeWelcome {
			if err := r.keep(w.Certificate); err != nil {
				r.cfg.Log.Warn("a renewed certificate was not kept", "error", err.Error())
			} else {
				r.cfg.Log.Info("certificate renewed", "expires_at", w.Certificate.ExpiresAt)
			}
		}
	}
}

// connect carries one connection to a target, if the allow list lets it.
func (r *Relay) connect(s net.Conn, o protocol.Open) {
	started := time.Now()
	log := r.cfg.Log.With("call", o.Call, "target", o.Target, "address", o.Address())
	addr, ok := r.allowed(o.Host, o.Port)
	if !ok {
		_ = protocol.WriteLine(s, protocol.Opened{Code: "not_allowed",
			Error: "this relay's allow list does not name " + o.Address()})
		log.Warn("refused", "outcome", "not_allowed")
		return
	}
	d := net.Dialer{Timeout: r.cfg.DialTimeout}
	t, err := d.Dial("tcp", addr)
	if err != nil {
		_ = protocol.WriteLine(s, protocol.Opened{Code: "unreachable", Error: "the relay could not reach " + o.Address() + ": " + reason(err)})
		log.Warn("unreachable", "outcome", "unreachable", "error", reason(err))
		return
	}
	defer t.Close()
	if err := protocol.WriteLine(s, protocol.Opened{OK: true}); err != nil {
		return
	}
	up, down := pipe(s, t)
	log.Info("connection", "outcome", "done", "bytes_up", up, "bytes_down", down,
		"duration_ms", time.Since(started).Milliseconds())
}

// pipe copies both ways until both are done; it answers the bytes sent each way.
func pipe(a, b net.Conn) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		aToB, _ = io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = b.Close()
		}
	}()
	bToA, _ = io.Copy(a, b)
	_ = a.Close()
	wg.Wait()
	return
}

// allowed says where to dial for host:port, if the allow list names it. A name is allowed by a name rule and
// dialled by name; an address (or a name's addresses) by a network rule, and dialled at the address it allowed.
func (r *Relay) allowed(host string, port int) (string, bool) {
	if port < 1 || port > 65535 || host == "" {
		return "", false
	}
	if r.allow.Names(host, port) {
		return net.JoinHostPort(host, strconv.Itoa(port)), true
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if addrs, err := net.LookupIP(host); err == nil {
		ips = addrs
	}
	for _, ip := range ips {
		if r.allow.Holds(ip, port) {
			return net.JoinHostPort(ip.String(), strconv.Itoa(port)), true
		}
	}
	return "", false
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 20 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	return c
}

func loadOrMakeKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not a relay key", path)
		}
		return ed25519.NewKeyFromSeed(b), nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key.Seed(), 0o600); err != nil {
		return nil, fmt.Errorf("keeping its key: %w", err)
	}
	return key, nil
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func jitter(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

func reason(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
