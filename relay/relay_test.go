package relay

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/hashicorp/yamux"

	"github.com/byke-project/bridge/protocol"
)

// fakeGateway is the gateway's side of the protocol, enough to test a relay: it enrolls one token, welcomes the
// certificates it issued, and hands each session to the test.
type fakeGateway struct {
	t        *testing.T
	key      ed25519.PrivateKey
	token    string
	sessions chan *yamux.Session
	mu       sync.Mutex
	seen     []string // enroll, hello, refused
}

func newFakeGateway(t *testing.T) (*fakeGateway, *httptest.Server) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	g := &fakeGateway{t: t, key: key, token: "bet_test", sessions: make(chan *yamux.Session, 4)}
	srv := httptest.NewServer(http.HandlerFunc(g.handle))
	t.Cleanup(srv.Close)
	return g, srv
}

func (g *fakeGateway) note(s string) {
	g.mu.Lock()
	g.seen = append(g.seen, s)
	g.mu.Unlock()
}

func (g *fakeGateway) handle(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.Version}})
	if err != nil {
		return
	}
	ctx := context.Background()
	nonce := protocol.Nonce()
	_ = wsjson.Write(ctx, c, protocol.Challenge{Type: protocol.TypeChallenge, Nonce: nonce})
	var raw json.RawMessage
	if wsjson.Read(ctx, c, &raw) != nil {
		return
	}
	issuers := map[string]ed25519.PublicKey{"k1": g.key.Public().(ed25519.PublicKey)}
	var cert protocol.Certificate
	switch protocol.TypeOf(raw) {
	case protocol.TypeEnroll:
		var e protocol.Enroll
		_ = json.Unmarshal(raw, &e)
		if e.Token != g.token || !protocol.Proven(e.PublicKey, nonce, e.Proof) {
			g.note("refused")
			_ = wsjson.Write(ctx, c, protocol.Refused{Type: protocol.TypeRefused, Reason: "the token is not valid"})
			c.Close(websocket.StatusPolicyViolation, "refused")
			return
		}
		g.note("enroll")
		g.token = "" // one use
		cert = protocol.Certificate{RelayID: "r1", Account: "acc", Bridge: "office", PublicKey: e.PublicKey,
			IssuedAt: time.Now(), ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}
		cert.Sign("k1", g.key)
	case protocol.TypeHello:
		var h protocol.Hello
		_ = json.Unmarshal(raw, &h)
		if h.Certificate.Verify(issuers, time.Now()) != nil || !protocol.Proven(h.Certificate.PublicKey, nonce, h.Proof) {
			g.note("refused")
			_ = wsjson.Write(ctx, c, protocol.Refused{Type: protocol.TypeRefused, Reason: "not a relay of ours"})
			return
		}
		g.note("hello")
		cert = h.Certificate
	}
	_ = wsjson.Write(ctx, c, protocol.Welcome{Type: protocol.TypeWelcome, Certificate: cert})
	c.SetReadLimit(16 << 20)
	s, err := yamux.Client(websocket.NetConn(ctx, c, websocket.MessageBinary), yamuxConfig())
	if err != nil {
		return
	}
	g.sessions <- s
	<-s.CloseChan()
}

// open asks the relay for a connection, answering what it said and the stream.
func open(t *testing.T, s *yamux.Session, host string, port int) (protocol.Opened, net.Conn) {
	t.Helper()
	st, err := s.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteLine(st, protocol.Open{Kind: protocol.KindConnect, Target: "t", Host: host, Port: port, Call: "c1"}); err != nil {
		t.Fatal(err)
	}
	var o protocol.Opened
	if err := protocol.ReadLine(st, &o); err != nil {
		t.Fatal(err)
	}
	return o, st
}

func echoServer(t *testing.T) (string, int) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte("echo: " + line))
			}()
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func TestARelayEnrollsOnce_thenSaysHello_andCarriesOnlyWhatItsAllowListNames(t *testing.T) {
	g, srv := newFakeGateway(t)
	host, port := echoServer(t)
	dir := t.TempDir()
	cfg := Config{Server: "ws" + strings.TrimPrefix(srv.URL, "http") + protocol.Path, Token: "bet_test", StateDir: dir,
		Allow: []string{"127.0.0.1:" + itoa(port)}, Version: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	s := <-g.sessions

	o, st := open(t, s, host, port)
	if !o.OK {
		t.Fatalf("an allowed target: %+v", o)
	}
	_, _ = st.Write([]byte("hi\n"))
	got, _ := bufio.NewReader(st).ReadString('\n')
	if got != "echo: hi\n" {
		t.Fatalf("the bytes both ways: %q", got)
	}
	st.Close()

	if o, _ := open(t, s, host, port+1); o.OK || o.Code != "not_allowed" {
		t.Fatalf("a port its list doesn't name: %+v", o)
	}
	if o, _ := open(t, s, "169.254.169.254", 80); o.OK || o.Code != "not_allowed" {
		t.Fatalf("anything else: %+v", o)
	}

	// Restarted without its token, it says hello with the certificate it kept.
	cancel()
	s.Close()
	cfg.Token = ""
	r2, err := New(cfg)
	if err != nil {
		t.Fatalf("enrolled, it needs no token: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go r2.Run(ctx2)
	<-g.sessions
	g.mu.Lock()
	defer g.mu.Unlock()
	if strings.Join(g.seen, ",") != "enroll,hello" {
		t.Fatalf("the gateway saw %v", g.seen)
	}
}

func TestATokenTheGatewayRefusesStopsTheRelay(t *testing.T) {
	_, srv := newFakeGateway(t)
	r, err := New(Config{Server: "ws" + strings.TrimPrefix(srv.URL, "http") + protocol.Path, Token: "bet_wrong",
		StateDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = r.Run(ctx)
	var refused Refusal
	if !asRefusal(err, &refused) {
		t.Fatalf("a refused token ends the relay: %v", err)
	}
}

func TestWithNeitherACertificateNorATokenItWontStart(t *testing.T) {
	if _, err := New(Config{Server: "ws://x", StateDir: t.TempDir()}); err != ErrNotEnrolled {
		t.Fatalf("%v", err)
	}
}

func TestTheAllowList(t *testing.T) {
	r := &Relay{}
	var err error
	r.allow, err = protocol.ParseAllow([]string{"erp.internal:8080", "*.corp.example:443", "10.0.4.0/24:5432", "192.168.1.9:*"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"erp.internal", 8080, "erp.internal:8080"},
		{"ERP.internal.", 8080, "ERP.internal.:8080"},
		{"erp.internal", 8081, ""},
		{"crm.corp.example", 443, "crm.corp.example:443"},
		{"corp.example", 443, ""},
		{"10.0.4.17", 5432, "10.0.4.17:5432"},
		{"10.0.5.17", 5432, ""},
		{"192.168.1.9", 22, "192.168.1.9:22"},
		{"127.0.0.1", 8080, ""},
	} {
		got, ok := r.allowed(c.host, c.port)
		if (c.want != "") != ok || ok && got != c.want {
			t.Errorf("%s:%d → %q %v, want %q", c.host, c.port, got, ok, c.want)
		}
	}
	for _, bad := range []string{"erp.internal", "erp.internal:0", "10.0.0.0/33:80", ":80"} {
		if _, err := protocol.ParseAllow([]string{bad}); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestWhatAListCoversFromOutside(t *testing.T) {
	l, _ := protocol.ParseAllow([]string{"erp.internal:8080", "10.0.4.0/24:5432"})
	for _, c := range []struct {
		host string
		port int
		want bool
	}{{"erp.internal", 8080, true}, {"erp.internal", 9090, false}, {"10.0.4.7", 5432, true}, {"10.0.5.7", 5432, false},
		{"db.internal", 5432, true /* a name a network rule resolves: the relay decides */}, {"db.internal", 5433, false}} {
		if got := l.Covers(c.host, c.port); got != c.want {
			t.Errorf("%s:%d → %v", c.host, c.port, got)
		}
	}
}

func TestACertificateIsBykesWordUntilItExpires(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c := protocol.Certificate{RelayID: "r1", Account: "a", Bridge: "b", PublicKey: pub, IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour)}
	c.Sign("k1", key)
	issuers := map[string]ed25519.PublicKey{"k1": key.Public().(ed25519.PublicKey)}
	if err := c.Verify(issuers, time.Now()); err != nil {
		t.Fatal(err)
	}
	if c.Verify(issuers, time.Now().Add(2*time.Hour)) == nil {
		t.Fatal("expired, it holds no more")
	}
	other := c
	other.Bridge = "another"
	if other.Verify(issuers, time.Now()) == nil {
		t.Fatal("a field changed, the signature fails")
	}
	if c.Verify(map[string]ed25519.PublicKey{}, time.Now()) == nil {
		t.Fatal("an unknown issuer")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func asRefusal(err error, r *Refusal) bool {
	x, ok := err.(Refusal)
	if ok {
		*r = x
	}
	return ok
}
