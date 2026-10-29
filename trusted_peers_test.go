package traefik_get_real_ip_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	plugin "github.com/ptapiabordones/traefik-get-real-ip"
)

// run sends one request through the plugin and returns the headers the next handler saw.
func run(t *testing.T, cfg *plugin.Config, remoteAddr string, headers map[string]string) http.Header {
	t.Helper()
	var seen http.Header
	next := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() })
	h, err := plugin.New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

func cfConfig(peers ...string) *plugin.Config {
	cfg := plugin.CreateConfig()
	cfg.Proxy = []plugin.Proxy{{
		ProxyHeadername: "*",
		RealIP:          "Cf-Connecting-Ip",
		OverwriteXFF:    true,
		TrustedPeers:    peers,
	}}
	return cfg
}

var spoof = map[string]string{
	"Cf-Connecting-Ip": "203.0.113.9",
	"X-Forwarded-For":  "198.51.100.7",
	"X-Real-Ip":        "198.51.100.7",
}

// The header is honoured when the TCP peer is a trusted Cloudflare edge.
func TestTrustedPeerHeaderIsHonoured(t *testing.T) {
	h := run(t, cfConfig("173.245.48.0/20"), "173.245.48.10:51000", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9", got)
	}
	if got := h.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For = %q, want 203.0.113.9", got)
	}
}

// A client hitting the origin directly cannot choose its own IP.
func TestUntrustedPeerCannotSpoof(t *testing.T) {
	h := run(t, cfConfig("173.245.48.0/20"), "54.255.189.178:40000", spoof)
	if got := h.Get("X-Real-Ip"); got != "54.255.189.178" {
		t.Fatalf("X-Real-Ip = %q, want the peer 54.255.189.178", got)
	}
	if got := h.Get("X-Forwarded-For"); got != "54.255.189.178" {
		t.Fatalf("X-Forwarded-For = %q, want the peer 54.255.189.178", got)
	}
}

// Cloudflare's IPv6 edge ranges work too.
func TestIPv6PeerIsTrusted(t *testing.T) {
	h := run(t, cfConfig("2606:4700::/32"), "[2606:4700:10::6814:1]:443", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9", got)
	}
}

// A single IP (no mask) is accepted as a peer.
func TestSingleIPPeer(t *testing.T) {
	h := run(t, cfConfig("192.168.1.254"), "192.168.1.254:1234", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9", got)
	}
}

// Without trustedPeers the behaviour is exactly the legacy one (header honoured from anyone).
func TestLegacyWithoutTrustedPeersIsUnchanged(t *testing.T) {
	h := run(t, cfConfig(), "54.255.189.178:40000", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9 (legacy)", got)
	}
	// and nothing is rewritten when no entry applies in legacy mode
	h = run(t, cfConfig(), "54.255.189.178:40000", map[string]string{"X-Real-Ip": "198.51.100.7"})
	if got := h.Get("X-Real-Ip"); got != "198.51.100.7" {
		t.Fatalf("legacy mode rewrote X-Real-Ip: %q", got)
	}
}

// A typo in trustedPeers must never open the entry to everyone: it trusts nobody.
func TestInvalidPeersTrustNobody(t *testing.T) {
	h := run(t, cfConfig("not-a-cidr", "300.1.1.1/8"), "173.245.48.10:51000", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Real-Ip"); got != "173.245.48.10" {
		t.Fatalf("X-Real-Ip = %q, want the peer 173.245.48.10", got)
	}
}

// A trusted peer that sends no usable header is still sanitised to the peer address.
func TestTrustedPeerWithoutHeaderFallsBackToPeer(t *testing.T) {
	h := run(t, cfConfig("173.245.48.0/20"), "173.245.48.10:51000", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if got := h.Get("X-Forwarded-For"); got != "173.245.48.10" {
		t.Fatalf("X-Forwarded-For = %q, want the peer 173.245.48.10", got)
	}
}

// With several entries, only the one whose peers match is used.
func TestMultipleEntriesPickByPeer(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.Proxy = []plugin.Proxy{
		{ProxyHeadername: "*", RealIP: "Cf-Connecting-Ip", TrustedPeers: []string{"173.245.48.0/20"}},
		{ProxyHeadername: "*", RealIP: "X-Other-Ip", TrustedPeers: []string{"10.0.0.0/8"}},
	}
	h := run(t, cfg, "10.1.2.3:5555", map[string]string{"Cf-Connecting-Ip": "203.0.113.9", "X-Other-Ip": "192.0.2.50"})
	if got := h.Get("X-Real-Ip"); got != "192.0.2.50" {
		t.Fatalf("X-Real-Ip = %q, want 192.0.2.50 from the second entry", got)
	}
}

// With deny403OnFail, a direct hit from an untrusted peer is rejected instead of passed through.
func TestUntrustedPeerGets403WithDeny403OnFail(t *testing.T) {
	cfg := cfConfig("173.245.48.0/20")
	cfg.Deny403OnFail = true
	next := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {})
	h, err := plugin.New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "54.255.189.178:40000"
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
