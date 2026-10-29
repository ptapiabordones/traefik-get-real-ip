package traefik_get_real_ip_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	plugin "github.com/ptapiabordones/traefik-get-real-ip"
)

const edgeSecret = "s3cr3t-edge-token"

// secretConfig is the obti.cl shape: Cloudflare adds a secret header, the origin only trusts requests that carry it.
func secretConfig(erase, sanitize bool) *plugin.Config {
	cfg := plugin.CreateConfig()
	cfg.SanitizeUnmatched = sanitize
	cfg.Proxy = []plugin.Proxy{{
		ProxyHeadername:  "X-Eas-Edge",
		ProxyHeadervalue: edgeSecret,
		RealIP:           "Cf-Connecting-Ip",
		OverwriteXFF:     true,
		EraseHeader:      erase,
	}}
	return cfg
}

func TestSecretHeaderHonoursTheClientIP(t *testing.T) {
	h := run(t, secretConfig(false, true), "192.168.1.254:5000", map[string]string{
		"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9",
	})
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9", got)
	}
}

// Direct hit without the secret: the claimed Cloudflare IP is ignored and forged values never pass.
func TestMissingSecretCannotSpoof(t *testing.T) {
	h := run(t, secretConfig(false, true), "192.168.1.254:5000", spoof)
	for _, name := range []string{"X-Real-Ip", "X-Forwarded-For"} {
		if got := h.Get(name); got != "192.168.1.254" {
			t.Fatalf("%s = %q, want the peer 192.168.1.254", name, got)
		}
	}
	// the forged Cf-Connecting-Ip must not survive into the logs either
	if got := h.Get("Cf-Connecting-Ip"); got != "" {
		t.Fatalf("untrusted Cf-Connecting-Ip kept: %q", got)
	}
}

func TestWrongSecretCannotSpoof(t *testing.T) {
	h := run(t, secretConfig(false, true), "192.168.1.254:5000", map[string]string{
		"X-Eas-Edge": "guess", "Cf-Connecting-Ip": "203.0.113.9", "X-Real-Ip": "198.51.100.7",
	})
	if got := h.Get("X-Real-Ip"); got != "192.168.1.254" {
		t.Fatalf("X-Real-Ip = %q, want the peer", got)
	}
}

// Without sanitizeUnmatched the previous behaviour stays: nothing is rewritten when no entry matches.
func TestSanitizeUnmatchedIsOptIn(t *testing.T) {
	h := run(t, secretConfig(false, false), "192.168.1.254:5000", map[string]string{"X-Real-Ip": "198.51.100.7"})
	if got := h.Get("X-Real-Ip"); got != "198.51.100.7" {
		t.Fatalf("X-Real-Ip = %q, want it untouched", got)
	}
}

// eraseHeader drops the secret but keeps Cf-Connecting-Ip (logs and Loki dashboards read it).
func TestEraseHeaderDropsOnlyTheSecret(t *testing.T) {
	h := run(t, secretConfig(true, true), "192.168.1.254:5000", map[string]string{
		"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9", "Cf-Ipcountry": "CL",
	})
	if got := h.Get("X-Eas-Edge"); got != "" {
		t.Fatalf("secret still present: %q", got)
	}
	if got := h.Get("Cf-Connecting-Ip"); got != "203.0.113.9" {
		t.Fatalf("Cf-Connecting-Ip = %q, must be kept", got)
	}
	if got := h.Get("Cf-Ipcountry"); got != "CL" {
		t.Fatalf("Cf-Ipcountry = %q, must be kept", got)
	}
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9", got)
	}
}

func TestSecretIsKeptWhenEraseHeaderIsOff(t *testing.T) {
	h := run(t, secretConfig(false, true), "192.168.1.254:5000", map[string]string{
		"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9",
	})
	if got := h.Get("X-Eas-Edge"); got != edgeSecret {
		t.Fatalf("secret = %q, want it kept when eraseHeader is off", got)
	}
}

// An empty secret (e.g. an empty file behind the env var) must never open the gate to requests without the header.
func TestEmptySecretNeverMatches(t *testing.T) {
	cfg := secretConfig(false, true)
	cfg.Proxy[0].ProxyHeadervalue = ""
	h := run(t, cfg, "192.168.1.254:5000", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Real-Ip"); got != "192.168.1.254" {
		t.Fatalf("X-Real-Ip = %q, want the peer: an empty secret must not match", got)
	}
}

// chain applies the same middleware twice, like EAS does (entrypoint middlewares + router middlewares).
func chain(t *testing.T, cfg *plugin.Config, remoteAddr string, headers map[string]string) http.Header {
	t.Helper()
	var seen http.Header
	final := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() })
	second, err := plugin.New(context.Background(), final, cfg, "router")
	if err != nil {
		t.Fatal(err)
	}
	first, err := plugin.New(context.Background(), second, cfg, "entrypoint")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	first.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

// The incident of 2026-10-28: with eraseHeader the second pass lost the real IP. It must keep it now.
func TestTwoPassesWithEraseHeaderKeepTheRealIP(t *testing.T) {
	h := chain(t, secretConfig(true, true), "192.168.1.254:5000", map[string]string{
		"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9", "Cf-Ipcountry": "CL",
	})
	if got := h.Get("X-Real-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Real-Ip = %q, want 203.0.113.9 after two passes", got)
	}
	if got := h.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For = %q, want 203.0.113.9 after two passes", got)
	}
	if got := h.Get("Cf-Connecting-Ip"); got != "203.0.113.9" {
		t.Fatalf("Cf-Connecting-Ip = %q, must survive both passes (access log / Loki)", got)
	}
	if got := h.Get("X-Eas-Edge"); got != "" {
		t.Fatalf("secret still present after the chain: %q", got)
	}
}

// A forged request stays sanitized through both passes.
func TestTwoPassesStillSanitizeForgedRequests(t *testing.T) {
	h := chain(t, secretConfig(true, true), "192.168.1.254:5000", spoof)
	for _, name := range []string{"X-Real-Ip", "X-Forwarded-For"} {
		if got := h.Get(name); got != "192.168.1.254" {
			t.Fatalf("%s = %q, want the peer", name, got)
		}
	}
	if got := h.Get("Cf-Connecting-Ip"); got != "" {
		t.Fatalf("forged Cf-Connecting-Ip survived: %q", got)
	}
}

// A client cannot skip the check by sending headers that look like a previous pass.
func TestClientCannotFakeAnEarlierPass(t *testing.T) {
	h := chain(t, secretConfig(true, true), "192.168.1.254:5000", map[string]string{
		"Cf-Connecting-Ip": "203.0.113.9", "X-Real-Ip": "198.51.100.7", "Eas.real-ip.verified": "203.0.113.9",
	})
	if got := h.Get("X-Real-Ip"); got != "192.168.1.254" {
		t.Fatalf("X-Real-Ip = %q, want the peer", got)
	}
}

func verifiedConfig(erase bool) *plugin.Config {
	cfg := secretConfig(erase, true)
	cfg.VerifiedHeader = "X-Eas-Verified"
	return cfg
}

// Valid secret => the marker says "1".
func TestVerifiedHeaderIsOneForTrustedRequests(t *testing.T) {
	h := run(t, verifiedConfig(true), "192.168.1.254:5000", map[string]string{"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Eas-Verified"); got != "1" {
		t.Fatalf("X-Eas-Verified = %q, want 1", got)
	}
}

// The honeypot case: a request that carries the decoy header but not the secret is marked "0".
func TestVerifiedHeaderIsZeroForDecoyWithoutSecret(t *testing.T) {
	h := run(t, verifiedConfig(true), "54.255.189.178:5000", map[string]string{"X-From-Cdn": "cf-foo", "Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Eas-Verified"); got != "0" {
		t.Fatalf("X-Eas-Verified = %q, want 0", got)
	}
	if got := h.Get("X-From-Cdn"); got != "cf-foo" {
		t.Fatalf("the decoy header must stay visible for the log: %q", got)
	}
}

// A client cannot claim to be verified.
func TestClientCannotForgeTheVerifiedMarker(t *testing.T) {
	h := run(t, verifiedConfig(true), "54.255.189.178:5000", map[string]string{"X-Eas-Verified": "1", "Cf-Connecting-Ip": "203.0.113.9"})
	if got := h.Get("X-Eas-Verified"); got != "0" {
		t.Fatalf("X-Eas-Verified = %q, a forged 1 must become 0", got)
	}
}

// Two passes (entrypoint + router) keep a trusted request at 1 and an untrusted one at 0.
func TestVerifiedHeaderSurvivesTwoPasses(t *testing.T) {
	ok := chain(t, verifiedConfig(true), "192.168.1.254:5000", map[string]string{"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9"})
	if got := ok.Get("X-Eas-Verified"); got != "1" {
		t.Fatalf("trusted after two passes: X-Eas-Verified = %q, want 1", got)
	}
	bad := chain(t, verifiedConfig(true), "192.168.1.254:5000", map[string]string{"X-From-Cdn": "cf-foo", "X-Eas-Verified": "1"})
	if got := bad.Get("X-Eas-Verified"); got != "0" {
		t.Fatalf("untrusted after two passes: X-Eas-Verified = %q, want 0", got)
	}
}

// With trustedPeers (ms1) the marker follows the peer check.
func TestVerifiedHeaderWithTrustedPeers(t *testing.T) {
	cfg := cfConfig("173.245.48.0/20")
	cfg.VerifiedHeader = "X-Eas-Verified"
	if got := run(t, cfg, "173.245.48.10:51000", map[string]string{"Cf-Connecting-Ip": "203.0.113.9"}).Get("X-Eas-Verified"); got != "1" {
		t.Fatalf("Cloudflare peer: X-Eas-Verified = %q, want 1", got)
	}
	if got := run(t, cfg, "54.255.189.178:5000", map[string]string{"Cf-Connecting-Ip": "203.0.113.9", "X-From-Cdn": "cf-foo"}).Get("X-Eas-Verified"); got != "0" {
		t.Fatalf("direct peer: X-Eas-Verified = %q, want 0", got)
	}
}

// Disabled by default: no header is added or touched.
func TestVerifiedHeaderOffByDefault(t *testing.T) {
	h := run(t, secretConfig(true, true), "192.168.1.254:5000", map[string]string{"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9"})
	if _, ok := h["X-Eas-Verified"]; ok {
		t.Fatalf("marker added although verifiedHeader is not configured")
	}
}
