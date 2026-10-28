package traefik_get_real_ip_test

import (
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
