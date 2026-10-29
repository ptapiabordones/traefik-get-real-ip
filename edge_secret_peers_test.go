package traefik_get_real_ip_test

import (
	"os"
	"strings"
	"testing"

	plugin "github.com/ptapiabordones/traefik-get-real-ip"
)

const pluginLog = "/var/log/traefik/plugin-real-ip.log"

// The plugin log must never contain the Cloudflare edge secret (found 2026-10-29: «Processing proxy
// configuration: <secret> (X-Eas-Edge)» was written to a world-readable file on obti.cl).
func TestPluginLogNeverContainsTheSecret(t *testing.T) {
	if err := os.MkdirAll("/var/log/traefik", 0o755); err != nil {
		t.Skipf("cannot create the log directory: %v", err)
	}
	_ = os.Remove(pluginLog)
	cfg := secretConfig(true, true)
	cfg.EnableLog = true
	run(t, cfg, "192.168.1.254:5000", map[string]string{"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9"})
	raw, err := os.ReadFile(pluginLog)
	if err != nil {
		t.Fatalf("expected the plugin log to exist: %v", err)
	}
	if strings.Contains(string(raw), edgeSecret) {
		t.Fatalf("the plugin log leaks the edge secret:\n%s", raw)
	}
	if !strings.Contains(string(raw), "(X-Eas-Edge)") {
		t.Fatalf("the log should still say which entry matched:\n%s", raw)
	}
}

var cloudflareRanges = []string{"173.245.48.0/20", "103.21.244.0/22"}

// ms1 shape: the peer must be a Cloudflare range AND the request must carry the secret.
func edgePeersConfig(withFallback bool) *plugin.Config {
	cfg := plugin.CreateConfig()
	cfg.VerifiedHeader = "X-Eas-Verified"
	cfg.Proxy = []plugin.Proxy{{
		ProxyHeadername:  "X-Eas-Edge",
		ProxyHeadervalue: edgeSecret,
		RealIP:           "Cf-Connecting-Ip",
		OverwriteXFF:     true,
		EraseHeader:      true,
		TrustedPeers:     cloudflareRanges,
	}}
	if withFallback {
		cfg.Proxy = append(cfg.Proxy, plugin.Proxy{
			ProxyHeadername: "*",
			RealIP:          "Cf-Connecting-Ip",
			OverwriteXFF:    true,
			TrustedPeers:    cloudflareRanges,
		})
	}
	return cfg
}

var viaCloudflare = "173.245.48.10:51000"

func TestEdgeSecretFromCloudflarePeerIsVerifiedAndErased(t *testing.T) {
	h := chain(t, edgePeersConfig(true), viaCloudflare, map[string]string{"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "203.0.113.9"})
	if h.Get("X-Real-Ip") != "203.0.113.9" || h.Get("X-Eas-Verified") != "1" {
		t.Fatalf("X-Real-Ip=%q X-Eas-Verified=%q, want 203.0.113.9 and 1", h.Get("X-Real-Ip"), h.Get("X-Eas-Verified"))
	}
	if h.Get("X-Eas-Edge") != "" {
		t.Fatalf("the secret must not reach the backends, got %q", h.Get("X-Eas-Edge"))
	}
}

// The temporary fallback keeps the real IP while Cloudflare is not sending the secret yet.
func TestFallbackKeepsTheIPWhileCloudflareHasNoSecretYet(t *testing.T) {
	h := chain(t, edgePeersConfig(true), viaCloudflare, map[string]string{"Cf-Connecting-Ip": "203.0.113.9"})
	if h.Get("X-Real-Ip") != "203.0.113.9" || h.Get("X-Eas-Verified") != "1" {
		t.Fatalf("fallback: X-Real-Ip=%q X-Eas-Verified=%q", h.Get("X-Real-Ip"), h.Get("X-Eas-Verified"))
	}
}

// The hole the secret closes: someone proxying through THEIR OWN Cloudflare account has a Cloudflare peer
// but not the secret. Without the fallback they are no longer believed.
func TestOwnCloudflareAccountWithoutTheSecretIsNotBelieved(t *testing.T) {
	h := chain(t, edgePeersConfig(false), viaCloudflare, map[string]string{"X-From-Cdn": "cf-foo", "Cf-Connecting-Ip": "198.51.100.77"})
	if h.Get("X-Eas-Verified") != "0" {
		t.Fatalf("X-Eas-Verified = %q, want 0", h.Get("X-Eas-Verified"))
	}
	if got := h.Get("X-Real-Ip"); got == "198.51.100.77" {
		t.Fatalf("the claimed client IP must not be believed, X-Real-Ip = %q", got)
	}
}

// A direct hit that knows the secret is still rejected: the peer is not a Cloudflare range.
func TestSecretFromANonCloudflarePeerIsNotBelieved(t *testing.T) {
	h := chain(t, edgePeersConfig(true), "54.255.189.178:5000", map[string]string{"X-Eas-Edge": edgeSecret, "Cf-Connecting-Ip": "198.51.100.77"})
	if h.Get("X-Eas-Verified") != "0" {
		t.Fatalf("X-Eas-Verified = %q, want 0", h.Get("X-Eas-Verified"))
	}
}
