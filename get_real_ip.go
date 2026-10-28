package traefik_get_real_ip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	xRealIP       = "X-Real-Ip"
	xForwardedFor = "X-Forwarded-For"
)

// Proxy 配置文件中的数组结构
type Proxy struct {
	ProxyHeadername  string `yaml:"proxyHeadername"`
	ProxyHeadervalue string `yaml:"proxyHeadervalue"`
	RealIP           string `yaml:"realIP"`
	OverwriteXFF     bool   `yaml:"overwriteXFF"` // override X-Forwarded-For
	// TrustedPeers lists the CIDRs (or single IPs) of the TCP peers allowed to set the headers
	// of this entry (e.g. the Cloudflare edge ranges). Empty = any peer (legacy behaviour).
	// NOT the same as the unused "trustedProxies" key found in older configs.
	TrustedPeers []string `yaml:"trustedPeers"`
}

// Config the plugin configuration.
type Config struct {
	Proxy             []Proxy `yaml:"proxy"`
	EnableLog         bool    `yaml:"enableLog"`         // Enable logging output
	Deny403OnFail     bool    `yaml:"deny403OnFail"`     // Return 403 when no matching CDN header found
	EraseProxyHeaders bool    `yaml:"eraseProxyHeaders"` // Erase CDN secret headers after processing
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		EnableLog:         false, // Logging disabled by default
		Deny403OnFail:     false, // Do not deny by default
		EraseProxyHeaders: false, // Do not erase headers by default
	}
}

// GetRealIP Define plugin
type GetRealIP struct {
	next              http.Handler
	name              string
	proxy             []Proxy
	enableLog         bool
	deny403OnFail     bool
	eraseProxyHeaders bool
	peers             [][]*net.IPNet // parsed TrustedPeers, same index as proxy; nil = any peer
	restrict          bool           // at least one entry restricts its peers
}

// parsePeers turns CIDRs / plain IPs into networks. Invalid entries are skipped, so a typo
// can never open the entry to everyone: a restricted entry whose list is all invalid trusts nobody.
func parsePeers(entries []string) []*net.IPNet {
	nets := []*net.IPNet{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

// peerIP returns the TCP peer address of the request (no port).
func peerIP(req *http.Request) net.IP {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	return net.ParseIP(host)
}

func inNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// New creates and returns a new realip plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Always log instance creation regardless of log settings
	fmt.Printf("[get-realip] Instance created with %d proxy configurations\n", len(config.Proxy))

	peers := make([][]*net.IPNet, len(config.Proxy))
	restrict := false
	for i, p := range config.Proxy {
		if len(p.TrustedPeers) > 0 {
			peers[i] = parsePeers(p.TrustedPeers)
			restrict = true
		}
	}

	return &GetRealIP{
		peers:             peers,
		restrict:          restrict,
		next:              next,
		name:              name,
		proxy:             config.Proxy,
		enableLog:         config.EnableLog,
		deny403OnFail:     config.Deny403OnFail,
		eraseProxyHeaders: config.EraseProxyHeaders,
	}, nil
}

// 真正干事情了
func (g *GetRealIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var realIPStr string
	var foundMatchingProxy bool
	var matchedProxy Proxy

	peer := peerIP(req)

	for idx, proxy := range g.proxy {
		if g.peers[idx] != nil && !inNets(peer, g.peers[idx]) {
			g.log("Skipping entry %d: peer %v is not in trustedPeers", idx, peer)
			continue
		}
		if proxy.ProxyHeadername == "*" || req.Header.Get(proxy.ProxyHeadername) == proxy.ProxyHeadervalue {
			foundMatchingProxy = true
			matchedProxy = proxy
			g.log("Processing proxy configuration: %s (%s)", proxy.ProxyHeadervalue, proxy.ProxyHeadername)

			// CDN来源确定
			nIP := req.Header.Get(proxy.RealIP)
			if proxy.RealIP == "RemoteAddr" {
				nIP, _, _ = net.SplitHostPort(req.RemoteAddr)
			}
			forwardedIPs := strings.Split(nIP, ",") // 从头部获取到IP并分割（主要担心xff有多个IP）

			g.log("Processing IP addresses: %v (%d found)", forwardedIPs, len(forwardedIPs))
			// 如果有多个，得到第一个 IP
			for i := 0; i <= len(forwardedIPs)-1; i++ {
				trimmedIP := strings.TrimSpace(forwardedIPs[i])
				finalIP := g.getIP(trimmedIP)
				g.log("Validating IP: %s (index: %d, parsed: %s)", trimmedIP, i, finalIP)
				if finalIP != nil {
					realIPStr = finalIP.String()
					break
				}
			}
		}
		// 获取到后直接设定 realIP
		if realIPStr != "" {
			if proxy.OverwriteXFF {
				g.log("Overwriting X-Forwarded-For header with: %s", realIPStr)
				req.Header.Set(xForwardedFor, realIPStr)
			}
			req.Header.Set(xRealIP, realIPStr)
			break
		}
	}

	// If deny403OnFail is enabled and no matching proxy configuration was found
	// return 403 Forbidden response
	if g.deny403OnFail && !foundMatchingProxy && len(g.proxy) > 0 {
		g.log("No matching proxy configuration found, returning 403")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	// Restricted mode and nothing was trusted: never let client-supplied forwarding headers through.
	if g.restrict && realIPStr == "" && peer != nil {
		req.Header.Set(xRealIP, peer.String())
		req.Header.Set(xForwardedFor, peer.String())
	}

	// Erase CDN secret headers if enabled and we found a matching proxy
	if g.eraseProxyHeaders && foundMatchingProxy {
		g.log("Erasing CDN secret headers")
		if matchedProxy.ProxyHeadername != "*" {
			req.Header.Del(matchedProxy.ProxyHeadername)
			g.log("Erased header: %s", matchedProxy.ProxyHeadername)
		}

		// Only erase RealIP header if it's not a standard header like X-Forwarded-For
		// that might be needed by other middleware
		if matchedProxy.RealIP != "RemoteAddr" && matchedProxy.RealIP != xForwardedFor {
			req.Header.Del(matchedProxy.RealIP)
			g.log("Erased header: %s", matchedProxy.RealIP)
		}
	}

	g.next.ServeHTTP(rw, req)
}

// getIP is used to obtain valid IP addresses. The parameter s is the input IP text,
// which should be in the format of x.x.x.x or x.x.x.x:1234.
func (g *GetRealIP) getIP(s string) net.IP {
	pureIP, _, err := net.SplitHostPort(s) // 如果有端口号则分离得到ip
	if err != nil {
		pureIP = s
	}
	ip := net.ParseIP(pureIP) // 解析是否为合法 ip
	return ip
}

// log is a method of GetRealIP that outputs logs only if logging is enabled.
// Logs to /var/log/traefik/plugin-real-ip.log with timestamps.
func (g *GetRealIP) log(format string, a ...interface{}) {
	if g.enableLog {
		logFile, err := os.OpenFile("/var/log/traefik/plugin-real-ip.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer logFile.Close()
			timestamp := time.Now().Format("2006-01-02T15:04:05-07:00")
			logFile.WriteString(fmt.Sprintf("[%s] [get-realip] %s\n", timestamp, fmt.Sprintf(format, a...)))
		}
	}
}
