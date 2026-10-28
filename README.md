# Traefik Get Real IP address

[中文文档](README.cn.md)

<!-- cspell:words traefik middlewares proxyHeadername proxyHeadervalue Kubernetes -->

When traefik is deployed behind multiple load balancers, this plugin can be used to detect different load balancers and extract the real IP from different header fields, then output the value to the `x-real-ip` header.

This plugin can prevent IP spoofing by checking if the values form the received header information of the load balancer match before extracting the IP address.

For example, in the configuration of `CloudFlare` load balancer shown below, we configure it to only accept the header `x-from-cdn` with a value equal to `cf-foo`, and extract the IP address from the `Cf-Connecting-Ip` header. Since users never know about the existence of the `x-from-cdn` header or its required value `cf-foo`, it remains secure 🛡️. To increase complexity and avoid being guessed, you can use a random string :)

```
 CloudFlare
┌─────────┐
│         ├────────────────────────────────►  ┌───────┬────────┐
└─────────┘ x-from-cdn:cf-foo                 │       │        │
            Cf-Connecting-Ip: realip          │       │        │
 CDN2                                         │       │        │
┌─────────┐                                   │       │ paxxs's│
│         ├────────────────────────────────►  │traefik│        │ x-real-ip:realip
└─────────┘ x-from-cdn:mf-bar                 │       │Get-rea ├─────────────►
            Client-iP: realip                 │       │ l-ip   │
 CDN3                                         │       │Plugin  │
┌─────────┐                                   │       │        │
│         ├───────────────────────────────►   │       │        │
└─────────┘ x-from-cdn:mf-fun                 └───────┴────────┘
            x-forwarded-for: realip,x.x.x.x
                           (truthedIP)          ▲  ▲
                                                │  │
 ┌────────┐                                     │  │
 └────────┘ ────────────────────────────────────┘  │
   "*"                                             │
 ┌────────┐                RemoteAddr/etc..        │
 └────────┘ ───────────────────────────────────────┘
```

## CDN Configuration

E.g. Cloudflare:

Rules > Transform Rules > HTTP Request Header Modification > Add
- Set static Header: `X-From-Cdn`
  - Value: `cf-foo`

![image](https://user-images.githubusercontent.com/10364775/164590908-43edab8a-cdc8-4d4c-abd6-542b6c798f3b.png)

![image](https://user-images.githubusercontent.com/10364775/164591134-4dd2fc97-cd0e-4deb-8fe3-bcd4555ebbde.png)

## Traefik Configuration
### Static

Plugin Info:
- moduleName: `github.com/Paxxs/traefik-get-real-ip`
- version: `[Please fill the latest version !]`

Traefik Configuration:
- yml
- toml
- docker-labels

```yml
pilot:
  token: [REDACTED]

experimental:
  plugins:
    real-ip:
      moduleName: github.com/Paxxs/traefik-get-real-ip
      version: [Please fill the latest version !]
```

### Dynamic

- yml
- toml
- docker labels
- Kubernetes

```yml
http:
  middlewares:
    real-ip-foo:
      plugin:
        real-ip:
          enableLog: false # default: false, enable to see detailed logs
          deny403OnFail: true # default: false, when true returns 403 if no matching CDN header found
          eraseProxyHeaders: true # default: false, erase CDN-specific headers after processing
          Proxy:
            - proxyHeadername: X-From-Cdn
              proxyHeadervalue: mf-fun
              realIP: X-Forwarded-For
            - proxyHeadername: X-From-Cdn
              proxyHeadervalue: mf-bar
              realIP: Client-Ip
              OverwriteXFF: true # default: false, v1.0.2 or above
            - proxyHeadername: X-From-Cdn
              proxyHeadervalue: cf-foo
              realIP: Cf-Connecting-Ip
              OverwriteXFF: true # default: false, v1.0.2 or above
            - proxyHeadername: "*"
              realIP: RemoteAddr

  routers:
    my-router:
      rule: Host(`localhost`)
      middlewares:
        - real-ip-foo
      service: my-service

  services:
    my-service:
      loadBalancer:
        servers:
          - url: 'http://127.0.0.1'
```

## Configuration Options

| Option            | Type  | Required | Default | Description                                                                                   |
| ----------------- | ----- | -------- | ------- | --------------------------------------------------------------------------------------------- |
| enableLog         | bool  | No       | false   | Enable detailed logging for debugging purposes                                                |
| deny403OnFail     | bool  | No       | false   | When true, returns a 403 Forbidden response if no matching CDN header is found                |
| eraseProxyHeaders | bool  | No       | false   | When true, erases CDN-specific headers after processing to prevent leaking CDN identification |
| Proxy             | array | Yes      | -       | Array of proxy configurations                                                                 |

### Proxy Configuration

| Option           | Type   | Required | Default | Description                                                                                                 |
| ---------------- | ------ | -------- | ------- | ----------------------------------------------------------------------------------------------------------- |
| proxyHeadername  | string | Yes      | -       | The header name to check for CDN identification. Use "*" to match all sources                               |
| proxyHeadervalue | string | No       | -       | The expected value for the header. Not required when proxyHeadername is "*"                                 |
| realIP           | string | Yes      | -       | The header to extract the real IP from. Special value "RemoteAddr" will use the connection's remote address |
| OverwriteXFF     | bool   | No       | false   | When set to true, also overwrites the X-Forwarded-For header with the extracted real IP (v1.0.2+)           |

### Processing Logic

1. The plugin checks each proxy configuration in order.
2. For each configuration, it checks if the request has the specified `proxyHeadername` with value `proxyHeadervalue` (or accepts any if `proxyHeadername` is "*").
3. When a match is found, it extracts the IP from the header specified in `realIP`.
4. The extracted IP is set as the `X-Real-Ip` header.
5. If `OverwriteXFF` is true, the `X-Forwarded-For` header is also overwritten with the extracted IP.
6. If `eraseProxyHeaders` is true, the plugin removes the CDN-specific headers (the matched `proxyHeadername` and `realIP` headers) to prevent leaking CDN identification to downstream services. Standard headers like X-Forwarded-For are preserved.
7. If no matching proxy configuration is found and `deny403OnFail` is set to true, the plugin returns a 403 Forbidden response, preventing further request processing.
8. Otherwise, the request is then passed to the next handler.

## EAS: `trustedPeers` (2026-10-28)

By default an entry with `proxyHeadername: '*'` believes `Cf-Connecting-Ip` from **any** client, so anyone who reaches the origin directly can choose the IP Traefik, CrowdSec and the apps see. `trustedPeers` (per entry) restricts an entry to the TCP peers listed there:

```yaml
Proxy:
- proxyHeadername: '*'
  realIP: CF-Connecting-IP
  OverwriteXFF: true
  trustedPeers:            # CIDRs or single IPs of the Cloudflare edge
  - 173.245.48.0/20
  - 2606:4700::/32
```

- Peer not in the list: the entry is skipped. If any entry uses `trustedPeers`, `X-Real-Ip` and `X-Forwarded-For` are then overwritten with the peer address (client-supplied values never pass); with `deny403OnFail: true` the request gets 403.
- Without `trustedPeers` the behaviour is exactly the previous one.
- Invalid entries are ignored; an entry whose list is entirely invalid trusts nobody (a typo cannot open it up).
- It replaces the old `trustedProxies` key found in EAS configs, which this plugin never implemented (it was silently ignored).
- Only meaningful where the TCP peer identifies the proxy (microserver1: the Cloudflare edge). On obti.cl the PA-850 source-NATs inbound traffic to 192.168.1.254, so the peer says nothing about the sender there.

### Secret-header mode (`eraseHeader`, `sanitizeUnmatched`) - when the TCP peer says nothing

Behind a NAT/firewall that hides the sender (obti.cl: the PA-850 source-NATs to 192.168.1.254) `trustedPeers` cannot work. Make Cloudflare add a **secret** request header (a Transform Rule per zone) and trust only requests that carry it:

```yaml
Proxy:
- proxyHeadername: X-Eas-Edge        # header set by the Cloudflare Transform Rule
  proxyHeadervalue: '{{ env "CF_EDGE_TOKEN" }}'
  realIP: CF-Connecting-IP
  OverwriteXFF: true
  eraseHeader: true                  # drop ONLY the secret before the backends / access log
sanitizeUnmatched: true              # no valid secret => X-Real-Ip/X-Forwarded-For = TCP peer
```

- **Do not use the global `eraseProxyHeaders: true`**: it also deletes `Cf-Connecting-Ip`, which then disappears from `access.log` (`request_Cf-Connecting-Ip`) and breaks the Loki dashboards. `eraseHeader` removes only the secret.
- Use a random secret (not a constant like `cf-foo`, which is public in the repo). Introduce it in two steps to avoid a gap: first the Cloudflare rule, then the origin config.
