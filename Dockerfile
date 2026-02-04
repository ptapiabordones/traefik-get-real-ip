ARG TRAEFIK_VERSION=3.6.7
FROM traefik:${TRAEFIK_VERSION}

LABEL org.opencontainers.image.source="https://github.com/ptapiabordones/traefik-get-real-ip"
LABEL org.opencontainers.image.description="Traefik EAS - Traefik with get-real-ip plugin for Cloudflare"
LABEL org.opencontainers.image.authors="ptapia@obti.cl"

# Plugin path must match go.mod module name
COPY . /plugins-local/src/github.com/ptapiabordones/traefik-get-real-ip/

# Create log directory for plugin
RUN mkdir -p /var/log/traefik
