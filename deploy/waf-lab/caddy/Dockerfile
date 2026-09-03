# Caddy + OWASP Coraza WAF, built with xcaddy. Coraza is a library, so the WAF
# edge is a Caddy binary with the coraza-caddy module compiled in.
FROM caddy:2.8-builder AS builder
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:2.8-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
COPY coraza/ /etc/caddy/coraza/
