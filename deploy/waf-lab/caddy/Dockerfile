# Caddy + OWASP Coraza WAF, built with xcaddy. Coraza is a library, so the WAF
# edge is a Caddy binary with the coraza-caddy module compiled in.
FROM caddy:2.11-builder AS builder
# coraza-caddy/v2 tracks a newer Go/Caddy than the builder image may ship (it
# pins GOTOOLCHAIN=local). Let Go fetch the toolchain the module requires so the
# WAF edge builds without hand-pinning the module to an older, unmaintained tag.
ENV GOTOOLCHAIN=auto
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2

FROM caddy:2.11-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
COPY coraza/ /etc/caddy/coraza/
