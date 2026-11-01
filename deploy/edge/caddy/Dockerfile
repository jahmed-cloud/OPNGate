FROM caddy:2.11.6-builder AS builder
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2@v2.6.2 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.14.1

FROM caddy:2.11.6
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
