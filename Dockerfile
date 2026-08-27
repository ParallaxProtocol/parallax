# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

# Build Prlx in a stock Go builder container
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache gcc musl-dev linux-headers git

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod /parallax/
COPY go.sum /parallax/
RUN cd /parallax && go mod download

ADD . /parallax
RUN cd /parallax && go run build/ci.go install ./cmd/parallaxd ./cmd/parallax-cli ./cmd/parallax-wallet ./cmd/parallax

# Pull Prlx into a second stage deploy alpine container. The tag is
# pinned (not :latest) so rebuilding a released version yields the same
# base; bump it deliberately alongside the Go builder image.
FROM alpine:3.24

# Upgrade first so security fixes released after the base tag (e.g. the
# libcrypto3/libssl3 patches) land in the image without a base bump.
RUN apk upgrade --no-cache \
  && apk add --no-cache ca-certificates \
  && addgroup -g 1000 parallax \
  && adduser -D -u 1000 -G parallax parallax \
  # Pre-create the mount points owned by the runtime user; a named
  # volume inherits the ownership baked into the image, and a root-owned
  # mount point would make the unprivileged daemon fail at startup.
  && mkdir -p /home/parallax/.parallax /home/parallax/.xhash \
  && chown -R parallax:parallax /home/parallax

COPY --from=builder /parallax/build/bin/parallaxd /usr/local/bin/
COPY --from=builder /parallax/build/bin/parallax-cli /usr/local/bin/
COPY --from=builder /parallax/build/bin/parallax-wallet /usr/local/bin/
COPY --from=builder /parallax/build/bin/parallax /usr/local/bin/

# Run as an unprivileged user. The datadir lives in the user's home; the
# VOLUME below is where operators mount persistent storage. XHash mining
# DAGs default to /home/parallax/.xhash — mount that too when mining.
USER parallax
VOLUME ["/home/parallax/.parallax"]

EXPOSE 8545 8546 32110 32110/udp
# Default to the multi-call wrapper so `docker run <image> node ...`
# and `docker run <image> rpc ...` both work out of the box.
ENTRYPOINT ["parallax"]

# Add some metadata labels to help programatic image consumption
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM" \
      org.opencontainers.image.title="Parallax" \
      org.opencontainers.image.description="Parallax full-node client suite (parallaxd, parallax-cli, parallax-wallet)" \
      org.opencontainers.image.source="https://github.com/ParallaxProtocol/parallax" \
      org.opencontainers.image.documentation="https://docs.parallaxprotocol.org" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.revision="$COMMIT" \
      org.opencontainers.image.version="$VERSION"
