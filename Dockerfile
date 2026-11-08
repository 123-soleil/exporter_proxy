# exporter_proxy container image. See "Docker" in README.md.
#
#   docker build -t exporter_proxy --build-arg VERSION=0.4.0 .
#
# The builder runs on the build machine's platform and cross-compiles for
# the target (docker buildx --platform linux/amd64,linux/arm64,linux/arm/v7):
# the final stage only copies files, so no emulation is needed.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Version information (prometheus/common/version), passed by the build:
# the build context has no .git.
ARG VERSION=dev
ARG REVISION=""
ARG BRANCH=""
ARG BUILD_DATE=""
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
# make build: static binary (CGO_ENABLED=0), -trimpath, like the releases.
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    make build VERSION="$VERSION" REVISION="$REVISION" BRANCH="$BRANCH" BUILD_DATE="$BUILD_DATE"

# Static base without shell or package manager; "nonroot" runs as
# uid/gid 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

ARG VERSION=dev
LABEL org.opencontainers.image.title="exporter_proxy" \
      org.opencontainers.image.description="TLS, mTLS and basic authentication proxy for Prometheus exporters" \
      org.opencontainers.image.source="https://github.com/123-soleil/exporter_proxy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$VERSION"

COPY --from=build /src/bin/exporter_proxy /usr/bin/exporter_proxy

USER 65532:65532
# Listener addresses come from the configuration; 9100 and 9999 are the
# ones of the examples (a listener and the metrics endpoint).
EXPOSE 9100 9999
# Default configuration: /etc/exporter_proxy/config.yml (mount it).
ENTRYPOINT ["/usr/bin/exporter_proxy"]
