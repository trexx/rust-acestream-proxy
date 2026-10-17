FROM rust:1.99-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS build

# musl-dev supplies the linker; nothing here needs OpenSSL, since the engine is
# plain HTTP and the service terminates no TLS of its own.
RUN apk add --no-cache musl-dev

WORKDIR /src
# One layer for manifests and source: with two small dependencies, a separate
# dependency-only build layer would save seconds and cost a stub main.rs.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Alpine's host target is x86_64-unknown-linux-musl, where Rust links musl
# statically by default — the equivalent of the old CGO_ENABLED=0 build.
RUN cargo build --release --locked

FROM docker.io/mwader/static-ffmpeg:9.0.2-amd64@sha256:73e53e0efe712c0dda05ec65c18e7185f2638c33293d62dd9d541b081c0b523d
LABEL org.opencontainers.image.source="https://github.com/trexx/rust-acestream-proxy"

# The base image ships /ffmpeg and /ffprobe at the filesystem root; the service
# exec's them by name, so "/" must be on PATH.
ENV PATH="/usr/local/bin:/"

COPY --from=build /src/target/release/rust-acestream-proxy /usr/local/bin/rust-acestream-proxy

USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/rust-acestream-proxy"]
