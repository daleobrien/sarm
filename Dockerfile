# syntax=docker/dockerfile:1

# ymawky — hand-rolled ARM64 web server, zero libc dependencies.
# This Dockerfile builds the Linux port (the default main branch is
# macOS-only and can't run inside a container) and packages it into
# a minimal FROM scratch image.
#
# Build:
#   docker build --platform linux/arm64 -t ymawky .
#
# Run (listens on 8080 inside the container):
#   docker run --rm -p 8080:8080 ymawky
#
# Custom port:
#   docker run --rm -p 9090:9090 ymawky 9090

# ── builder ────────────────────────────────────────────────────
ARG TARGETPLATFORM
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
        bash \
        ca-certificates \
        gcc \
        git \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Pull the Linux port (arm64 syscall numbers, openat2, etc.).
COPY docs docs
COPY src src
COPY err err
COPY www www
COPY Makefile Makefile
COPY Makefile.linux Makefile.linux
COPY build_err_pages.sh build_err_pages.sh
COPY embed_www.sh embed_www.sh

# Generate custom error pages (err/404.html, err/500.html, …).
RUN bash build_err_pages.sh

RUN make -f Makefile.linux

# ── scratch runtime ─────────────────────────────────────────────
FROM scratch

#
COPY --from=builder /build/ymawky /ymawky

EXPOSE 8080
ENTRYPOINT ["/ymawky"]
