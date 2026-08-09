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
FROM --platform=linux/arm64 debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
        bash \
        ca-certificates \
        cpp \
        git \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Pull the Linux port (arm64 syscall numbers, openat2, etc.).
RUN git clone --depth 1 --branch linux \
        https://github.com/imtomt/ymawky.git .

# ymawky hardcodes a bind to 127.0.0.1 which prevents Docker's
# -p port publishing from reaching the container.  Patch it to
# listen on every interface (0.0.0.0) — inside an isolated
# container this is the expected behaviour.
RUN sed -i \
    's|\.byte 0x7F, 0x00, 0x00, 0x01 // 127\.0\.0\.1|.byte 0x00, 0x00, 0x00, 0x00 // 0.0.0.0 (container)|' \
    src/ymawky.S

# Generate custom error pages (err/404.html, err/500.html, …).
RUN bash build_err_pages.sh

RUN make

# ── scratch runtime ─────────────────────────────────────────────
FROM scratch

COPY --from=builder /build/ymawky /ymawky
COPY --from=builder /build/www/   /www/
COPY --from=builder /build/err/   /err/

EXPOSE 8080
ENTRYPOINT ["/ymawky"]
