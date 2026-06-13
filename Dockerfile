# syntax=docker/dockerfile:1
#
# Multi-stage build for c-FuSa.
# Stage 1 compiles the cfusa binary with CMake + Ninja.
# Stage 2 produces a minimal Alpine runtime image.
#
# Build:
#   docker build -t c-fusa .
#
# Run (mount your C project at /project):
#   docker run --rm -v "$(pwd)":/project c-fusa check --dir /project/src
#   docker run --rm -v "$(pwd)":/project c-fusa lint
#   docker run --rm -v "$(pwd)":/project c-fusa trace
#   docker run --rm -v "$(pwd)":/project c-fusa release

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
    cmake ninja build-base git

WORKDIR /build

# Copy source tree
COPY . .

RUN cmake -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
      -G Ninja \
    && cmake --build build --parallel \
    && strip build/cfusa

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

# git for impact/provenance; zip for audit-pack; ca-certificates for TLS.
RUN apk add --no-cache git zip ca-certificates

COPY --from=builder /build/build/cfusa /usr/local/bin/cfusa

LABEL org.opencontainers.image.title="c-FuSa" \
      org.opencontainers.image.description="C functional safety toolkit (ISO 26262, IEC 61508, DO-178C, MISRA-C)" \
      org.opencontainers.image.source="https://github.com/SoundMatt/c-FuSa" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="SoundMatt" \
      org.opencontainers.image.version="0.5.14" \
      io.x-fusa.tool="c-FuSa" \
      io.x-fusa.language="c" \
      io.x-fusa.binary="cfusa" \
      io.x-fusa.spec-version="1.9"

# Default working directory is /project; mount your C project here.
WORKDIR /project

ENTRYPOINT ["cfusa"]
CMD ["help"]
