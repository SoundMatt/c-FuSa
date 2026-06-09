# c-FuSa — multi-stage Docker build
# Stage 1: builder
FROM ubuntu:22.04 AS builder

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        cmake \
        build-essential \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel "$(nproc)"

# Stage 2: minimal runtime image
FROM ubuntu:22.04

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/cfusa /usr/local/bin/cfusa

WORKDIR /workspace
ENTRYPOINT ["cfusa"]
CMD ["help"]
