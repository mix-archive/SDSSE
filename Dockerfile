FROM ubuntu:latest AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential cmake zip git curl pkg-config flex bison autoconf automake libtool m4 ca-certificates ninja-build && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN --mount=type=cache,target=/root/.cache/vcpkg \
    ./extern/vcpkg/bootstrap-vcpkg.sh -disableMetrics && \
    cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(nproc) && \
    mkdir -p /artifacts && \
    cmake --install build --prefix /artifacts

FROM scratch AS output
COPY --from=builder /artifacts /
COPY --from=builder /src/Data /data

FROM ubuntu:latest AS runtime
COPY --from=output /bin /app/bin
COPY --from=output /data /app/data
WORKDIR /app
