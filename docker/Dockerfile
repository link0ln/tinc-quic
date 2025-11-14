# Multi-stage Dockerfile for tinc with MsQuic support
# Stage 1: Build MsQuic library
FROM ubuntu:22.04 AS msquic-builder

ENV DEBIAN_FRONTEND=noninteractive

# Install MsQuic build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    liblttng-ust-dev \
    lttng-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy MsQuic submodule
COPY msquic /build/msquic

# Build MsQuic
# Note: Building only Release configuration for smaller size
RUN cd msquic && \
    mkdir -p build/linux/x64_Release && \
    cd build/linux/x64_Release && \
    cmake -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DQUIC_TLS=openssl \
        -DQUIC_BUILD_TOOLS=OFF \
        -DQUIC_BUILD_TEST=OFF \
        -DQUIC_BUILD_PERF=OFF \
        ../../.. && \
    cmake --build . --config Release

# Stage 2: Build tinc
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime and build dependencies for tinc
RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    zlib1g-dev \
    liblzo2-dev \
    libncurses5-dev \
    libreadline-dev \
    liblttng-ust1 \
    net-tools \
    iproute2 \
    iputils-ping \
    vim \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy pre-built MsQuic from stage 1
COPY --from=msquic-builder /build/msquic/build/linux/x64_Release/bin/Release/libmsquic.so.* /usr/lib/
COPY --from=msquic-builder /build/msquic/src/inc/msquic.h /usr/include/
COPY --from=msquic-builder /build/msquic/src/inc/msquic_posix.h /usr/include/
RUN ldconfig

# Copy MsQuic directory for build reference (needed for configure)
COPY --from=msquic-builder /build/msquic /build/msquic

# Copy all source files (autoreconf needs all subdirectories)
COPY . /build/

# Build tinc with MsQuic support
# Note: This layer rebuilds when source changes, but MsQuic is already cached from stage 1
RUN autoreconf -fsi && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-openssl \
        --with-msquic \
        --enable-maintainer-mode && \
    make && \
    make install

# Create necessary directories
RUN mkdir -p /etc/tinc /var/run /var/log

# Copy entrypoint script
COPY docker/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tincd", "-D", "-d5"]
