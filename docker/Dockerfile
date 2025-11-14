# Stage 1: Build quiche library
FROM ubuntu:22.04 AS quiche-builder

ENV DEBIAN_FRONTEND=noninteractive

# Install minimal dependencies for quiche
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libssl-dev \
    pkg-config \
    cmake \
    libclang-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy ONLY quiche dependencies and source
COPY deps/quiche /build/deps/quiche

# Build quiche (this layer is cached unless quiche changes)
RUN cd deps/quiche && \
    cargo build --release --features ffi,pkg-config-meta

# Stage 2: Build tinc
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install all runtime and build dependencies
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
    net-tools \
    iproute2 \
    iputils-ping \
    vim \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy pre-built quiche from stage 1
COPY --from=quiche-builder /build/deps/quiche/target/release/libquiche.so /usr/lib/
COPY --from=quiche-builder /build/deps/quiche/quiche/include/quiche.h /usr/include/
RUN ldconfig

# Copy quiche for pkg-config (needed for tinc configure)
COPY --from=quiche-builder /build/deps/quiche /build/deps/quiche

# Copy all source files (autoreconf needs all subdirectories)
COPY . /build/

# Build tinc (autoreconf, configure, make)
# Note: This layer rebuilds when source changes, but quiche is already cached from stage 1
RUN autoreconf -fsi && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-openssl \
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
