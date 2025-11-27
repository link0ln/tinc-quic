FROM build-base

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

COPY . /build/

RUN autoreconf -fsi && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-openssl \
        --with-msquic \
        --disable-legacy-protocol \
        --enable-maintainer-mode && \
    make && \
    make install

# Install debugging and network stress testing utilities
RUN apt-get update && apt-get install -y \
    procps \
    lsof \
    tcpdump \
    strace \
    iperf3 \
    iptraf-ng \
    nload \
    nethogs \
    bmon \
    speedometer \
    mtr \
    hping3 \
    netperf \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /etc/tinc /var/run /var/log

# Copy entrypoint script
COPY docker/scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tincd", "-D", "-d5"]
