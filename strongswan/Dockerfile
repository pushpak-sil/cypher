FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    iproute2 \
    iputils-ping \
    tcpdump \
    curl \
    iperf3 \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]