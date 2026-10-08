FROM gcc:latest

USER root

# Install dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    cmake \
    make \
    pkg-config \
    libssl-dev \
    openssl \
    iproute2 \
    iputils-ping \
    iptables \
    iperf3 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Build Picoquic
# -----------------------------

WORKDIR /usr/local

RUN git clone https://github.com/private-octopus/picoquic.git

WORKDIR /usr/local/picoquic

RUN cmake -DPICOQUIC_FETCH_PTLS=Y . \
    && make -j$(nproc)

# -----------------------------
# SeamlessNet
# -----------------------------

WORKDIR /usr/local/SeamlessNet

COPY . .

CMD ["bash"]