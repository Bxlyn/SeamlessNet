FROM gcc:latest

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    make \
    pkg-config \
    libssl-dev \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Build picoquic
WORKDIR /usr/local

RUN git clone https://github.com/private-octopus/picoquic.git

WORKDIR /usr/local/picoquic

RUN cmake -DPICOQUIC_FETCH_PTLS=Y . \
    && make -j$(nproc)

# Copy SeamlessNet source code
WORKDIR /usr/local/SeamlessNet

COPY . .

# Create non-root user
RUN useradd -m -s /bin/bash jigabit \
    && chown -R jigabit:jigabit /usr/local/SeamlessNet \
    && chown -R jigabit:jigabit /usr/local/picoquic

USER jigabit

WORKDIR /usr/local/SeamlessNet

CMD ["bash"]