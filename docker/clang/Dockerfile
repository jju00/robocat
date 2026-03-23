FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    bear \
    cmake \
    ninja-build \
    make \
    gcc \
    g++ \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    pkg-config \
    php-cli \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["bash"]