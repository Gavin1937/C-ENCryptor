
FROM ubuntu:22.04

# setup enviroments & working dir
RUN apt update -y && apt upgrade -y && \
    apt install -y gcc g++ gdb cmake make libssl-dev nano vim
WORKDIR /src/C-ENCryptor

# copy source code
COPY . .

# build C-ENCryptor lib & demo
RUN \
    mkdir build && \
    cmake -S . -B build && cmake --build build && \
    mkdir demo/build && \
    cmake -S demo -B demo/build && cmake --build demo/build

ENTRYPOINT ["/bin/bash"]