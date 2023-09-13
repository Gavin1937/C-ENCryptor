FROM ubuntu:22.04

# setup enviroments
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Los_Angeles
RUN apt update -y && apt upgrade -y && \
    apt install -y tzdata gcc g++ gdb cmake make libssl-dev nano vim less git

# setup working dir & copy source code
WORKDIR /src/C-ENCryptor
COPY . .

# build C-ENCryptor lib & demo
RUN \
    mkdir build && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build && \
    mkdir demo/build && \
    cmake -S demo -B demo/build -DCMAKE_BUILD_TYPE=Debug && cmake --build demo/build

ENTRYPOINT ["/bin/bash"]