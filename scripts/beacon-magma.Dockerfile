FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i \
    -e 's|http://archive.ubuntu.com/ubuntu|http://mirrors.ustc.edu.cn/ubuntu|g' \
    -e 's|http://security.ubuntu.com/ubuntu|http://mirrors.ustc.edu.cn/ubuntu|g' \
    /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl wget gawk time \
    build-essential make autoconf automake autogen libtool pkg-config \
    cmake ninja-build clang-15 lld-15 llvm-15-dev libz3-dev \
    zlib1g-dev liblzma-dev libjpeg-dev nasm \
    libasound2-dev libflac-dev libogg-dev libvorbis-dev libopus-dev \
    libmp3lame-dev libmpg123-dev python3 python-is-python3 \
    libreadline-dev bison re2c libicu-dev \
    libopenjp2-7-dev libpng-dev libcairo2-dev libtiff-dev liblcms2-dev \
    libjbig-dev liblerc-dev libdeflate-dev libzstd-dev libwebp-dev \
    libbrotli-dev libbz2-dev \
    libboost-dev tcl \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-rt-15-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data/zym/TractFuzz
