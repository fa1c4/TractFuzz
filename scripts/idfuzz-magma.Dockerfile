FROM tractfuzz-beacon-magma:ubuntu24.04
RUN apt-get update && apt-get install -y --no-install-recommends python3-numpy \
    && rm -rf /var/lib/apt/lists/*
