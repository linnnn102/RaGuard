FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ffuf \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /SecLists
RUN git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/danielmiessler/SecLists.git /SecLists && \
    cd /SecLists && \
    git sparse-checkout set Fuzzing Discovery

RUN mkdir -p /fuzz /results

WORKDIR /fuzz

CMD ["bash"]
