FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    tshark \
    gstreamer1.0-tools \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-rtsp \
    python3 \
    python3-pip \
    python3-numpy \
    python3-matplotlib \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY entrypoint.sh analyze.py report.py ./
RUN chmod +x entrypoint.sh

# Default configuration via environment variables
ENV RTSP_URL=""
ENV CAPTURE_DURATION="60"
ENV OUTPUT_DIR="/data"
ENV NETWORK_INTERFACE=""

ENTRYPOINT ["/app/entrypoint.sh"]
