# RTP Frame Analyzer

Measures H.264 frame delivery timing at the **raw network packet level** (UDP/RTP) to determine whether video stream stalls originate from the camera/encoder or the receiver's processing pipeline.

This tool captures RTP packets with `tcpdump`, reconstructs H.264 frame boundaries, computes per-frame delivery statistics, and generates a self-contained HTML report with embedded plots.

## Why This Tool Exists

When an RTSP camera stream stutters or freezes, it can be difficult to determine whether the problem is:

- **The camera** (encoder too slow, network interface bottleneck)
- **The network** (packet loss, jitter, congestion)
- **The receiver** (CPU overload, GStreamer/FFmpeg pipeline stalls)

By measuring at the raw UDP packet level — before any video processing pipeline — this tool isolates the camera and network behavior from receiver-side effects.

## Quick Start

### Using Docker Compose (recommended)

```bash
# Clone the repository
git clone <repo-url> && cd rtp-frame-analyzer

# Run with your camera's RTSP URL
RTSP_URL=rtsp://192.168.2.10:554/stream_0 docker compose up --build

# Report will be at ./output/run_<timestamp>/report.html
```

### Using Docker directly

```bash
# Build
docker build -t rtp-frame-analyzer .

# Run (60-second capture)
docker run --rm \
  --network=host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -e RTSP_URL=rtsp://192.168.2.10:554/stream_0 \
  -e CAPTURE_DURATION=60 \
  -v $(pwd)/output:/data \
  rtp-frame-analyzer

# Report will be at ./output/run_<timestamp>/report.html
```

### Running natively (no Docker)

If you have the dependencies installed:

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install tcpdump tshark gstreamer1.0-tools gstreamer1.0-plugins-good \
  gstreamer1.0-plugins-bad python3-numpy python3-matplotlib

# Ensure tcpdump has capture permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)

# Run
RTSP_URL=rtsp://192.168.2.10:554/stream_0 ./entrypoint.sh
```

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `RTSP_URL` | **Yes** | — | RTSP stream URL of the camera to analyze |
| `CAPTURE_DURATION` | No | `60` | How many seconds to capture (longer = more data) |
| `OUTPUT_DIR` | No | `/data` (Docker) or `./output` | Where to write capture data and the report |
| `NETWORK_INTERFACE` | No | `auto` | Network interface to capture on. Auto-detected from route to camera IP |

### Examples

```bash
# 2-minute capture
RTSP_URL=rtsp://10.0.0.100:554/live CAPTURE_DURATION=120 docker compose up --build

# Specify output directory
RTSP_URL=rtsp://10.0.0.100:554/live OUTPUT_DIR=/tmp/analysis docker compose up --build

# Specify network interface explicitly
RTSP_URL=rtsp://10.0.0.100:554/live NETWORK_INTERFACE=eth0 docker compose up --build
```

## Docker Permissions

The container requires two Linux capabilities for raw packet capture:

- **`NET_RAW`**: Required by `tcpdump` to capture packets
- **`NET_ADMIN`**: Required to set promiscuous mode on the interface

Additionally, **`--network=host`** is required so the container shares the host's network stack and can:
1. Reach the camera on the local network
2. Capture packets on the host's physical interface
3. Receive the RTP stream triggered by the RTSP client

These are set automatically in `docker-compose.yml`. If running `docker run` manually, include all three flags:

```bash
docker run --network=host --cap-add=NET_RAW --cap-add=NET_ADMIN ...
```

## Output

Each run creates a timestamped directory under `OUTPUT_DIR`:

```
output/
└── run_20260210_134500/
    ├── report.html          # Self-contained HTML report (open in any browser)
    ├── capture.pcap         # Raw packet capture (can be opened in Wireshark)
    ├── rtp_packets.csv      # Extracted RTP packet fields
    ├── metadata.json        # Run configuration metadata
    ├── stats.json           # Computed statistics (machine-readable)
    ├── frame_log.jsonl      # Per-frame timing data (NDJSON)
    ├── gst_client.log       # GStreamer RTSP client log
    ├── 01_timeseries.png    # Inter-frame interval over time
    ├── 02_distributions.png # I-frame and P-frame interval distributions
    ├── 03_scatter.png       # Frame size vs delivery interval
    ├── 04_delivery_duration.png # Per-frame RTP delivery time
    ├── 05_cumulative_excess.png # Cumulative excess latency
    ├── 06_jitter.png        # Delivery jitter (wall clock vs RTP expected)
    └── 07_size_vs_delivery.png  # Frame size vs delivery duration + regression
```

### Report Contents

The HTML report includes:

1. **Run metadata** (RTSP URL, duration, interface, host)
2. **Key finding summary** with I-frame latency ratio
3. **Statistics table** with per-frame-type metrics (median, P95, P99, max intervals; sizes; delivery durations; packet counts)
4. **Linear regression** of frame size vs delivery duration
5. **7 analysis plots** with detailed captions
6. **Methodology** section explaining the measurement approach
7. **Interpretation** with root cause analysis and mitigations

## How It Works

```
┌────────────────────────────────────────────────────────────────────┐
│                        RTP Frame Analyzer                         │
│                                                                   │
│  1. Start tcpdump    ──► Captures raw UDP packets from camera     │
│  2. Start RTSP client ──► Triggers camera to stream via RTP      │
│  3. Wait duration     ──► Accumulates packet data                 │
│  4. Stop both         ──► Clean shutdown                          │
│  5. tshark extract    ──► Parse RTP headers from pcap             │
│  6. Python analysis   ──► Reconstruct frames, compute timing      │
│  7. Generate report   ──► Self-contained HTML with embedded plots │
└────────────────────────────────────────────────────────────────────┘
```

### Frame Reconstruction

H.264 over RTP splits each video frame into multiple RTP packets (due to MTU limits). Frame boundaries are identified by:

- **RTP Timestamp**: All packets of the same frame share the same timestamp (90kHz clock)
- **RTP Marker Bit**: The last packet of a frame has `M=1`

### Frame Classification

Frames are classified as **I-frame** (keyframe) or **P-frame** (predicted) by size heuristic — I-frames are typically 5-20x larger than P-frames.

## License

MIT
