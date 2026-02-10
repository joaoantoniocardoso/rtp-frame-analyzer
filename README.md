# RTP Frame Analyzer

Measures H.264 frame delivery timing at the **raw network packet level** (UDP/RTP) to determine whether video stream stalls originate from the camera/encoder or the receiver's processing pipeline.

This tool captures RTP packets with `tcpdump`, reconstructs H.264 frame boundaries, computes per-frame delivery statistics, and generates a self-contained HTML report with embedded plots and a video player.

## Why This Tool Exists

When an RTSP camera stream stutters or freezes, it can be difficult to determine whether the problem is:

- **The camera** (encoder too slow, network interface bottleneck)
- **The network** (packet loss, jitter, congestion)
- **The receiver** (CPU overload, GStreamer/FFmpeg pipeline stalls)

By measuring at the raw UDP packet level — before any video processing pipeline — this tool isolates the camera and network behavior from receiver-side effects.

---

## Quick Start (Linux)

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

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install tcpdump tshark gstreamer1.0-tools gstreamer1.0-plugins-good \
  gstreamer1.0-plugins-bad gstreamer1.0-plugins-base gstreamer1.0-rtsp \
  python3-numpy python3-matplotlib iproute2 curl

# Ensure tcpdump has capture permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)

# Run
RTSP_URL=rtsp://192.168.2.10:554/stream_0 ./entrypoint.sh
```

---

## Running on Windows

Docker Desktop for Windows does **not** support `--network=host`. Instead, the container uses bridge networking, which means the camera must be reachable from the Docker VM's network. In practice this works when the camera is on a routable subnet.

### Prerequisites

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) and ensure it is running.
2. Open **PowerShell** (or Windows Terminal).
3. The camera must be reachable from your PC (verify with `ping 192.168.2.10`).

### Steps

```powershell
# Clone the repository
git clone <repo-url>
cd rtp-frame-analyzer

# Build the image
docker build -t rtp-frame-analyzer .

# Run (adjust RTSP_URL to your camera)
docker run --rm `
  --network=host `
  --cap-add=NET_RAW `
  --cap-add=NET_ADMIN `
  -e RTSP_URL=rtsp://192.168.2.10:554/stream_0 `
  -e CAPTURE_DURATION=60 `
  -v "${PWD}/output:/data" `
  rtp-frame-analyzer

# Report will be at .\output\run_<timestamp>\report.html
```

> **Note on `--network=host` on Windows:** Docker Desktop runs Linux containers inside a WSL2 VM. The `--network=host` flag shares the *VM's* network stack, not the Windows host directly. In most configurations with WSL2 mirrored networking (the default since Docker Desktop 4.29+), this works transparently — the camera IP is reachable from the VM. If the camera is unreachable from inside the container, try:
>
> 1. Ensure your `.wslconfig` has `networkingMode=mirrored` (or `nat` with proper routing).
> 2. Alternatively, specify the network interface explicitly: `-e NETWORK_INTERFACE=eth0`.
> 3. As a last resort, run natively inside WSL2 (see below).

### Running natively inside WSL2

If Docker networking is problematic, you can run directly inside your WSL2 Ubuntu distribution:

```bash
# Inside WSL2 terminal
sudo apt update && sudo apt install -y tcpdump tshark gstreamer1.0-tools \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-base \
  gstreamer1.0-rtsp python3-numpy python3-matplotlib iproute2 curl

sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)

cd /path/to/rtp-frame-analyzer
RTSP_URL=rtsp://192.168.2.10:554/stream_0 ./entrypoint.sh
```

---

## Running on macOS

Docker Desktop for macOS also does **not** support `--network=host` (it is silently ignored). The Docker VM uses its own virtual network, but traffic to LAN IPs is typically routed through.

### Prerequisites

1. Install [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/).
2. The camera must be reachable from your Mac (verify with `ping 192.168.2.10`).

### Steps

```bash
# Clone the repository
git clone <repo-url> && cd rtp-frame-analyzer

# Build the image (works on both Intel and Apple Silicon — Docker uses Rosetta/QEMU)
docker build -t rtp-frame-analyzer .

# Run
docker run --rm \
  --network=host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -e RTSP_URL=rtsp://192.168.2.10:554/stream_0 \
  -e CAPTURE_DURATION=60 \
  -v "$(pwd)/output:/data" \
  rtp-frame-analyzer

# Report will be at ./output/run_<timestamp>/report.html
```

> **Note on `--network=host` on macOS:** Since Docker Desktop runs a Linux VM, `--network=host` gives the container the VM's network, not the Mac's. In practice, the VM bridges to the Mac's network, so LAN cameras are usually reachable. If the camera is unreachable from inside the container:
>
> 1. Verify the camera responds: `docker run --rm rtp-frame-analyzer ping -c 1 192.168.2.10`
> 2. If not, the camera may be on a subnet that the Docker VM cannot route to (e.g., a USB Ethernet adapter). In that case, run natively (see below).

### Running natively on macOS (using Homebrew)

```bash
# Install dependencies
brew install gstreamer tcpdump wireshark  # wireshark provides tshark
pip3 install numpy matplotlib

# tcpdump on macOS typically has permissions already; if not:
# sudo chmod u+s $(which tcpdump)

# Run
RTSP_URL=rtsp://192.168.2.10:554/stream_0 ./entrypoint.sh
```

> **macOS caveats:**
> - `/proc` does not exist on macOS, so system monitoring (CPU, memory snapshots) will be skipped. The report will still include all RTP analysis and plots.
> - `ip route` is not available; set `NETWORK_INTERFACE` explicitly: `NETWORK_INTERFACE=en0 RTSP_URL=... ./entrypoint.sh`
> - Network interface names differ from Linux (e.g., `en0` instead of `eth0`).

---

## Running on Raspberry Pi

The tool works on Raspberry Pi, both via Docker and natively. Native execution is recommended on Pi for best performance.

### Supported models

| Model | Architecture | Docker base image | Native |
|---|---|---|---|
| Raspberry Pi 3 | armv7l (armhf) | `arm32v7/ubuntu:24.04` | Yes |
| Raspberry Pi 4 | armv7l (armhf) or aarch64 | `arm32v7/ubuntu:24.04` or `arm64v8/ubuntu:24.04` | Yes |
| Raspberry Pi 5 | aarch64 | `arm64v8/ubuntu:24.04` | Yes |

> **Note:** Pi 4 can run 32-bit (armhf) or 64-bit (arm64) OS. Check with `uname -m`: `armv7l` = 32-bit, `aarch64` = 64-bit.

### Native installation (recommended for Pi)

Native avoids Docker overhead, which matters on the limited Pi hardware.

```bash
# Install dependencies (Raspberry Pi OS / Debian-based)
sudo apt update && sudo apt install -y \
  tcpdump tshark \
  gstreamer1.0-tools gstreamer1.0-plugins-base \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-rtsp \
  python3-numpy python3-matplotlib \
  iproute2 curl

# Grant tcpdump raw packet capture permissions (avoids needing sudo)
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)

# Clone and run
git clone <repo-url> && cd rtp-frame-analyzer
RTSP_URL=rtsp://192.168.2.10:554/stream_0 CAPTURE_DURATION=60 ./entrypoint.sh

# Report at ./output/run_<timestamp>/report.html
```

### Docker on Raspberry Pi

Docker works on Pi 3/4/5 if you have Docker Engine installed. The default `Dockerfile` (based on `ubuntu:24.04`) automatically pulls the correct architecture.

```bash
# Install Docker on Pi (if not already installed)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect

# Clone and build
git clone <repo-url> && cd rtp-frame-analyzer
docker build -t rtp-frame-analyzer .

# Run
docker run --rm \
  --network=host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -e RTSP_URL=rtsp://192.168.2.10:554/stream_0 \
  -e CAPTURE_DURATION=60 \
  -v $(pwd)/output:/data \
  rtp-frame-analyzer
```

> **Pi performance notes:**
> - The capture itself (tcpdump + GStreamer RTSP client) is lightweight and works fine on all Pi models.
> - The Python analysis and plot generation can take 30-60 seconds on Pi 3, ~15 seconds on Pi 4, and ~10 seconds on Pi 5. This is a one-time cost after capture completes.
> - For 4K streams at high bitrates (>15 Mbps), ensure your Ethernet link is not saturated. Pi 3's Ethernet shares the USB 2.0 bus (~300 Mbps effective). Pi 4 and 5 have dedicated gigabit Ethernet.

### Cross-building from a PC for Raspberry Pi

If you want to build the Docker image on your (faster) PC and transfer it to a Pi:

```bash
# On your PC: build for ARM (requires Docker Buildx)
# For Pi 3 / Pi 4 (32-bit OS):
docker buildx build --platform linux/arm/v7 -t rtp-frame-analyzer:armv7 --load .

# For Pi 4 (64-bit OS) / Pi 5:
docker buildx build --platform linux/arm64 -t rtp-frame-analyzer:arm64 --load .

# Save and transfer to Pi
docker save rtp-frame-analyzer:arm64 | gzip > rtp-frame-analyzer-arm64.tar.gz
scp rtp-frame-analyzer-arm64.tar.gz pi@<pi-ip>:~/

# On the Pi: load and run
docker load < rtp-frame-analyzer-arm64.tar.gz
docker run --rm --network=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e RTSP_URL=rtsp://192.168.2.10:554/stream_0 \
  -v $(pwd)/output:/data \
  rtp-frame-analyzer:arm64
```

---

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

---

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

---

## Output

Each run creates a timestamped directory under `OUTPUT_DIR`:

```
output/
└── run_20260210_134500/
    ├── report.html          # Self-contained HTML report (open in any browser)
    ├── video.mp4            # Captured video (H.264 passthrough, no re-encoding)
    ├── capture.pcap         # Raw packet capture (can be opened in Wireshark)
    ├── rtp_packets.csv      # Extracted RTP packet fields
    ├── metadata.json        # Run configuration metadata
    ├── camera_info.json     # Camera settings (RadCam only, or {"detected": false})
    ├── stats.json           # Computed statistics (machine-readable)
    ├── frame_log.jsonl      # Per-frame timing data (NDJSON)
    ├── gst_client.log       # GStreamer RTSP client log
    ├── sysmon/              # System monitoring snapshots during capture
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

1. **Captured video** with an HTML5 player (no re-encoding — raw H.264 in MP4 container)
2. **System context** (host hardware, CPU/memory usage, network bandwidth)
3. **Camera settings** (RadCam only: firmware, encoder config, image settings — auto-detected)
4. **Frame delivery statistics** with per-frame-type metrics (median, P95, P99, max intervals; sizes; delivery durations; packet counts)
5. **Linear regression** of frame size vs delivery duration
6. **Methodology** section explaining the measurement approach
7. **7 analysis plots** with detailed captions
8. **Observations** — neutral, data-driven findings

### Camera Metadata (RadCam)

When the target camera is a RadCam (HiSilicon-based), the tool automatically queries its proprietary HTTP API to collect:

- **System config**: firmware version, device name, MAC address, platform version
- **Encoder settings** (both channels): resolution, framerate, GOP, bitrate, codec, profile, rate control mode
- **RTSP config**: transport settings
- **Image adjustment**: brightness, contrast, sharpness, saturation, exposure, AWB, gain
- **Extended image settings**: flip, mirror, WDR, noise reduction, lens correction, IR cut

This metadata is saved to `camera_info.json` and embedded in the report for cross-comparison across different camera configurations. If the camera is not a RadCam (or the API is unreachable), this section is silently skipped.

---

## How It Works

```
┌────────────────────────────────────────────────────────────────────┐
│                        RTP Frame Analyzer                         │
│                                                                   │
│  1. Start tcpdump    ──► Captures raw UDP packets from camera     │
│  2. Start RTSP client ──► Triggers camera to stream via RTP      │
│     (also saves H.264 to MP4 — no re-encoding)                   │
│  3. Wait duration     ──► Accumulates packet data                 │
│  4. Stop both         ──► Clean EOS shutdown finalizes MP4        │
│  5. tshark extract    ──► Parse RTP headers from pcap             │
│  6. Python analysis   ──► Reconstruct frames, compute timing      │
│  7. Generate report   ──► HTML with plots + embedded video player │
└────────────────────────────────────────────────────────────────────┘
```

### Frame Reconstruction

H.264 over RTP splits each video frame into multiple RTP packets (due to MTU limits). Frame boundaries are identified by:

- **RTP Timestamp**: All packets of the same frame share the same timestamp (90kHz clock)
- **RTP Marker Bit**: The last packet of a frame has `M=1`

### Frame Classification

Frames are classified as **I-frame** (keyframe) or **P-frame** (predicted) by size heuristic — I-frames are typically 5-20x larger than P-frames.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `tcpdump: permission denied` | Run with `--cap-add=NET_RAW --cap-add=NET_ADMIN`, or use `sudo setcap` for native |
| Camera unreachable from Docker | Check `--network=host` is set; on macOS/Windows, try native or WSL2 |
| `Too few RTP packets captured` | Verify RTSP URL works: `gst-launch-1.0 rtspsrc location=<URL> ! fakesink` |
| MP4 file empty or corrupt | Ensure clean shutdown (the `-e` EOS flag handles this); check `gst_client.log` |
| Slow plot generation on Pi | Normal — Python/matplotlib is CPU-intensive; ~30-60s on Pi 3, faster on Pi 4/5 |
| `auto` interface detection fails | Set `NETWORK_INTERFACE` explicitly (e.g., `eth0`, `en0`, `enp3s0`) |

## License

MIT
