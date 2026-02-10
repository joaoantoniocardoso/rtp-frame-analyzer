#!/usr/bin/env bash
#
# RTP Frame Analyzer - Entrypoint
#
# Orchestrates: RTSP session setup -> raw packet capture -> analysis -> HTML report
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (all overridable via environment variables)
# ---------------------------------------------------------------------------
: "${RTSP_URL:?Error: RTSP_URL is required. Example: RTSP_URL=rtsp://192.168.2.10:554/stream_0}"
: "${CAPTURE_DURATION:=60}"
: "${OUTPUT_DIR:=/data}"
: "${NETWORK_INTERFACE:=auto}"
: "${CAMERA_TELNET_USER:=root}"
: "${CAMERA_TELNET_PASSWORD:=}"
: "${CAMERA_MONITOR_INTERVAL:=2}"
: "${CAMERA_BASELINE_DURATION:=5}"

echo "========================================"
echo " RTP Frame Analyzer"
echo "========================================"
echo " RTSP URL:       ${RTSP_URL}"
echo " Capture:        ${CAPTURE_DURATION}s"
echo " Output:         ${OUTPUT_DIR}"
echo " Interface:      ${NETWORK_INTERFACE}"
if [ -n "${CAMERA_TELNET_PASSWORD}" ]; then
    echo " Camera monitor: enabled (telnet, ${CAMERA_BASELINE_DURATION}s baseline)"
else
    echo " Camera monitor: disabled (set CAMERA_TELNET_PASSWORD to enable)"
fi
echo "========================================"

# ---------------------------------------------------------------------------
# Resolve camera IP and network interface
# ---------------------------------------------------------------------------
# Extract host from RTSP URL: rtsp://user:pass@host:port/path or rtsp://host:port/path
CAMERA_IP=$(echo "${RTSP_URL}" | sed -E 's|^rtsp://([^@]*@)?([^:/]+).*|\2|')
echo "[1/6] Camera IP resolved: ${CAMERA_IP}"

if [ "${NETWORK_INTERFACE}" = "auto" ]; then
    NETWORK_INTERFACE=$(ip route get "${CAMERA_IP}" 2>/dev/null | grep -oP 'dev \K\S+' || true)
    if [ -z "${NETWORK_INTERFACE}" ]; then
        echo "ERROR: Could not auto-detect network interface for ${CAMERA_IP}."
        echo "       Set NETWORK_INTERFACE explicitly."
        exit 1
    fi
    echo "       Auto-detected interface: ${NETWORK_INTERFACE}"
fi

# Verify connectivity
if ! ping -c 1 -W 3 "${CAMERA_IP}" > /dev/null 2>&1; then
    echo "WARNING: Cannot ping ${CAMERA_IP}. Proceeding anyway (ICMP may be blocked)."
fi

# ---------------------------------------------------------------------------
# Prepare output directory
# ---------------------------------------------------------------------------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="${OUTPUT_DIR}/run_${TIMESTAMP}"
mkdir -p "${RUN_DIR}"
echo "[2/6] Output directory: ${RUN_DIR}"

PCAP_FILE="${RUN_DIR}/capture.pcap"
CSV_FILE="${RUN_DIR}/rtp_packets.csv"

# ---------------------------------------------------------------------------
# Collect system + camera metadata (Python handles JSON safely)
# ---------------------------------------------------------------------------
echo "[2.5/6] Collecting system and camera metadata..."
python3 /app/collect_metadata.py \
    "${CAMERA_IP}" "${CAPTURE_DURATION}" "${NETWORK_INTERFACE}" "${TIMESTAMP}" "${RUN_DIR}"

# ---------------------------------------------------------------------------
# Start camera SoC monitoring (if telnet password is provided)
# ---------------------------------------------------------------------------
CAM_MONITOR_PID=""
CAM_MONITOR_FILE="${RUN_DIR}/camera_soc_monitor.ndjson"

if [ -n "${CAMERA_TELNET_PASSWORD}" ]; then
    # Total monitor duration = baseline + capture + buffer
    CAM_MONITOR_DURATION=$(( CAMERA_BASELINE_DURATION + CAPTURE_DURATION + 10 ))
    echo "[2.7/6] Starting camera SoC monitor (${CAMERA_BASELINE_DURATION}s baseline + ${CAPTURE_DURATION}s capture)..."
    python3 /app/camera_monitor.py "${CAMERA_IP}" \
        --user "${CAMERA_TELNET_USER}" \
        --password "${CAMERA_TELNET_PASSWORD}" \
        --output "${CAM_MONITOR_FILE}" \
        --interval "${CAMERA_MONITOR_INTERVAL}" \
        --duration "${CAM_MONITOR_DURATION}" &
    CAM_MONITOR_PID=$!
    sleep 1
    if kill -0 "${CAM_MONITOR_PID}" 2>/dev/null; then
        echo "       Camera monitor running (PID ${CAM_MONITOR_PID})"
        echo "       Collecting ${CAMERA_BASELINE_DURATION}s baseline before starting RTSP..."
        sleep "${CAMERA_BASELINE_DURATION}"
    else
        echo "       WARNING: Camera monitor failed to start. Continuing without it."
        CAM_MONITOR_PID=""
    fi
else
    echo "[2.7/6] Camera SoC monitoring skipped (set CAMERA_TELNET_PASSWORD to enable)"
fi

# ---------------------------------------------------------------------------
# Start packet capture
# ---------------------------------------------------------------------------
echo "[3/6] Starting packet capture on ${NETWORK_INTERFACE}..."

tcpdump -i "${NETWORK_INTERFACE}" \
    -w "${PCAP_FILE}" \
    "udp and host ${CAMERA_IP}" \
    -s 100 \
    &
TCPDUMP_PID=$!
sleep 1

if ! kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    echo "ERROR: tcpdump failed to start. Check permissions (--cap-add=NET_RAW --cap-add=NET_ADMIN)."
    exit 1
fi
echo "       tcpdump running (PID ${TCPDUMP_PID})"

# ---------------------------------------------------------------------------
# Start RTSP client to trigger the stream + record video
# ---------------------------------------------------------------------------
echo "[4/6] Connecting RTSP client to ${RTSP_URL}..."

VIDEO_FILE="${RUN_DIR}/video.mp4"

# Pipeline explanation:
#   rtph264depay: extracts H.264 NAL units from RTP packets
#   queue:        decouples rtspsrc timing from the rest of the pipeline
#   h264parse config-interval=-1: injects SPS/PPS before every I-frame
#   video/x-h264,stream-format=avc,alignment=au: ensures access-unit alignment for mp4mux
#   h264timestamper: assigns PTS to buffers that lack one — without this, mp4mux
#                    fatally errors with "Buffer has no PTS" on slower systems
#                    (e.g. Raspberry Pi) where initial RTSP buffers arrive before
#                    timestamps are established.
#   mp4mux:       muxes into browser-compatible MP4 container
#   -e (--eos-on-shutdown): on SIGINT, sends EOS for clean MP4 finalization.
gst-launch-1.0 -e \
    rtspsrc location="${RTSP_URL}" latency=0 protocols=udp \
    ! rtph264depay \
    ! queue \
    ! h264parse config-interval=-1 \
    ! "video/x-h264,stream-format=avc,alignment=au" \
    ! h264timestamper \
    ! mp4mux \
    ! filesink location="${VIDEO_FILE}" \
    > "${RUN_DIR}/gst_client.log" 2>&1 &
GST_PID=$!
sleep 3

if ! kill -0 "${GST_PID}" 2>/dev/null; then
    echo "ERROR: GStreamer RTSP client failed to connect. Check RTSP_URL."
    echo "       Log: ${RUN_DIR}/gst_client.log"
    kill "${TCPDUMP_PID}" 2>/dev/null || true
    cat "${RUN_DIR}/gst_client.log"
    exit 1
fi
echo "       RTSP client connected (PID ${GST_PID})"

# Watchdog: if the recording pipeline dies mid-capture, restart with fakesink
# to keep the RTSP session alive so tcpdump still collects data.
(
    while sleep 5; do
        if ! kill -0 "${GST_PID}" 2>/dev/null; then
            echo "       WARNING: Recording pipeline died. Restarting with fakesink..."
            gst-launch-1.0 \
                rtspsrc location="${RTSP_URL}" latency=0 protocols=udp \
                ! fakesink \
                > "${RUN_DIR}/gst_fallback.log" 2>&1 &
            FALLBACK_PID=$!
            echo "${FALLBACK_PID}" > "${RUN_DIR}/.fallback_pid"
            echo "       Fallback RTSP client running (PID ${FALLBACK_PID})"
            break
        fi
    done
) &
WATCHDOG_PID=$!

# ---------------------------------------------------------------------------
# Snapshot helper: reads /proc counters into a file
# ---------------------------------------------------------------------------
snapshot_system() {
    local OUT="$1"
    {
        echo "--- timestamp ---"
        date +%s.%N
        echo "--- /proc/stat ---"
        head -1 /proc/stat          # cpu aggregate line
        echo "--- /proc/meminfo ---"
        grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo
        echo "--- /proc/net/dev ${NETWORK_INTERFACE} ---"
        grep "${NETWORK_INTERFACE}" /proc/net/dev
        echo "--- loadavg ---"
        cat /proc/loadavg
        echo "--- thermal ---"
        # Try thermal_zone first (Raspberry Pi, ARM SBCs)
        for tz in /sys/class/thermal/thermal_zone*/temp; do
            [ -r "$tz" ] && echo "tz_$(basename "$(dirname "$tz")"):$(cat "$tz")"
        done
        # Fallback: hwmon sensors (desktops, servers)
        for hw in /sys/class/hwmon/hwmon*/temp*_input; do
            [ -r "$hw" ] && echo "hwmon_$(basename "$(dirname "$hw")")_$(basename "$hw" _input):$(cat "$hw")"
        done
    } > "${OUT}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Capture for the configured duration, with system monitoring
# ---------------------------------------------------------------------------
SYSMON_DIR="${RUN_DIR}/sysmon"
mkdir -p "${SYSMON_DIR}"

echo "       Capturing for ${CAPTURE_DURATION}s (with system monitoring)..."

# Snapshot at capture start
snapshot_system "${SYSMON_DIR}/start.txt"

# Background monitor: sample every 2 seconds
(
    i=0
    while true; do
        snapshot_system "${SYSMON_DIR}/sample_$(printf '%04d' $i).txt"
        i=$((i + 1))
        sleep 2
    done
) &
MONITOR_PID=$!

sleep "${CAPTURE_DURATION}"

# Stop monitor
kill "${MONITOR_PID}" 2>/dev/null || true
wait "${MONITOR_PID}" 2>/dev/null || true

# Snapshot at capture end
snapshot_system "${SYSMON_DIR}/end.txt"

echo "       Stopping capture..."

# Stop watchdog
kill "${WATCHDOG_PID}" 2>/dev/null || true
wait "${WATCHDOG_PID}" 2>/dev/null || true

# Stop fallback RTSP client if the watchdog spawned one
if [ -f "${RUN_DIR}/.fallback_pid" ]; then
    FALLBACK_PID=$(cat "${RUN_DIR}/.fallback_pid")
    kill "${FALLBACK_PID}" 2>/dev/null || true
    wait "${FALLBACK_PID}" 2>/dev/null || true
    rm -f "${RUN_DIR}/.fallback_pid"
fi

# Send SIGINT to GStreamer so -e flag triggers EOS -> MP4 is finalized cleanly
kill -INT "${GST_PID}" 2>/dev/null || true
echo "       Waiting for MP4 finalization..."
# Give GStreamer time to flush and finalize the MP4 container
wait "${GST_PID}" 2>/dev/null || true
kill "${TCPDUMP_PID}" 2>/dev/null || true
wait "${TCPDUMP_PID}" 2>/dev/null || true

# Stop camera SoC monitor
if [ -n "${CAM_MONITOR_PID}" ] && kill -0 "${CAM_MONITOR_PID}" 2>/dev/null; then
    kill "${CAM_MONITOR_PID}" 2>/dev/null || true
    wait "${CAM_MONITOR_PID}" 2>/dev/null || true
    echo "       Camera SoC monitor stopped."
fi

PCAP_SIZE=$(du -h "${PCAP_FILE}" | cut -f1)
echo "       Capture complete: ${PCAP_FILE} (${PCAP_SIZE})"

if [ -f "${VIDEO_FILE}" ]; then
    VIDEO_SIZE=$(du -h "${VIDEO_FILE}" | cut -f1)
    echo "       Video saved: ${VIDEO_FILE} (${VIDEO_SIZE})"
else
    echo "       WARNING: Video file was not created (MP4 muxing may have failed)"
fi

# ---------------------------------------------------------------------------
# Extract RTP fields with tshark
# ---------------------------------------------------------------------------
echo "[5/6] Extracting RTP packet data..."

# Discover the camera's source port (the most common UDP source port from camera IP)
SRC_PORT=$(tshark -r "${PCAP_FILE}" \
    -Y "ip.src==${CAMERA_IP}" \
    -T fields -e udp.srcport \
    -c 1000 2>/dev/null \
    | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')

if [ -z "${SRC_PORT}" ]; then
    echo "ERROR: Could not determine camera RTP source port from capture."
    exit 1
fi
echo "       Camera RTP source port: ${SRC_PORT}"

tshark -r "${PCAP_FILE}" \
    -d "udp.port==${SRC_PORT},rtp" \
    -Y "rtp && udp.srcport==${SRC_PORT}" \
    -T fields \
    -e frame.time_epoch \
    -e rtp.seq \
    -e rtp.timestamp \
    -e rtp.marker \
    -e rtp.p_type \
    -e udp.length \
    -E separator=, \
    > "${CSV_FILE}" 2>/dev/null

PACKET_COUNT=$(wc -l < "${CSV_FILE}")
echo "       Extracted ${PACKET_COUNT} RTP packets to ${CSV_FILE}"

if [ "${PACKET_COUNT}" -lt 100 ]; then
    echo "ERROR: Too few RTP packets captured. Check network connectivity and RTSP URL."
    exit 1
fi

# ---------------------------------------------------------------------------
# Analyze and generate report
# ---------------------------------------------------------------------------
echo "[6/6] Analyzing packets and generating report..."

CAM_MONITOR_ARG=""
if [ -f "${CAM_MONITOR_FILE}" ]; then
    CAM_MONITOR_ARG="--camera-monitor ${CAM_MONITOR_FILE}"
fi

python3 /app/analyze.py "${CSV_FILE}" \
    --output-dir "${RUN_DIR}" \
    --metadata "${RUN_DIR}/metadata.json" \
    --sysmon-dir "${SYSMON_DIR}" \
    ${CAM_MONITOR_ARG}

python3 /app/report.py "${RUN_DIR}"

echo ""
echo "========================================"
echo " Analysis Complete"
echo "========================================"
echo " Report:  ${RUN_DIR}/report.html"
echo " Data:    ${RUN_DIR}/"
echo "========================================"
