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

echo "========================================"
echo " RTP Frame Analyzer"
echo "========================================"
echo " RTSP URL:       ${RTSP_URL}"
echo " Capture:        ${CAPTURE_DURATION}s"
echo " Output:         ${OUTPUT_DIR}"
echo " Interface:      ${NETWORK_INTERFACE}"
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
# Start RTSP client to trigger the stream
# ---------------------------------------------------------------------------
echo "[4/6] Connecting RTSP client to ${RTSP_URL}..."

gst-launch-1.0 \
    rtspsrc location="${RTSP_URL}" latency=0 protocols=udp \
    ! fakesink \
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
kill "${GST_PID}" 2>/dev/null || true
sleep 1
kill "${TCPDUMP_PID}" 2>/dev/null || true
wait "${GST_PID}" 2>/dev/null || true
wait "${TCPDUMP_PID}" 2>/dev/null || true

PCAP_SIZE=$(du -h "${PCAP_FILE}" | cut -f1)
echo "       Capture complete: ${PCAP_FILE} (${PCAP_SIZE})"

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

python3 /app/analyze.py "${CSV_FILE}" \
    --output-dir "${RUN_DIR}" \
    --metadata "${RUN_DIR}/metadata.json" \
    --sysmon-dir "${SYSMON_DIR}" \

python3 /app/report.py "${RUN_DIR}"

echo ""
echo "========================================"
echo " Analysis Complete"
echo "========================================"
echo " Report:  ${RUN_DIR}/report.html"
echo " Data:    ${RUN_DIR}/"
echo "========================================"
