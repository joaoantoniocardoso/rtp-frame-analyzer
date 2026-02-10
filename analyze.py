#!/usr/bin/env python3
"""
RTP Frame Analyzer - Packet Analysis Engine

Reconstructs H.264 frame boundaries from raw RTP packet captures and computes
per-frame delivery timing at the network level. This provides definitive
evidence of whether delivery latency originates from the camera/encoder or
from the receiver's processing pipeline.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# 1. Load RTP packet data
# ---------------------------------------------------------------------------

def load_rtp_csv(csv_path: str) -> list[dict]:
    """Load RTP packet data from tshark-exported CSV."""
    packets = []
    with open(csv_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 6:
                continue
            try:
                pkt = {
                    "wall_time": float(parts[0]),
                    "seq": int(parts[1]),
                    "rtp_ts": int(parts[2]),
                    "marker": parts[3].strip().lower() in ("true", "1"),
                    "pt": int(parts[4]),
                    "udp_len": int(parts[5]),
                }
                packets.append(pkt)
            except (ValueError, IndexError):
                continue
    return packets


# ---------------------------------------------------------------------------
# 2. Reconstruct frames
# ---------------------------------------------------------------------------

def reconstruct_frames(packets: list[dict]) -> list[dict]:
    """
    Reconstruct H.264 frames from RTP packets using marker bit and RTP
    timestamp transitions as frame boundaries.
    """
    if not packets:
        return []

    frames = []
    current_frame_packets = []
    current_rtp_ts = packets[0]["rtp_ts"]

    for pkt in packets:
        if pkt["rtp_ts"] != current_rtp_ts:
            if current_frame_packets:
                frames.append(_make_frame(current_frame_packets))
            current_frame_packets = [pkt]
            current_rtp_ts = pkt["rtp_ts"]
        else:
            current_frame_packets.append(pkt)

        if pkt["marker"] and current_frame_packets:
            frames.append(_make_frame(current_frame_packets))
            current_frame_packets = []
            current_rtp_ts = pkt["rtp_ts"]

    if current_frame_packets:
        frames.append(_make_frame(current_frame_packets))

    return frames


def _make_frame(packets: list[dict]) -> dict:
    wall_times = [p["wall_time"] for p in packets]
    total_payload = sum(p["udp_len"] - 8 for p in packets)
    return {
        "rtp_ts": packets[0]["rtp_ts"],
        "first_packet_time": min(wall_times),
        "last_packet_time": max(wall_times),
        "num_packets": len(packets),
        "total_bytes": total_payload,
        "delivery_duration_ms": (max(wall_times) - min(wall_times)) * 1000,
        "seq_start": packets[0]["seq"],
        "seq_end": packets[-1]["seq"],
        "has_marker": any(p["marker"] for p in packets),
    }


# ---------------------------------------------------------------------------
# 3. Classify frames
# ---------------------------------------------------------------------------

def classify_frames(frames: list[dict]) -> list[dict]:
    """Classify frames as I or P by size (I-frames >> P-frames)."""
    if not frames:
        return frames
    sizes = [f["total_bytes"] for f in frames]
    median_size = np.median(sizes)
    threshold = median_size * 3
    for f in frames:
        f["frame_type"] = "I" if f["total_bytes"] > threshold else "P"
    return frames


# ---------------------------------------------------------------------------
# 4. Compute timing
# ---------------------------------------------------------------------------

def compute_timing(frames: list[dict]) -> list[dict]:
    RTP_CLOCK_RATE = 90000
    for i in range(1, len(frames)):
        prev, curr = frames[i - 1], frames[i]
        curr["wall_interval_ms"] = (
            curr["last_packet_time"] - prev["last_packet_time"]
        ) * 1000
        rtp_delta = curr["rtp_ts"] - prev["rtp_ts"]
        if rtp_delta < 0:
            rtp_delta += 2**32
        curr["expected_interval_ms"] = (rtp_delta / RTP_CLOCK_RATE) * 1000
        curr["jitter_ms"] = curr["wall_interval_ms"] - curr["expected_interval_ms"]
    frames[0]["wall_interval_ms"] = 0
    frames[0]["expected_interval_ms"] = 0
    frames[0]["jitter_ms"] = 0
    return frames


# ---------------------------------------------------------------------------
# 5. Statistics
# ---------------------------------------------------------------------------

def compute_stats(frames: list[dict]) -> dict:
    if len(frames) < 2:
        return {}
    analysis = frames[1:]
    i_frames = [f for f in analysis if f["frame_type"] == "I"]
    p_frames = [f for f in analysis if f["frame_type"] == "P"]

    def grp(fl, label):
        if not fl:
            return {}
        ivs = [f["wall_interval_ms"] for f in fl]
        jts = [f["jitter_ms"] for f in fl]
        szs = [f["total_bytes"] for f in fl]
        dds = [f["delivery_duration_ms"] for f in fl]
        return {
            f"{label}_count": len(fl),
            f"{label}_interval_mean_ms": float(np.mean(ivs)),
            f"{label}_interval_median_ms": float(np.median(ivs)),
            f"{label}_interval_p5_ms": float(np.percentile(ivs, 5)),
            f"{label}_interval_p95_ms": float(np.percentile(ivs, 95)),
            f"{label}_interval_p99_ms": float(np.percentile(ivs, 99)),
            f"{label}_interval_max_ms": float(np.max(ivs)),
            f"{label}_interval_min_ms": float(np.min(ivs)),
            f"{label}_interval_std_ms": float(np.std(ivs)),
            f"{label}_jitter_mean_ms": float(np.mean(jts)),
            f"{label}_jitter_std_ms": float(np.std(jts)),
            f"{label}_size_mean_bytes": float(np.mean(szs)),
            f"{label}_size_max_bytes": float(np.max(szs)),
            f"{label}_delivery_mean_ms": float(np.mean(dds)),
            f"{label}_delivery_max_ms": float(np.max(dds)),
            f"{label}_delivery_p95_ms": float(np.percentile(dds, 95)),
            f"{label}_num_packets_mean": float(np.mean([f["num_packets"] for f in fl])),
        }

    all_ivs = [f["wall_interval_ms"] for f in analysis]
    # Detect nominal frame period from RTP timestamps
    expected = [f["expected_interval_ms"] for f in analysis if f["expected_interval_ms"] > 0]
    nominal_ms = float(np.median(expected)) if expected else 33.33
    stall_thresh = nominal_ms * 1.5

    stats = {
        "total_frames": len(frames),
        "duration_s": frames[-1]["last_packet_time"] - frames[0]["first_packet_time"],
        "fps": len(frames) / max(1e-9, frames[-1]["last_packet_time"] - frames[0]["first_packet_time"]),
        "nominal_interval_ms": nominal_ms,
        "stall_threshold_ms": stall_thresh,
        "stall_count": sum(1 for iv in all_ivs if iv > stall_thresh),
        "stall_pct": sum(1 for iv in all_ivs if iv > stall_thresh) / max(1, len(analysis)) * 100,
        "cumulative_excess_ms": sum(max(0, iv - nominal_ms) for iv in all_ivs),
    }
    stats.update(grp(i_frames, "I"))
    stats.update(grp(p_frames, "P"))
    return stats


# ---------------------------------------------------------------------------
# 6. Save frame log
# ---------------------------------------------------------------------------

def save_frame_log(frames: list[dict], path: str):
    with open(path, "w") as f:
        for fr in frames:
            rec = {
                "wall_time_s": fr["last_packet_time"],
                "interval_ms": fr.get("wall_interval_ms", 0),
                "expected_interval_ms": fr.get("expected_interval_ms", 0),
                "jitter_ms": fr.get("jitter_ms", 0),
                "frame_type": fr.get("frame_type", "?"),
                "size_bytes": fr["total_bytes"],
                "rtp_ts": fr["rtp_ts"],
                "num_rtp_packets": fr["num_packets"],
                "delivery_duration_ms": fr["delivery_duration_ms"],
            }
            f.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# 7. System metrics from sysmon snapshots
# ---------------------------------------------------------------------------

def _parse_snapshot(path: str) -> dict | None:
    """Parse a single sysmon snapshot file."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None

    snap: dict = {}

    # Timestamp
    for line in text.splitlines():
        try:
            snap["ts"] = float(line.strip())
            break
        except ValueError:
            continue

    # CPU from /proc/stat: cpu  user nice system idle iowait irq softirq steal
    for line in text.splitlines():
        if line.startswith("cpu "):
            parts = line.split()
            vals = [int(x) for x in parts[1:]]
            snap["cpu_user"] = vals[0]
            snap["cpu_nice"] = vals[1]
            snap["cpu_system"] = vals[2]
            snap["cpu_idle"] = vals[3]
            snap["cpu_iowait"] = vals[4] if len(vals) > 4 else 0
            snap["cpu_irq"] = vals[5] if len(vals) > 5 else 0
            snap["cpu_softirq"] = vals[6] if len(vals) > 6 else 0
            snap["cpu_steal"] = vals[7] if len(vals) > 7 else 0
            snap["cpu_total"] = sum(vals[:8]) if len(vals) >= 8 else sum(vals)
            snap["cpu_busy"] = snap["cpu_total"] - snap["cpu_idle"] - snap["cpu_iowait"]
            break

    # Memory
    for line in text.splitlines():
        for key in ("MemTotal", "MemFree", "MemAvailable", "Cached", "Buffers"):
            if line.startswith(key + ":"):
                snap[f"mem_{key.lower()}_kb"] = int(line.split()[1])

    # Network: /proc/net/dev line
    # face |bytes packets ... (rx) | bytes packets ... (tx)
    for line in text.splitlines():
        if ":" in line and not line.startswith("---"):
            parts = line.split(":")
            if len(parts) == 2:
                vals = parts[1].split()
                if len(vals) >= 16:
                    try:
                        snap["net_rx_bytes"] = int(vals[0])
                        snap["net_rx_packets"] = int(vals[1])
                        snap["net_tx_bytes"] = int(vals[8])
                        snap["net_tx_packets"] = int(vals[9])
                    except (ValueError, IndexError):
                        pass

    # Load average
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                la1, la5, la15 = float(parts[0]), float(parts[1]), float(parts[2])
                if 0 < la1 < 1000:  # sanity check
                    snap["loadavg_1"] = la1
                    snap["loadavg_5"] = la5
                    snap["loadavg_15"] = la15
            except ValueError:
                continue

    # Thermal zones (millidegrees -> degrees C)
    temps = []
    in_thermal = False
    for line in text.splitlines():
        if line.startswith("--- thermal"):
            in_thermal = True
            continue
        if line.startswith("---"):
            if in_thermal:
                break
            continue
        if in_thermal and ":" in line:
            try:
                _, raw = line.split(":", 1)
                temps.append(int(raw.strip()) / 1000.0)
            except (ValueError, IndexError):
                continue
    if temps:
        snap["temp_c"] = max(temps)  # use the hottest zone

    return snap if "ts" in snap else None


def parse_sysmon(sysmon_dir: str) -> dict:
    """
    Parse all sysmon snapshots and compute aggregate system metrics for the
    capture window (start.txt -> end.txt), plus per-sample timeseries.
    """
    sd = Path(sysmon_dir)
    result: dict = {}

    start = _parse_snapshot(str(sd / "start.txt"))
    end = _parse_snapshot(str(sd / "end.txt"))

    if not start or not end:
        return result

    # Aggregate CPU usage over the capture window
    if "cpu_total" in start and "cpu_total" in end:
        d_total = end["cpu_total"] - start["cpu_total"]
        d_busy = end["cpu_busy"] - start["cpu_busy"]
        d_idle = (end["cpu_idle"] + end.get("cpu_iowait", 0)) - (
            start["cpu_idle"] + start.get("cpu_iowait", 0)
        )
        if d_total > 0:
            result["cpu_usage_pct"] = round(d_busy / d_total * 100, 1)
            result["cpu_idle_pct"] = round(d_idle / d_total * 100, 1)
            result["cpu_iowait_pct"] = round(
                (end.get("cpu_iowait", 0) - start.get("cpu_iowait", 0)) / d_total * 100, 1
            )

    # Network bandwidth over the capture window
    wall_dt = end.get("ts", 0) - start.get("ts", 0)
    if wall_dt > 0 and "net_rx_bytes" in start and "net_rx_bytes" in end:
        rx_bytes = end["net_rx_bytes"] - start["net_rx_bytes"]
        tx_bytes = end["net_tx_bytes"] - start["net_tx_bytes"]
        result["net_rx_mbps"] = round(rx_bytes * 8 / wall_dt / 1e6, 2)
        result["net_tx_mbps"] = round(tx_bytes * 8 / wall_dt / 1e6, 2)
        result["net_rx_bytes"] = rx_bytes
        result["net_tx_bytes"] = tx_bytes

    # Memory at capture start
    if "mem_memtotal_kb" in start:
        result["mem_total_mb"] = round(start["mem_memtotal_kb"] / 1024, 0)
    if "mem_memavailable_kb" in start:
        result["mem_available_mb"] = round(start["mem_memavailable_kb"] / 1024, 0)
    if "mem_memtotal_kb" in start and "mem_memavailable_kb" in start:
        used = start["mem_memtotal_kb"] - start["mem_memavailable_kb"]
        result["mem_used_pct"] = round(used / start["mem_memtotal_kb"] * 100, 1)

    # Load average at start and end
    if "loadavg_1" in start:
        result["loadavg_start"] = [start.get("loadavg_1"), start.get("loadavg_5"), start.get("loadavg_15")]
    if "loadavg_1" in end:
        result["loadavg_end"] = [end.get("loadavg_1"), end.get("loadavg_5"), end.get("loadavg_15")]

    # Temperature at start / end
    if "temp_c" in start:
        result["temp_start_c"] = start["temp_c"]
    if "temp_c" in end:
        result["temp_end_c"] = end["temp_c"]

    # Per-sample CPU + temperature + memory timeseries for plotting
    samples = sorted(sd.glob("sample_*.txt"))
    if len(samples) >= 2:
        cpu_ts = []
        prev_snap = _parse_snapshot(str(samples[0]))
        for sp in samples[1:]:
            curr_snap = _parse_snapshot(str(sp))
            if prev_snap and curr_snap and "cpu_total" in prev_snap and "cpu_total" in curr_snap:
                dt = curr_snap["cpu_total"] - prev_snap["cpu_total"]
                db = curr_snap["cpu_busy"] - prev_snap["cpu_busy"]
                if dt > 0:
                    entry: dict = {
                        "t": curr_snap.get("ts", 0) - start.get("ts", 0),
                        "cpu_pct": round(db / dt * 100, 1),
                    }
                    if "temp_c" in curr_snap:
                        entry["temp_c"] = round(curr_snap["temp_c"], 1)
                    # Memory usage
                    mem_total = curr_snap.get("mem_memtotal_kb", 0)
                    mem_avail = curr_snap.get("mem_memavailable_kb")
                    if mem_total > 0 and mem_avail is not None:
                        entry["mem_pct"] = round(
                            (mem_total - mem_avail) / mem_total * 100, 1
                        )
                    cpu_ts.append(entry)
            prev_snap = curr_snap
        result["cpu_timeseries"] = cpu_ts

        # Temperature aggregate stats from samples
        all_temps = [s["temp_c"] for s in
                     [_parse_snapshot(str(sp)) for sp in samples]
                     if s and "temp_c" in s]
        if all_temps:
            result["temp_min_c"] = round(min(all_temps), 1)
            result["temp_max_c"] = round(max(all_temps), 1)
            result["temp_mean_c"] = round(sum(all_temps) / len(all_temps), 1)

    return result


def parse_camera_monitor(ndjson_path: str, rtsp_start_ts: float | None = None) -> dict:
    """
    Parse camera SoC monitor NDJSON file.

    If rtsp_start_ts is provided, samples before it are classified as
    'baseline' and after as 'streaming'.  Otherwise all samples are 'streaming'.
    """
    samples = []
    with open(ndjson_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not samples:
        return {}

    result: dict = {"sample_count": len(samples)}

    # Classify samples into baseline vs streaming
    if rtsp_start_ts is not None:
        baseline = [s for s in samples if s["ts"] < rtsp_start_ts]
        streaming = [s for s in samples if s["ts"] >= rtsp_start_ts]
    else:
        baseline = []
        streaming = samples

    result["baseline_samples"] = len(baseline)
    result["streaming_samples"] = len(streaming)

    def _stats(sample_list, prefix):
        """Compute aggregate stats for a list of samples."""
        if not sample_list:
            return {}
        out = {}
        # Temperature
        temps = [s["temp_c"] for s in sample_list if "temp_c" in s]
        if temps:
            out[f"{prefix}_temp_mean_c"] = round(float(np.mean(temps)), 1)
            out[f"{prefix}_temp_min_c"] = round(float(np.min(temps)), 1)
            out[f"{prefix}_temp_max_c"] = round(float(np.max(temps)), 1)

        # CPU usage from /proc/stat deltas
        cpu_pcts = []
        for i in range(1, len(sample_list)):
            prev, curr = sample_list[i - 1], sample_list[i]
            if "cpu_total" in prev and "cpu_total" in curr:
                dt = curr["cpu_total"] - prev["cpu_total"]
                db = curr["cpu_busy"] - prev["cpu_busy"]
                if dt > 0:
                    cpu_pcts.append(round(db / dt * 100, 1))
        if cpu_pcts:
            out[f"{prefix}_cpu_mean_pct"] = round(float(np.mean(cpu_pcts)), 1)
            out[f"{prefix}_cpu_min_pct"] = round(float(np.min(cpu_pcts)), 1)
            out[f"{prefix}_cpu_max_pct"] = round(float(np.max(cpu_pcts)), 1)

        # Memory usage
        mem_used_pcts = []
        for s in sample_list:
            total = s.get("mem_memtotal_kb", 0)
            avail = s.get("mem_memavailable_kb")
            free = s.get("mem_memfree_kb")
            if total > 0:
                if avail is not None:
                    used_pct = (total - avail) / total * 100
                elif free is not None:
                    used_pct = (total - free) / total * 100
                else:
                    continue
                mem_used_pcts.append(round(used_pct, 1))
        if mem_used_pcts:
            out[f"{prefix}_mem_mean_pct"] = round(float(np.mean(mem_used_pcts)), 1)
            out[f"{prefix}_mem_min_pct"] = round(float(np.min(mem_used_pcts)), 1)
            out[f"{prefix}_mem_max_pct"] = round(float(np.max(mem_used_pcts)), 1)
            # Also store absolute values from the last sample
            last = sample_list[-1]
            out[f"{prefix}_mem_total_kb"] = last.get("mem_memtotal_kb", 0)
            out[f"{prefix}_mem_free_kb"] = last.get("mem_memfree_kb", 0)
            out[f"{prefix}_mem_available_kb"] = last.get("mem_memavailable_kb", 0)

        # Voltages (from last sample)
        last = sample_list[-1]
        for vkey in ("core_volt", "cpu_volt", "npu_volt"):
            if vkey in last:
                out[f"{prefix}_{vkey}_mv"] = last[vkey]

        return out

    result.update(_stats(baseline, "baseline"))
    result.update(_stats(streaming, "streaming"))
    result.update(_stats(samples, "overall"))

    # Build timeseries for plotting (relative to first sample)
    t0 = samples[0]["ts"]
    timeseries = []
    for i in range(1, len(samples)):
        prev, curr = samples[i - 1], samples[i]
        entry: dict = {"t": round(curr["ts"] - t0, 2)}

        if "temp_c" in curr:
            entry["temp_c"] = curr["temp_c"]

        if "cpu_total" in prev and "cpu_total" in curr:
            dt = curr["cpu_total"] - prev["cpu_total"]
            db = curr["cpu_busy"] - prev["cpu_busy"]
            if dt > 0:
                entry["cpu_pct"] = round(db / dt * 100, 1)

        total = curr.get("mem_memtotal_kb", 0)
        avail = curr.get("mem_memavailable_kb")
        free = curr.get("mem_memfree_kb")
        if total > 0:
            if avail is not None:
                entry["mem_pct"] = round((total - avail) / total * 100, 1)
            elif free is not None:
                entry["mem_pct"] = round((total - free) / total * 100, 1)

        for vkey in ("core_volt", "cpu_volt", "npu_volt"):
            if vkey in curr:
                entry[vkey] = curr[vkey]

        entry["is_baseline"] = curr["ts"] < rtsp_start_ts if rtsp_start_ts else False
        timeseries.append(entry)

    result["timeseries"] = timeseries

    # Mark the RTSP start time relative to t0
    if rtsp_start_ts is not None:
        result["rtsp_start_offset_s"] = round(rtsp_start_ts - t0, 2)

    return result


def compute_bandwidth(packets: list[dict], duration_s: float) -> dict:
    """Compute RTP stream bandwidth from raw packets."""
    if not packets or duration_s <= 0:
        return {}
    total_bytes = sum(p["udp_len"] for p in packets)
    return {
        "rtp_total_bytes": total_bytes,
        "rtp_bandwidth_mbps": round(total_bytes * 8 / duration_s / 1e6, 2),
        "rtp_packet_rate_pps": round(len(packets) / duration_s, 1),
        "rtp_avg_packet_size": round(total_bytes / len(packets), 0),
    }


# ---------------------------------------------------------------------------
# 8. Plots
# ---------------------------------------------------------------------------

def generate_plots(frames: list[dict], stats: dict, out_dir: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out = Path(out_dir)
    analysis = frames[1:]
    t0 = frames[0]["first_packet_time"]
    times = [f["last_packet_time"] - t0 for f in analysis]
    intervals = [f["wall_interval_ms"] for f in analysis]
    sizes_kb = [f["total_bytes"] / 1024 for f in analysis]
    types = [f["frame_type"] for f in analysis]
    jitters = [f["jitter_ms"] for f in analysis]
    delivery = [f["delivery_duration_ms"] for f in analysis]

    im = [i for i, t in enumerate(types) if t == "I"]
    pm = [i for i, t in enumerate(types) if t == "P"]

    CI, CP, CBG = "#e74c3c", "#3498db", "#f8f9fa"
    nominal = stats.get("nominal_interval_ms", 33.33)

    def _sel(lst, idxs):
        return [lst[i] for i in idxs]

    # ---- 1. Timeseries ----
    fig, ax = plt.subplots(figsize=(14, 5))
    ax.set_facecolor(CBG)
    ax.scatter(_sel(times, pm), _sel(intervals, pm), s=3, alpha=0.5, c=CP, label="P-frame")
    ax.scatter(_sel(times, im), _sel(intervals, im), s=30, alpha=0.9, c=CI, label="I-frame", marker="D", zorder=5)
    ax.axhline(nominal, color="green", ls="--", alpha=0.7, label=f"{nominal:.1f}ms nominal")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Inter-frame Interval (ms)")
    ax.set_title("Network-Level Inter-frame Arrival Interval")
    ax.legend()
    ax.set_ylim(0, min(250, max(intervals) * 1.1))
    fig.tight_layout()
    fig.savefig(out / "01_timeseries.png", dpi=150)
    plt.close(fig)

    # ---- 2. Distributions ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    for ax, (idxs, color, label) in zip(axes, [(im, CI, "I-frame"), (pm, CP, "P-frame")]):
        ax.set_facecolor(CBG)
        data = _sel(intervals, idxs)
        if data:
            lo = max(0, min(data) * 0.8)
            hi = min(max(data) * 1.05, 250)
            bins = np.linspace(lo, hi, 80)
            ax.hist(data, bins=bins, color=color, alpha=0.7, edgecolor="white")
            ax.axvline(np.median(data), color="black", ls="--", label=f"median={np.median(data):.1f}ms")
            ax.axvline(np.percentile(data, 95), color="orange", ls=":", label=f"p95={np.percentile(data, 95):.1f}ms")
        ax.axvline(nominal, color="green", ls="--", alpha=0.7, label=f"{nominal:.1f}ms nominal")
        ax.set_xlabel("Inter-frame Interval (ms)")
        ax.set_ylabel("Count")
        ax.set_title(f"{label} Interval Distribution")
        ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "02_distributions.png", dpi=150)
    plt.close(fig)

    # ---- 3. Scatter: size vs interval ----
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_facecolor(CBG)
    ax.scatter(_sel(sizes_kb, pm), _sel(intervals, pm), s=5, alpha=0.4, c=CP, label="P-frame")
    ax.scatter(_sel(sizes_kb, im), _sel(intervals, im), s=40, alpha=0.8, c=CI, label="I-frame", marker="D")
    ax.axhline(nominal, color="green", ls="--", alpha=0.7, label=f"{nominal:.1f}ms nominal")
    ax.set_xlabel("Frame Size (KB)")
    ax.set_ylabel("Inter-frame Interval (ms)")
    ax.set_title("Frame Size vs Delivery Interval")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "03_scatter.png", dpi=150)
    plt.close(fig)

    # ---- 4. Frame delivery duration ----
    fig, ax = plt.subplots(figsize=(14, 5))
    ax.set_facecolor(CBG)
    ax.scatter(_sel(times, pm), _sel(delivery, pm), s=3, alpha=0.5, c=CP, label="P-frame")
    ax.scatter(_sel(times, im), _sel(delivery, im), s=30, alpha=0.9, c=CI, label="I-frame", marker="D", zorder=5)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Frame Delivery Duration (ms)")
    ax.set_title("Time to Deliver All RTP Packets Per Frame (first-to-last packet)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "04_delivery_duration.png", dpi=150)
    plt.close(fig)

    # ---- 5. Cumulative excess ----
    cumul = []
    running = 0.0
    for iv in intervals:
        running += max(0, iv - nominal)
        cumul.append(running)
    fig, ax = plt.subplots(figsize=(14, 5))
    ax.set_facecolor(CBG)
    ax.plot(times, cumul, color="purple", lw=1)
    for idx in im:
        ax.axvline(times[idx], color=CI, alpha=0.15, lw=0.5)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Cumulative Excess Latency (ms)")
    ax.set_title("Cumulative Excess Latency Over Time")
    fig.tight_layout()
    fig.savefig(out / "05_cumulative_excess.png", dpi=150)
    plt.close(fig)

    # ---- 6. Jitter ----
    fig, ax = plt.subplots(figsize=(14, 5))
    ax.set_facecolor(CBG)
    ax.scatter(_sel(times, pm), _sel(jitters, pm), s=3, alpha=0.5, c=CP, label="P-frame")
    ax.scatter(_sel(times, im), _sel(jitters, im), s=30, alpha=0.9, c=CI, label="I-frame", marker="D", zorder=5)
    ax.axhline(0, color="green", ls="--", alpha=0.7, label="Zero jitter")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Delivery Jitter (ms)")
    ax.set_title("Delivery Jitter (Wall Clock - RTP Expected)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "06_jitter.png", dpi=150)
    plt.close(fig)

    # ---- 7. Size vs delivery duration with regression ----
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_facecolor(CBG)
    all_sizes = [f["total_bytes"] / 1024 for f in analysis]
    all_delivery = [f["delivery_duration_ms"] for f in analysis]
    ax.scatter(_sel(all_sizes, pm), _sel(all_delivery, pm), s=5, alpha=0.4, c=CP, label="P-frame")
    ax.scatter(_sel(all_sizes, im), _sel(all_delivery, im), s=40, alpha=0.8, c=CI, label="I-frame", marker="D")
    # Linear regression
    if len(all_sizes) > 10:
        coeffs = np.polyfit(all_sizes, all_delivery, 1)
        xs = np.linspace(0, max(all_sizes) * 1.05, 100)
        ax.plot(xs, np.polyval(coeffs, xs), "k--", alpha=0.6,
                label=f"fit: {coeffs[0]:.3f} ms/KB + {coeffs[1]:.1f}ms")
        stats["regression_slope_ms_per_kb"] = float(coeffs[0])
        stats["regression_intercept_ms"] = float(coeffs[1])
    ax.set_xlabel("Frame Size (KB)")
    ax.set_ylabel("Delivery Duration (ms)")
    ax.set_title("Frame Size vs Delivery Duration (with linear fit)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "07_size_vs_delivery.png", dpi=150)
    plt.close(fig)

    # ---- 8. Host system monitoring (CPU, Memory, Temperature) ----
    host_ts = stats.get("system_metrics", {}).get("cpu_timeseries", [])
    if len(host_ts) >= 2:
        ht_times = [e["t"] for e in host_ts]
        ht_cpu = [e.get("cpu_pct") for e in host_ts]
        ht_mem = [e.get("mem_pct") for e in host_ts]
        ht_temp = [e.get("temp_c") for e in host_ts]

        has_cpu = any(v is not None for v in ht_cpu)
        has_mem = any(v is not None for v in ht_mem)
        has_temp = any(v is not None for v in ht_temp)
        n_axes = sum([has_cpu or has_mem, has_temp])

        if n_axes > 0:
            fig, axes_arr = plt.subplots(n_axes, 1, figsize=(14, 3.5 * n_axes),
                                         sharex=True, squeeze=False)
            axes_flat = axes_arr.flatten()
            ax_idx = 0

            # CPU + Memory subplot
            if has_cpu or has_mem:
                ax = axes_flat[ax_idx]
                ax.set_facecolor(CBG)
                if has_cpu:
                    valid = [(t, v) for t, v in zip(ht_times, ht_cpu) if v is not None]
                    if valid:
                        ax.plot([t for t, _ in valid], [v for _, v in valid],
                                color="#e74c3c", lw=1.5, marker=".", ms=4, label="CPU %")
                if has_mem:
                    valid = [(t, v) for t, v in zip(ht_times, ht_mem) if v is not None]
                    if valid:
                        ax.plot([t for t, _ in valid], [v for _, v in valid],
                                color="#3498db", lw=1.5, marker="s", ms=3, label="Memory %")
                ax.set_ylabel("Usage (%)")
                ax.set_ylim(0, 105)
                ax.set_title("Host System — CPU & Memory Usage During Capture")
                ax.legend(loc="upper right", fontsize=8)
                ax.grid(True, alpha=0.3)
                ax_idx += 1

            # Temperature subplot
            if has_temp:
                ax = axes_flat[ax_idx]
                ax.set_facecolor(CBG)
                valid = [(t, v) for t, v in zip(ht_times, ht_temp) if v is not None]
                if valid:
                    ax.plot([t for t, _ in valid], [v for _, v in valid],
                            color="#e67e22", lw=1.5, marker="^", ms=4, label="Temperature")
                ax.set_ylabel("Temperature (°C)")
                ax.set_title("Host System — Temperature During Capture")
                ax.legend(loc="upper right", fontsize=8)
                ax.grid(True, alpha=0.3)

            axes_flat[-1].set_xlabel("Time (s)")
            fig.tight_layout()
            fig.savefig(out / "08_host_system.png", dpi=150)
            plt.close(fig)

    # ---- 9. Camera SoC monitoring (CPU, Memory, Temperature) ----
    cam_ts = stats.get("camera_soc", {}).get("timeseries", [])
    rtsp_offset = stats.get("camera_soc", {}).get("rtsp_start_offset_s")
    if len(cam_ts) >= 2:
        ct_times = [e["t"] for e in cam_ts]
        ct_cpu = [e.get("cpu_pct") for e in cam_ts]
        ct_mem = [e.get("mem_pct") for e in cam_ts]
        ct_temp = [e.get("temp_c") for e in cam_ts]
        ct_baseline = [e.get("is_baseline", False) for e in cam_ts]

        has_cpu = any(v is not None for v in ct_cpu)
        has_mem = any(v is not None for v in ct_mem)
        has_temp = any(v is not None for v in ct_temp)

        n_axes = sum([has_cpu or has_mem, has_temp])
        if n_axes > 0:
            fig, axes_arr = plt.subplots(n_axes, 1, figsize=(14, 3.5 * n_axes),
                                         sharex=True, squeeze=False)
            axes_flat = axes_arr.flatten()
            ax_idx = 0

            def _add_baseline_region(ax_obj):
                """Shade the baseline region."""
                if rtsp_offset is not None and rtsp_offset > 0:
                    ax_obj.axvspan(0, rtsp_offset, alpha=0.10, color="gray",
                                   label="Baseline (no stream)")
                    ax_obj.axvline(rtsp_offset, color="gray", ls=":", alpha=0.6, lw=1)

            # CPU + Memory subplot
            if has_cpu or has_mem:
                ax = axes_flat[ax_idx]
                ax.set_facecolor(CBG)
                _add_baseline_region(ax)
                if has_cpu:
                    valid = [(t, v) for t, v in zip(ct_times, ct_cpu) if v is not None]
                    if valid:
                        ax.plot([t for t, _ in valid], [v for _, v in valid],
                                color="#e74c3c", lw=1.5, marker=".", ms=4, label="CPU %")
                if has_mem:
                    valid = [(t, v) for t, v in zip(ct_times, ct_mem) if v is not None]
                    if valid:
                        ax.plot([t for t, _ in valid], [v for _, v in valid],
                                color="#3498db", lw=1.5, marker="s", ms=3, label="Memory %")
                ax.set_ylabel("Usage (%)")
                ax.set_ylim(0, 105)
                ax.set_title("Camera SoC — CPU & Memory Usage (baseline → streaming)")
                ax.legend(loc="upper right", fontsize=8)
                ax.grid(True, alpha=0.3)
                ax_idx += 1

            # Temperature subplot
            if has_temp:
                ax = axes_flat[ax_idx]
                ax.set_facecolor(CBG)
                _add_baseline_region(ax)
                valid = [(t, v) for t, v in zip(ct_times, ct_temp) if v is not None]
                if valid:
                    ax.plot([t for t, _ in valid], [v for _, v in valid],
                            color="#e67e22", lw=1.5, marker="^", ms=4, label="Temperature")
                ax.set_ylabel("Temperature (°C)")
                ax.set_title("Camera SoC — Temperature (baseline → streaming)")
                ax.legend(loc="upper right", fontsize=8)
                ax.grid(True, alpha=0.3)

            axes_flat[-1].set_xlabel("Time (s)")
            fig.tight_layout()
            fig.savefig(out / "09_camera_soc.png", dpi=150)
            plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyze RTP packets for frame timing")
    parser.add_argument("csv_file", help="Path to tshark-extracted RTP CSV")
    parser.add_argument("--output-dir", default=None, help="Output directory")
    parser.add_argument("--metadata", default=None, help="Path to run metadata JSON")
    parser.add_argument("--sysmon-dir", default=None, help="Path to sysmon snapshot directory")
    parser.add_argument("--camera-info", default=None, help="Path to camera_info.json (RadCam API data)")
    parser.add_argument("--camera-monitor", default=None, help="Path to camera_monitor NDJSON file")
    args = parser.parse_args()

    out_dir = args.output_dir or str(Path(args.csv_file).parent / "analysis")
    os.makedirs(out_dir, exist_ok=True)

    print("  Loading RTP packets...")
    packets = load_rtp_csv(args.csv_file)
    print(f"  Loaded {len(packets)} RTP packets")

    print("  Reconstructing frames...")
    frames = reconstruct_frames(packets)
    print(f"  Reconstructed {len(frames)} frames")

    print("  Classifying frames...")
    frames = classify_frames(frames)
    i_n = sum(1 for f in frames if f["frame_type"] == "I")
    p_n = sum(1 for f in frames if f["frame_type"] == "P")
    print(f"  I-frames: {i_n}, P-frames: {p_n}")

    print("  Computing timing...")
    frames = compute_timing(frames)

    print("  Computing statistics...")
    stats = compute_stats(frames)

    # RTP bandwidth
    print("  Computing bandwidth...")
    bw = compute_bandwidth(packets, stats.get("duration_s", 0))
    stats["bandwidth"] = bw

    # System metrics
    if args.sysmon_dir and os.path.isdir(args.sysmon_dir):
        print("  Parsing system metrics...")
        sysmon = parse_sysmon(args.sysmon_dir)
        stats["system_metrics"] = sysmon
    else:
        stats["system_metrics"] = {}

    # Camera info (RadCam API)
    if args.camera_info and os.path.exists(args.camera_info):
        print("  Loading camera info...")
        with open(args.camera_info) as f:
            camera_info = json.load(f)
        if camera_info.get("detected"):
            stats["camera_info"] = camera_info
            # Print camera summary
            venc = camera_info.get("venc_config_ch0", {}) or {}
            sys_cfg = camera_info.get("sys_config", {}) or {}
            print(f"  Camera: {camera_info.get('type', 'Unknown')}")
            if sys_cfg.get("version"):
                print(f"  Firmware: {sys_cfg['version']}")
            if venc.get("pic_width"):
                profile_map = {0: "Baseline", 1: "Main", 2: "High"}
                encode_map = {1: "H.264", 2: "H.265"}
                rc_map = {0: "VBR", 1: "CBR"}
                print(f"  Encoder: {encode_map.get(venc.get('encode_type'), '?')} "
                      f"{venc.get('pic_width')}x{venc.get('pic_height')} "
                      f"@{venc.get('frame_rate')}fps "
                      f"GOP={venc.get('gop')} "
                      f"BR={venc.get('bitrate')}kbps "
                      f"{profile_map.get(venc.get('encode_profile'), '?')} "
                      f"{rc_map.get(venc.get('rc_mode'), '?')}")
        else:
            stats["camera_info"] = {"detected": False}
    else:
        stats["camera_info"] = {"detected": False}

    # Camera SoC monitor data (telnet-based)
    if args.camera_monitor and os.path.exists(args.camera_monitor):
        print("  Parsing camera SoC monitor data...")
        # Use the first RTP packet time as the RTSP start reference
        rtsp_start = packets[0]["wall_time"] if packets else None
        cam_soc = parse_camera_monitor(args.camera_monitor, rtsp_start)
        stats["camera_soc"] = cam_soc
        if cam_soc.get("baseline_samples", 0) > 0:
            print(f"  Camera SoC: {cam_soc['sample_count']} samples "
                  f"({cam_soc['baseline_samples']} baseline, "
                  f"{cam_soc['streaming_samples']} streaming)")
        else:
            print(f"  Camera SoC: {cam_soc['sample_count']} samples")
        if "overall_temp_mean_c" in cam_soc:
            print(f"  Camera SoC temp:    {cam_soc['overall_temp_mean_c']}°C avg "
                  f"(min={cam_soc.get('overall_temp_min_c', '?')}°C "
                  f"max={cam_soc.get('overall_temp_max_c', '?')}°C)")
        if "baseline_cpu_mean_pct" in cam_soc:
            print(f"  Camera CPU (baseline):  {cam_soc['baseline_cpu_mean_pct']}%")
        if "streaming_cpu_mean_pct" in cam_soc:
            print(f"  Camera CPU (streaming): {cam_soc['streaming_cpu_mean_pct']}%")
    else:
        stats["camera_soc"] = {}

    # Merge metadata if available
    if args.metadata and os.path.exists(args.metadata):
        with open(args.metadata) as f:
            stats["metadata"] = json.load(f)

    print("  Generating plots...")
    generate_plots(frames, stats, out_dir)

    # Save outputs
    with open(os.path.join(out_dir, "stats.json"), "w") as f:
        json.dump(stats, f, indent=2)

    save_frame_log(frames, os.path.join(out_dir, "frame_log.jsonl"))

    # Print summary
    sm = stats.get("system_metrics", {})
    print()
    print("  " + "=" * 60)
    print("  NETWORK-LEVEL FRAME DELIVERY STATISTICS")
    print("  " + "=" * 60)
    print(f"  Total frames:       {stats['total_frames']}")
    print(f"  Duration:           {stats['duration_s']:.1f}s")
    print(f"  Effective FPS:      {stats['fps']:.2f}")
    print(f"  Nominal interval:   {stats['nominal_interval_ms']:.2f}ms")
    print(f"  Stall frames:       {stats['stall_count']} ({stats['stall_pct']:.2f}%)")
    print(f"  Cumulative excess:  {stats['cumulative_excess_ms']:.1f}ms")
    if "I_count" in stats:
        print(f"  I-frame interval:   median={stats['I_interval_median_ms']:.1f}ms  "
              f"p95={stats['I_interval_p95_ms']:.1f}ms  max={stats['I_interval_max_ms']:.1f}ms")
        print(f"  I-frame size:       mean={stats['I_size_mean_bytes']/1024:.0f}KB  "
              f"delivery={stats['I_delivery_mean_ms']:.1f}ms")
    if "P_count" in stats:
        print(f"  P-frame interval:   median={stats['P_interval_median_ms']:.1f}ms  "
              f"p95={stats['P_interval_p95_ms']:.1f}ms  max={stats['P_interval_max_ms']:.1f}ms")
        print(f"  P-frame size:       mean={stats['P_size_mean_bytes']/1024:.0f}KB  "
              f"delivery={stats['P_delivery_mean_ms']:.1f}ms")
    if "regression_slope_ms_per_kb" in stats:
        print(f"  Delivery regression: {stats['regression_slope_ms_per_kb']:.3f} ms/KB "
              f"+ {stats['regression_intercept_ms']:.1f}ms")
    if bw:
        print(f"  RTP bandwidth:      {bw.get('rtp_bandwidth_mbps', 0)} Mbps  "
              f"({bw.get('rtp_packet_rate_pps', 0)} pps)")
    if sm.get("cpu_usage_pct") is not None:
        print(f"  Host CPU usage:     {sm['cpu_usage_pct']}%")
    if sm.get("temp_mean_c") is not None:
        print(f"  CPU temperature:    {sm['temp_mean_c']}°C avg  "
              f"(min={sm.get('temp_min_c', '?')}°C  max={sm.get('temp_max_c', '?')}°C)")
    if sm.get("net_rx_mbps") is not None:
        print(f"  Interface RX:       {sm['net_rx_mbps']} Mbps (total)")
    csoc = stats.get("camera_soc", {})
    if csoc.get("overall_temp_mean_c") is not None:
        print(f"  Camera SoC temp:    {csoc['overall_temp_mean_c']}°C avg  "
              f"(baseline={csoc.get('baseline_temp_mean_c', 'N/A')}°C  "
              f"streaming={csoc.get('streaming_temp_mean_c', 'N/A')}°C)")
    if csoc.get("baseline_cpu_mean_pct") is not None:
        print(f"  Camera CPU:         baseline={csoc['baseline_cpu_mean_pct']}%  "
              f"streaming={csoc.get('streaming_cpu_mean_pct', 'N/A')}%")
    if csoc.get("baseline_mem_mean_pct") is not None:
        print(f"  Camera memory:      baseline={csoc['baseline_mem_mean_pct']}%  "
              f"streaming={csoc.get('streaming_mem_mean_pct', 'N/A')}%")
    print("  " + "=" * 60)


if __name__ == "__main__":
    main()
