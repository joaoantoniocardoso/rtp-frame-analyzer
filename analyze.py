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
# 7. Plots
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyze RTP packets for frame timing")
    parser.add_argument("csv_file", help="Path to tshark-extracted RTP CSV")
    parser.add_argument("--output-dir", default=None, help="Output directory")
    parser.add_argument("--metadata", default=None, help="Path to run metadata JSON")
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
    print("  " + "=" * 60)


if __name__ == "__main__":
    main()
