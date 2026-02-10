#!/usr/bin/env python3
"""
RTP Frame Analyzer - HTML Report Generator

Generates a self-contained HTML report with embedded Base64 images,
statistics tables, and methodology description.
"""

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def img_to_base64(path: Path) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def fmt(val, unit="ms", decimals=1):
    """Format a numeric value with unit."""
    if isinstance(val, (int, float)):
        return f"{val:.{decimals}f}{unit}"
    return str(val)


def generate_html(run_dir: str) -> str:
    rd = Path(run_dir)
    stats_path = rd / "stats.json"
    if not stats_path.exists():
        print(f"ERROR: {stats_path} not found.", file=sys.stderr)
        sys.exit(1)

    with open(stats_path) as f:
        stats = json.load(f)

    meta = stats.get("metadata", {})

    # Collect plot images
    plots = []
    plot_files = sorted(rd.glob("*.png"))
    for pf in plot_files:
        plots.append({
            "name": pf.stem.replace("_", " ").title(),
            "b64": img_to_base64(pf),
            "filename": pf.name,
        })

    # Build HTML
    timestamp = meta.get("timestamp", datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
    rtsp_url = meta.get("rtsp_url", "N/A")
    camera_ip = meta.get("camera_ip", "N/A")
    duration = meta.get("capture_duration_s", stats.get("duration_s", "N/A"))
    iface = meta.get("network_interface", "N/A")
    hostname = meta.get("hostname", "N/A")

    # I-frame / P-frame stats
    def s(key, default="N/A"):
        v = stats.get(key)
        return v if v is not None else default

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RTP Frame Analysis Report &mdash; {timestamp}</title>
<style>
  :root {{
    --primary: #2563eb;
    --danger: #e74c3c;
    --success: #059669;
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }}
  h1 {{
    font-size: 1.8rem;
    border-bottom: 3px solid var(--primary);
    padding-bottom: 0.5rem;
    margin-bottom: 1.5rem;
  }}
  h2 {{
    font-size: 1.3rem;
    color: var(--primary);
    margin: 2rem 0 1rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.3rem;
  }}
  h3 {{
    font-size: 1.1rem;
    margin: 1.5rem 0 0.5rem;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .meta-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
  }}
  .meta-card .label {{
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
  }}
  .meta-card .value {{
    font-size: 1.2rem;
    font-weight: 600;
    margin-top: 0.25rem;
    word-break: break-all;
  }}
  .stat-table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    background: var(--card);
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
  }}
  .stat-table th {{
    background: #f1f5f9;
    text-align: left;
    padding: 0.6rem 1rem;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--muted);
  }}
  .stat-table td {{
    padding: 0.5rem 1rem;
    border-top: 1px solid var(--border);
    font-variant-numeric: tabular-nums;
  }}
  .stat-table tr:hover {{ background: #f8fafc; }}
  .stat-table .num {{ text-align: right; font-family: 'SF Mono', 'Fira Code', monospace; }}
  .alert {{
    padding: 1rem 1.25rem;
    border-radius: 8px;
    margin: 1.5rem 0;
    border-left: 4px solid;
  }}
  .alert-danger {{
    background: #fef2f2;
    border-color: var(--danger);
    color: #991b1b;
  }}
  .alert-info {{
    background: #eff6ff;
    border-color: var(--primary);
    color: #1e40af;
  }}
  .plot-container {{
    margin: 1.5rem 0;
    text-align: center;
  }}
  .plot-container img {{
    max-width: 100%;
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }}
  .plot-caption {{
    font-size: 0.85rem;
    color: var(--muted);
    margin-top: 0.5rem;
  }}
  .methodology {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin: 1rem 0;
  }}
  .methodology pre {{
    background: #f1f5f9;
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 0.8rem;
    line-height: 1.5;
    margin: 0.5rem 0;
  }}
  .methodology code {{
    font-family: 'SF Mono', 'Fira Code', monospace;
  }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }}
  .badge-i {{ background: #fecaca; color: #991b1b; }}
  .badge-p {{ background: #bfdbfe; color: #1e40af; }}
  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    font-size: 0.8rem;
    color: var(--muted);
    text-align: center;
  }}
</style>
</head>
<body>

<h1>RTP Frame Delivery Analysis Report</h1>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">RTSP URL</div>
    <div class="value" style="font-size:0.9rem">{rtsp_url}</div>
  </div>
  <div class="meta-card">
    <div class="label">Camera IP</div>
    <div class="value">{camera_ip}</div>
  </div>
  <div class="meta-card">
    <div class="label">Capture Duration</div>
    <div class="value">{duration}s</div>
  </div>
  <div class="meta-card">
    <div class="label">Interface</div>
    <div class="value">{iface}</div>
  </div>
  <div class="meta-card">
    <div class="label">Host</div>
    <div class="value">{hostname}</div>
  </div>
  <div class="meta-card">
    <div class="label">Timestamp</div>
    <div class="value">{timestamp}</div>
  </div>
</div>
"""

    # Summary highlight (neutral, data-only)
    i_median = s("I_interval_median_ms")
    i_delivery = s("I_delivery_mean_ms")
    p_median = s("P_interval_median_ms")
    nominal = s("nominal_interval_ms", 33.33)
    if isinstance(i_median, (int, float)) and isinstance(nominal, (int, float)):
        i_ratio = i_median / nominal
        html += f"""
<div class="alert alert-info">
  <strong>Measurement summary:</strong> Over this capture, the median inter-frame arrival
  interval was <strong>{i_median:.1f}ms</strong> for I-frames
  ({i_ratio:.1f}x the {nominal:.1f}ms nominal period) and
  <strong>{p_median:.1f}ms</strong> for P-frames.
  The mean time to deliver all RTP packets of a single I-frame was
  <strong>{i_delivery:.1f}ms</strong>.
  These values were measured at the raw UDP packet level before any
  video processing pipeline.
</div>
"""

    # ---------------------------------------------------------------------------
    # System Context section
    # ---------------------------------------------------------------------------
    sys_meta = meta.get("system", {})
    sm = stats.get("system_metrics", {})
    bw = stats.get("bandwidth", {})

    html += "\n<h2>1. System Context</h2>\n"
    html += '<table class="stat-table">\n'

    # Host hardware / OS
    html += '  <tr><th colspan="2">Host</th></tr>\n'
    for label, val in [
        ("Hostname", hostname),
        ("OS", sys_meta.get("os", "N/A")),
        ("Kernel", sys_meta.get("kernel", "N/A")),
        ("Architecture", sys_meta.get("arch", "N/A")),
        ("CPU Model", sys_meta.get("cpu_model", "N/A")),
        ("CPU Cores", sys_meta.get("cpu_cores", "N/A")),
        ("CPU Governor", sys_meta.get("cpu_governor", "N/A")),
    ]:
        if val and val != "N/A":
            html += f'  <tr><td>{label}</td><td class="num">{val}</td></tr>\n'

    # Memory
    html += '  <tr><th colspan="2">Memory</th></tr>\n'
    mem_total = sm.get("mem_total_mb")
    mem_avail = sm.get("mem_available_mb")
    mem_pct = sm.get("mem_used_pct")
    html += f'  <tr><td>Total</td><td class="num">{int(mem_total)} MB</td></tr>\n' if mem_total else ""
    html += f'  <tr><td>Available (at capture start)</td><td class="num">{int(mem_avail)} MB</td></tr>\n' if mem_avail else ""
    html += f'  <tr><td>Used</td><td class="num">{mem_pct}%</td></tr>\n' if mem_pct is not None else ""

    # CPU during capture
    html += '  <tr><th colspan="2">CPU During Capture</th></tr>\n'
    cpu_pct = sm.get("cpu_usage_pct")
    cpu_idle = sm.get("cpu_idle_pct")
    cpu_iow = sm.get("cpu_iowait_pct")
    html += f'  <tr><td>Average Usage</td><td class="num">{cpu_pct}%</td></tr>\n' if cpu_pct is not None else ""
    html += f'  <tr><td>Idle</td><td class="num">{cpu_idle}%</td></tr>\n' if cpu_idle is not None else ""
    html += f'  <tr><td>I/O Wait</td><td class="num">{cpu_iow}%</td></tr>\n' if cpu_iow is not None else ""
    la_start = sm.get("loadavg_start")
    la_end = sm.get("loadavg_end")
    if la_start:
        html += f'  <tr><td>Load Average (start)</td><td class="num">{la_start[0]:.2f} / {la_start[1]:.2f} / {la_start[2]:.2f}</td></tr>\n'
    if la_end:
        html += f'  <tr><td>Load Average (end)</td><td class="num">{la_end[0]:.2f} / {la_end[1]:.2f} / {la_end[2]:.2f}</td></tr>\n'

    # Network / Bandwidth
    html += '  <tr><th colspan="2">Network &amp; Bandwidth</th></tr>\n'
    link_speed = sys_meta.get("link_speed_mbps", "N/A")
    html += f'  <tr><td>Interface</td><td class="num">{iface}</td></tr>\n'
    if link_speed and link_speed != "N/A":
        html += f'  <tr><td>Link Speed</td><td class="num">{link_speed} Mbps</td></tr>\n'
    net_rx = sm.get("net_rx_mbps")
    net_tx = sm.get("net_tx_mbps")
    if net_rx is not None:
        html += f'  <tr><td>Interface RX (total, during capture)</td><td class="num">{net_rx} Mbps</td></tr>\n'
    if net_tx is not None:
        html += f'  <tr><td>Interface TX (total, during capture)</td><td class="num">{net_tx} Mbps</td></tr>\n'
    rtp_bw = bw.get("rtp_bandwidth_mbps")
    rtp_pps = bw.get("rtp_packet_rate_pps")
    rtp_avg = bw.get("rtp_avg_packet_size")
    rtp_total = bw.get("rtp_total_bytes")
    if rtp_bw is not None:
        html += f'  <tr><td>RTP Stream Bandwidth</td><td class="num">{rtp_bw} Mbps</td></tr>\n'
    if rtp_pps is not None:
        html += f'  <tr><td>RTP Packet Rate</td><td class="num">{rtp_pps} pps</td></tr>\n'
    if rtp_avg is not None:
        html += f'  <tr><td>RTP Avg Packet Size</td><td class="num">{int(rtp_avg)} bytes</td></tr>\n'
    if rtp_total is not None:
        html += f'  <tr><td>RTP Total Data</td><td class="num">{rtp_total / 1024 / 1024:.1f} MB</td></tr>\n'
    if net_rx is not None and rtp_bw is not None and net_rx > 0:
        rtp_share = rtp_bw / net_rx * 100
        html += f'  <tr><td>RTP Share of Interface RX</td><td class="num">{rtp_share:.1f}%</td></tr>\n'

    html += "</table>\n"

    # ---------------------------------------------------------------------------
    # Camera Settings section (RadCam only)
    # ---------------------------------------------------------------------------
    cam = stats.get("metadata", {}).get("camera", {})
    if cam.get("detected"):
        html += "\n<h2>2. Camera Settings</h2>\n"
        html += '<p>Collected via the RadCam proprietary HTTP API at capture time. '
        html += 'These settings were active during the measurement.</p>\n'

        # System / Firmware
        sys_cfg = cam.get("sys_config") or {}
        if sys_cfg:
            html += '<table class="stat-table">\n'
            html += '  <tr><th colspan="2">Camera Identity &amp; Firmware</th></tr>\n'
            for label, key in [
                ("Device Name", "dev_name"),
                ("Firmware Version", "version"),
                ("Platform Version", "pf_version"),
                ("User-Platform Version", "upf_version"),
                ("Kernel Version", "kernel_version"),
                ("Device Type", "dev_type"),
                ("Device MAC", "device_mac"),
                ("Device ID", "device_id"),
                ("Driver Board Version", "driver_board_version"),
            ]:
                val = sys_cfg.get(key)
                if val is not None and str(val).strip():
                    html += f'  <tr><td>{label}</td><td class="num">{str(val).strip()}</td></tr>\n'
            html += "</table>\n"

        # Video Encoder (channel 0)
        venc = cam.get("venc_config_ch0") or {}
        if venc:
            encode_type_map = {1: "H.264", 2: "H.265"}
            profile_map = {0: "Baseline", 1: "Main", 2: "High"}
            rc_map = {0: "VBR", 1: "CBR"}
            html += '<table class="stat-table">\n'
            html += '  <tr><th colspan="2">Video Encoder (Channel 0 &mdash; Primary Stream)</th></tr>\n'
            for label, key, fmt_fn in [
                ("Resolution", None, lambda v: f"{venc.get('pic_width')}x{venc.get('pic_height')}"),
                ("Frame Rate", "frame_rate", lambda v: f"{v} fps"),
                ("GOP (Group of Pictures)", "gop", lambda v: str(v)),
                ("Bitrate", "bitrate", lambda v: f"{v} kbps ({v/1024:.1f} Mbps)"),
                ("Codec", "encode_type", lambda v: encode_type_map.get(v, f"Unknown ({v})")),
                ("H.264 Profile", "encode_profile", lambda v: profile_map.get(v, f"Unknown ({v})")),
                ("Rate Control Mode", "rc_mode", lambda v: rc_map.get(v, f"Unknown ({v})")),
                ("Max Frame Rate", "max_framerate", lambda v: f"{v} fps"),
            ]:
                if key is None:
                    # Composite field
                    if venc.get("pic_width") and venc.get("pic_height"):
                        html += f'  <tr><td>{label}</td><td class="num">{fmt_fn(None)}</td></tr>\n'
                else:
                    val = venc.get(key)
                    if val is not None:
                        html += f'  <tr><td>{label}</td><td class="num">{fmt_fn(val)}</td></tr>\n'

            # Supported resolutions
            pix_list = venc.get("pixel_list", [])
            if pix_list:
                res_str = ", ".join(f"{p['width']}x{p['height']}" for p in pix_list if 'width' in p)
                html += f'  <tr><td>Supported Resolutions</td><td class="num">{res_str}</td></tr>\n'
            html += "</table>\n"

        # Video Encoder (channel 1) -- if present and different
        venc1 = cam.get("venc_config_ch1") or {}
        if venc1 and venc1.get("pic_width"):
            html += '<table class="stat-table">\n'
            html += '  <tr><th colspan="2">Video Encoder (Channel 1 &mdash; Sub-Stream)</th></tr>\n'
            for label, key, fmt_fn in [
                ("Resolution", None, lambda v: f"{venc1.get('pic_width')}x{venc1.get('pic_height')}"),
                ("Frame Rate", "frame_rate", lambda v: f"{v} fps"),
                ("GOP", "gop", lambda v: str(v)),
                ("Bitrate", "bitrate", lambda v: f"{v} kbps"),
                ("Codec", "encode_type", lambda v: encode_type_map.get(v, f"Unknown ({v})")),
                ("H.264 Profile", "encode_profile", lambda v: profile_map.get(v, f"Unknown ({v})")),
                ("Rate Control Mode", "rc_mode", lambda v: rc_map.get(v, f"Unknown ({v})")),
            ]:
                if key is None:
                    if venc1.get("pic_width") and venc1.get("pic_height"):
                        html += f'  <tr><td>{label}</td><td class="num">{fmt_fn(None)}</td></tr>\n'
                else:
                    val = venc1.get(key)
                    if val is not None:
                        html += f'  <tr><td>{label}</td><td class="num">{fmt_fn(val)}</td></tr>\n'
            html += "</table>\n"

        # RTSP config
        rtsp_cfg = cam.get("rtsp_config") or {}
        if rtsp_cfg and rtsp_cfg.get("code") == 0:
            html += '<table class="stat-table">\n'
            html += '  <tr><th colspan="2">RTSP Configuration</th></tr>\n'
            # Show all non-metadata fields
            skip_keys = {"code", "device_mac", "deviceID", "device_id", "log", "device_ip", "sign_tby"}
            for key, val in rtsp_cfg.items():
                if key not in skip_keys and val is not None:
                    html += f'  <tr><td>{key}</td><td class="num">{val}</td></tr>\n'
            html += "</table>\n"

        # Image adjustment
        img_adj = cam.get("image_adjustment") or {}
        if img_adj and img_adj.get("code") == 0:
            html += '<table class="stat-table">\n'
            html += '  <tr><th colspan="2">Image Adjustment Settings</th></tr>\n'
            skip_keys = {"code", "device_mac", "deviceID", "device_id", "log",
                         "device_ip", "sign_tby", "validSupport"}
            for key, val in img_adj.items():
                if key not in skip_keys and val is not None:
                    nice_key = key.replace("_", " ").title()
                    html += f'  <tr><td>{nice_key}</td><td class="num">{val}</td></tr>\n'
            html += "</table>\n"

        # Extended image adjustment
        img_ex = cam.get("image_adjustment_ex") or {}
        if img_ex and img_ex.get("code") == 0:
            html += '<table class="stat-table">\n'
            html += '  <tr><th colspan="2">Extended Image Settings</th></tr>\n'
            skip_keys = {"code", "device_mac", "deviceID", "device_id", "log",
                         "device_ip", "sign_tby"}
            for key, val in img_ex.items():
                if key not in skip_keys and val is not None:
                    nice_key = key.replace("_", " ").title()
                    html += f'  <tr><td>{nice_key}</td><td class="num">{val}</td></tr>\n'
            html += "</table>\n"

        # Bump remaining section numbers
        section_offset = 3
    else:
        section_offset = 2

    # Overview stats
    html += f"""
<h2>{section_offset}. Frame Delivery Statistics</h2>
<table class="stat-table">
  <tr><th colspan="2">Overall</th></tr>
"""
    html += f"""
  <tr><td>Total Frames</td><td class="num">{s('total_frames')}</td></tr>
  <tr><td>Duration</td><td class="num">{fmt(s('duration_s'), 's')}</td></tr>
  <tr><td>Effective FPS</td><td class="num">{fmt(s('fps'), '', 2)}</td></tr>
  <tr><td>Nominal Interval</td><td class="num">{fmt(s('nominal_interval_ms'))}</td></tr>
  <tr><td>Stall Frames (&gt;{fmt(s('stall_threshold_ms'))})</td>
      <td class="num">{s('stall_count')} ({fmt(s('stall_pct'), '%')})</td></tr>
  <tr><td>Cumulative Excess Latency</td><td class="num">{fmt(s('cumulative_excess_ms'))}</td></tr>
"""

    # I-frame stats
    if "I_count" in stats:
        html += f"""
  <tr><th colspan="2"><span class="badge badge-i">I-FRAME</span> Statistics</th></tr>
  <tr><td>Count</td><td class="num">{s('I_count')}</td></tr>
  <tr><td>Interval &mdash; Median</td><td class="num">{fmt(s('I_interval_median_ms'))}</td></tr>
  <tr><td>Interval &mdash; P95</td><td class="num">{fmt(s('I_interval_p95_ms'))}</td></tr>
  <tr><td>Interval &mdash; P99</td><td class="num">{fmt(s('I_interval_p99_ms'))}</td></tr>
  <tr><td>Interval &mdash; Max</td><td class="num">{fmt(s('I_interval_max_ms'))}</td></tr>
  <tr><td>Size &mdash; Mean</td><td class="num">{fmt(s('I_size_mean_bytes', 0) / 1024, ' KB', 0)}</td></tr>
  <tr><td>Delivery Duration &mdash; Mean</td><td class="num">{fmt(s('I_delivery_mean_ms'))}</td></tr>
  <tr><td>Delivery Duration &mdash; P95</td><td class="num">{fmt(s('I_delivery_p95_ms'))}</td></tr>
  <tr><td>Delivery Duration &mdash; Max</td><td class="num">{fmt(s('I_delivery_max_ms'))}</td></tr>
  <tr><td>RTP Packets per Frame (mean)</td><td class="num">{fmt(s('I_num_packets_mean'), '', 0)}</td></tr>
"""

    # P-frame stats
    if "P_count" in stats:
        html += f"""
  <tr><th colspan="2"><span class="badge badge-p">P-FRAME</span> Statistics</th></tr>
  <tr><td>Count</td><td class="num">{s('P_count')}</td></tr>
  <tr><td>Interval &mdash; Median</td><td class="num">{fmt(s('P_interval_median_ms'))}</td></tr>
  <tr><td>Interval &mdash; P95</td><td class="num">{fmt(s('P_interval_p95_ms'))}</td></tr>
  <tr><td>Interval &mdash; P99</td><td class="num">{fmt(s('P_interval_p99_ms'))}</td></tr>
  <tr><td>Interval &mdash; Max</td><td class="num">{fmt(s('P_interval_max_ms'))}</td></tr>
  <tr><td>Size &mdash; Mean</td><td class="num">{fmt(s('P_size_mean_bytes', 0) / 1024, ' KB', 0)}</td></tr>
  <tr><td>Delivery Duration &mdash; Mean</td><td class="num">{fmt(s('P_delivery_mean_ms'))}</td></tr>
  <tr><td>Delivery Duration &mdash; P95</td><td class="num">{fmt(s('P_delivery_p95_ms'))}</td></tr>
  <tr><td>Delivery Duration &mdash; Max</td><td class="num">{fmt(s('P_delivery_max_ms'))}</td></tr>
  <tr><td>RTP Packets per Frame (mean)</td><td class="num">{fmt(s('P_num_packets_mean'), '', 0)}</td></tr>
"""

    # Regression
    if "regression_slope_ms_per_kb" in stats:
        html += f"""
  <tr><th colspan="2">Delivery Regression</th></tr>
  <tr><td>Model</td><td class="num">delivery = {stats['regression_slope_ms_per_kb']:.3f} ms/KB &times; size + {stats['regression_intercept_ms']:.1f}ms</td></tr>
"""

    html += "</table>\n"

    # Methodology
    html += f"""
<h2>{section_offset + 1}. Methodology</h2>
<div class="methodology">
<h3>Measurement Point</h3>
<p>This analysis measures frame delivery timing at the <strong>raw network packet level</strong>,
before any video processing pipeline (GStreamer, FFmpeg, etc.) touches the data. This isolates
camera/encoder behavior from receiver-side processing.</p>

<pre><code>Camera Encoder ──► RTP Packetizer ──► UDP/IP ══► [Network] ══► NIC ──► Kernel ──► tcpdump ◄── MEASUREMENT POINT
                                                                                      │
                                                                                      ▼
                                                                              (GStreamer, etc.)
                                                                              NOT measured here</code></pre>

<h3>Frame Reconstruction</h3>
<p>H.264 frames are reconstructed from RTP packets using two signals:</p>
<ul>
  <li><strong>RTP Timestamp:</strong> All packets of the same frame share the same RTP timestamp (90kHz clock).</li>
  <li><strong>RTP Marker Bit:</strong> The last packet of a frame has M=1.</li>
</ul>

<h3>Frame Classification</h3>
<p>Frames are classified as I-frame or P-frame by size heuristic: I-frames are typically 5-20x
larger than P-frames. A threshold of 3x the median frame size is used.</p>

<h3>Timing Metrics</h3>
<ul>
  <li><strong>Inter-frame Interval:</strong> Wall-clock time between the last RTP packet of consecutive frames.</li>
  <li><strong>Delivery Duration:</strong> Wall-clock time from first to last RTP packet within a single frame.</li>
  <li><strong>Delivery Jitter:</strong> Difference between measured wall-clock interval and expected interval (from RTP timestamps).</li>
  <li><strong>Cumulative Excess:</strong> Running sum of (interval - nominal) for all frames where interval > nominal.</li>
</ul>
</div>
"""

    # Plots
    html += f"\n<h2>{section_offset + 2}. Analysis Plots</h2>\n"

    plot_descriptions = {
        "01_timeseries": "Inter-frame arrival interval over time. Each point represents one frame. I-frames are shown as red diamonds, P-frames as blue dots. The green dashed line marks the nominal frame period.",
        "02_distributions": "Distribution of inter-frame intervals, shown separately for I-frames and P-frames. Vertical lines mark the median and 95th percentile for each distribution.",
        "03_scatter": "Frame size (KB) plotted against inter-frame arrival interval (ms). This visualizes whether there is a relationship between frame size and delivery timing.",
        "04_delivery_duration": "Time elapsed from the first to the last RTP packet within each frame. This measures how long it takes to receive all RTP fragments of a single frame.",
        "05_cumulative_excess": "Running sum of excess latency (any interval beyond the nominal frame period). Red vertical lines mark I-frame positions. Steeper slopes indicate periods of higher accumulated delay.",
        "06_jitter": "Delivery jitter, defined as the difference between the measured wall-clock interval and the expected interval derived from RTP timestamps. Zero means the frame arrived exactly when expected.",
        "07_size_vs_delivery": "Frame size plotted against delivery duration (first-to-last RTP packet), with a linear regression fit. This shows whether delivery time scales with frame size.",
    }

    for plot in plots:
        stem = Path(plot["filename"]).stem
        desc = plot_descriptions.get(stem, "")
        html += f"""
<div class="plot-container">
  <img src="data:image/png;base64,{plot['b64']}" alt="{plot['name']}">
  <div class="plot-caption"><strong>{plot['name']}</strong>{': ' + desc if desc else ''}</div>
</div>
"""

    # Observations (neutral, data-driven)
    html += f"\n<h2>{section_offset + 3}. Observations</h2>\n"
    html += """<div class="methodology">
<p>The following observations are derived from the measured data. They describe what was
observed during this specific capture and may not generalize to other configurations,
network conditions, or hardware.</p>
<ul>
"""
    # Build observations dynamically from the data
    observations = []
    if isinstance(i_median, (int, float)) and isinstance(nominal, (int, float)):
        observations.append(
            f"I-frame inter-arrival intervals (median {i_median:.1f}ms) were "
            f"{'above' if i_median > nominal else 'at or below'} the nominal "
            f"frame period ({nominal:.1f}ms)."
        )
    if isinstance(s("I_delivery_mean_ms"), (int, float)):
        observations.append(
            f"The mean time to deliver all RTP packets of a single I-frame was "
            f"{s('I_delivery_mean_ms'):.1f}ms (max {s('I_delivery_max_ms'):.1f}ms)."
        )
    if isinstance(p_median, (int, float)) and isinstance(nominal, (int, float)):
        observations.append(
            f"P-frame inter-arrival intervals (median {p_median:.1f}ms) were "
            f"{'close to' if abs(p_median - nominal) < nominal * 0.15 else 'different from'} "
            f"the nominal frame period."
        )
    if isinstance(s("I_size_mean_bytes"), (int, float)) and isinstance(s("P_size_mean_bytes"), (int, float)):
        ratio = s("I_size_mean_bytes") / max(1, s("P_size_mean_bytes"))
        observations.append(
            f"I-frames were on average {ratio:.1f}x larger than P-frames "
            f"({s('I_size_mean_bytes')/1024:.0f} KB vs {s('P_size_mean_bytes')/1024:.0f} KB)."
        )
    if "regression_slope_ms_per_kb" in stats:
        observations.append(
            f"A linear regression of frame size vs delivery duration yielded a slope of "
            f"{stats['regression_slope_ms_per_kb']:.3f} ms/KB "
            f"(intercept {stats['regression_intercept_ms']:.1f}ms)."
        )
    if isinstance(s("stall_count"), (int, float)):
        observations.append(
            f"{int(s('stall_count'))} frames ({s('stall_pct'):.2f}%) exceeded "
            f"the stall threshold of {s('stall_threshold_ms'):.1f}ms."
        )
    if isinstance(s("cumulative_excess_ms"), (int, float)):
        observations.append(
            f"The cumulative excess latency over the capture was "
            f"{s('cumulative_excess_ms'):.1f}ms."
        )

    for obs in observations:
        html += f"  <li>{obs}</li>\n"

    html += """</ul>
</div>

<h3>How to Read This Report</h3>
<div class="methodology">
<p>This report presents raw measurements taken at the network packet level. It captures
what <em>actually happened</em> on the wire during the test window. Consider the following
when interpreting the results:</p>
<ul>
  <li><strong>Scope:</strong> These measurements reflect the combined behavior of the camera
      encoder, its RTP packetizer, and the network path. They do not include any
      receiver-side video processing overhead.</li>
  <li><strong>Reproducibility:</strong> Results may vary with different encoder settings
      (bitrate, GOP, resolution, profile), network conditions, or camera firmware versions.</li>
  <li><strong>Frame classification:</strong> I-frames and P-frames are identified by a size
      heuristic (threshold = 3&times; median frame size). This is generally reliable for
      H.264 but should be verified if results seem unexpected.</li>
  <li><strong>Raw data:</strong> The <code>stats.json</code>, <code>frame_log.jsonl</code>,
      and <code>capture.pcap</code> files are included alongside this report for independent
      verification and further analysis.</li>
</ul>
</div>
"""

    # Footer
    html += f"""
<footer>
  Generated by <strong>rtp-frame-analyzer</strong> &mdash; {timestamp}<br>
  Raw packet capture provides ground-truth timing independent of any video processing pipeline.
</footer>

</body>
</html>"""

    return html


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <run_directory>", file=sys.stderr)
        sys.exit(1)

    run_dir = sys.argv[1]
    html = generate_html(run_dir)

    out_path = Path(run_dir) / "report.html"
    with open(out_path, "w") as f:
        f.write(html)

    print(f"  Report generated: {out_path}")


if __name__ == "__main__":
    main()
