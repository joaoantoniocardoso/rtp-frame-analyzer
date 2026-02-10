#!/usr/bin/env python3
"""Collect system and camera metadata into a safe JSON file."""
import json
import os
import platform
import subprocess
import sys
import urllib.request


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return None


def _cam_api(ip, ep):
    try:
        with urllib.request.urlopen(f"http://{ip}/action/{ep}", timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


camera_ip, duration, iface, ts, run_dir = sys.argv[1:6]

system = {
    "kernel": platform.release(),
    "arch": platform.machine(),
    "os": _run("grep ^PRETTY_NAME= /etc/os-release | cut -d'\"' -f2") or platform.platform(),
    "cpu_model": _run("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'") or "N/A",
    "cpu_cores": _run("nproc") or "N/A",
    "cpu_governor": _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") or "N/A",
    "mem_total_kb": int(_run("grep MemTotal /proc/meminfo | awk '{print $2}'") or 0),
    "link_speed_mbps": _read(f"/sys/class/net/{iface}/speed") or "N/A",
    "scheduler_autogroup": _read("/proc/sys/kernel/sched_autogroup_enabled") or "N/A",
}

camera = {"detected": False}
sc = _cam_api(camera_ip, "getSysConfig")
if sc is not None:
    camera = {
        "detected": True,
        "type": "RadCam",
        "sys_config": sc,
        "venc_config_ch0": _cam_api(camera_ip, "getVencConf?channel=0"),
        "venc_config_ch1": _cam_api(camera_ip, "getVencConf?channel=1"),
        "rtsp_config": _cam_api(camera_ip, "getRtspConf"),
        "image_adjustment": _cam_api(camera_ip, "getImageAdjustment"),
        "image_adjustment_ex": _cam_api(camera_ip, "getImageAdjustmentEx"),
    }
    print("       RadCam detected, camera settings collected.")
else:
    print("       Camera API not reachable or not a RadCam (non-fatal).")

meta = {
    "rtsp_url": os.environ.get("RTSP_URL", ""),
    "camera_ip": camera_ip,
    "capture_duration_s": int(duration),
    "network_interface": iface,
    "timestamp": ts,
    "hostname": platform.node(),
    "system": system,
    "camera": camera,
}

with open(os.path.join(run_dir, "metadata.json"), "w") as f:
    json.dump(meta, f, indent=2)
with open(os.path.join(run_dir, "camera_info.json"), "w") as f:
    json.dump(camera, f, indent=2)
print("       Metadata saved.")
