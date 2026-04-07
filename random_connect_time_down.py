import os
import re
import json
import time
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import requests


# =========================
# 配置
# =========================
IP_INPUT_FILE = r"./tron_public_online_nodes_test.csv"
DOMAIN_INPUT_FILE = r"./tron_domains.txt"        # 每行: domain,30s / domain,50min / domain,1h
OUTPUT_ROOT = r"./tron_monitor_output"

IP_SCAN_INTERVAL_SECONDS = 30 * 60
TIMEOUT = 5
MAX_WORKERS = 50
DEFAULT_SCHEME = "http"
VERIFY_SSL = False

requests.packages.urllib3.disable_warnings()


# =========================
# 通用工具
# =========================
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*]+', '_', name)


def parse_interval_to_seconds(interval_str: str) -> int:
    s = interval_str.strip().lower()
    m = re.fullmatch(r"(\d+)\s*(s|min|h)", s)
    if not m:
        raise ValueError(f"Invalid interval format: {interval_str}")

    value = int(m.group(1))
    unit = m.group(2)

    if unit == "s":
        return value
    if unit == "min":
        return value * 60
    if unit == "h":
        return value * 3600

    raise ValueError(f"Unsupported interval unit: {interval_str}")


def build_url(target: str) -> str:
    raw = target.strip()

    if raw.startswith("http://") or raw.startswith("https://"):
        return raw.rstrip("/") + "/wallet/getnodeinfo"

    ip_match = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw)
    if ip_match:
        return f"http://{raw}:8090/wallet/getnodeinfo"

    return f"{DEFAULT_SCHEME}://{raw}/wallet/getnodeinfo"


def strip_machine_info(machine_info):
    """
    保留 machineInfo，但去掉 memoryDescInfoList
    """
    if not isinstance(machine_info, dict):
        return None

    cleaned = dict(machine_info)
    cleaned.pop("memoryDescInfoList", None)
    return cleaned



def read_domain_targets(file_path: str):
    if not os.path.exists(file_path):
        return []

    targets = []
    with open(file_path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            parts = [x.strip() for x in s.split(",")]
            if len(parts) != 2:
                print(f"[WARN] skip invalid domain line {lineno}: {s}")
                continue

            domain, interval_str = parts
            try:
                interval_sec = parse_interval_to_seconds(interval_str)
            except Exception as e:
                print(f"[WARN] skip invalid interval at line {lineno}: {s}, err={e}")
                continue

            targets.append({
                "domain": domain,
                "interval_sec": interval_sec,
            })

    return targets

def extract_ip_from_line(line: str):
    """
    支持输入格式：
      "98.128.230.186:18888",
      "98.128.230.186:18888"
      98.128.230.186:18888,
      98.128.230.186:18888
      98.128.230.186

    最终只返回 IP，不返回端口。
    """
    s = line.strip()
    if not s:
        return None

    # 去掉末尾逗号
    if s.endswith(","):
        s = s[:-1].strip()

    # 去掉外层引号
    s = s.strip('"').strip("'").strip()

    if not s:
        return None

    # 提取 ip，忽略 :port
    m = re.fullmatch(r'(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?', s)
    if not m:
        return None

    return m.group(1)


def read_ip_targets(file_path: str):
    if not os.path.exists(file_path):
        return []

    targets = []
    with open(file_path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            ip = extract_ip_from_line(s)
            if not ip:
                print(f"[WARN ] skip invalid ip line {lineno}: {s}")
                continue

            targets.append(ip)

    return targets


# =========================
# 提取逻辑
# =========================
def extract_random_matches(peer_list):
    """
    只提取 localDisconnectReason == RANDOM_ELIMINATION 的项
    每项只保留:
      - connectTime
      - nodeId（仅域名模式分组时要用）
    """
    matches = []

    if not isinstance(peer_list, list):
        return matches

    for peer in peer_list:
        try:
            if peer.get("localDisconnectReason") == "RANDOM_ELIMINATION":
                matches.append({
                    "connectTime": peer.get("connectTime"),
                    "nodeId": peer.get("nodeId"),
                })
        except Exception:
            continue

    return matches


def query_target(target: str):
    url = build_url(target)

    try:
        print(f"[QUERY] {url}")
        resp = requests.get(url, timeout=TIMEOUT, verify=VERIFY_SSL)

        if resp.status_code != 200:
            print(f"[FAIL ] {url} status={resp.status_code}")
            return {
                "ok": False,
                "target": target,
                "url": url,
                "error": f"HTTP {resp.status_code}",
                "matches": [],
                "machineInfo": None,
            }

        data = resp.json()
        peer_list = data.get("peerList", [])
        matches = extract_random_matches(peer_list)
        machine_info = strip_machine_info(data.get("machineInfo"))

        print(f"[ OK  ] {url} random_count={len(matches)}")

        return {
            "ok": True,
            "target": target,
            "url": url,
            "error": None,
            "matches": matches,
            "machineInfo": machine_info,
        }

    except Exception as e:
        print(f"[ERR  ] {url} error={e}")
        return {
            "ok": False,
            "target": target,
            "url": url,
            "error": str(e),
            "matches": [],
            "machineInfo": None,
        }


# =========================
# 落盘逻辑
# =========================
def save_ip_result(ip: str, result: dict):
    """
    IP 模式:
      OUTPUT_ROOT/ip/<ip>/<timestamp>.json

    文件内容只保留:
      - matchCount
      - matches: [{connectTime}, ...]
      - machineInfo（不含 memoryDescInfoList）
    """
    matches = result["matches"]
    if not matches:
        return

    ip_dir = os.path.join(OUTPUT_ROOT, "ip", sanitize_filename(ip))
    ensure_dir(ip_dir)

    ts = utc_now_str()
    file_path = os.path.join(ip_dir, f"{ts}.json")

    simplified_matches = []
    for m in matches:
        if m.get("connectTime") is not None:
            simplified_matches.append({
                "connectTime": m["connectTime"]
            })

    payload = {
        "matchCount": len(simplified_matches),
        "matches": simplified_matches,
        "machineInfo": result["machineInfo"],
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"[SAVE ] {file_path}")


def save_domain_result(domain: str, result: dict):
    """
    域名模式:
      OUTPUT_ROOT/domain/<domain>/<nodeId>/<timestamp>.json

    文件内容只保留:
      - matchCount
      - matches: [{connectTime}, ...]
      - machineInfo（不含 memoryDescInfoList）

    按 nodeId 分目录
    """
    matches = result["matches"]
    if not matches:
        return

    domain_dir = os.path.join(OUTPUT_ROOT, "domain", sanitize_filename(domain))
    ensure_dir(domain_dir)

    ts = utc_now_str()

    grouped = {}
    for m in matches:
        node_id = m.get("nodeId")
        if not node_id:
            continue
        grouped.setdefault(node_id, []).append(m)

    for node_id, items in grouped.items():
        node_dir = os.path.join(domain_dir, sanitize_filename(node_id))
        ensure_dir(node_dir)

        file_path = os.path.join(node_dir, f"{ts}.json")

        simplified_matches = []
        for x in items:
            if x.get("connectTime") is not None:
                simplified_matches.append({
                    "connectTime": x["connectTime"]
                })

        payload = {
            "matchCount": len(simplified_matches),
            "matches": simplified_matches,
            "machineInfo": result["machineInfo"],
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        print(f"[SAVE ] {file_path}")


# =========================
# 调度逻辑
# =========================
def process_single_ip(ip: str):
    result = query_target(ip)
    if result["ok"] and result["matches"]:
        save_ip_result(ip, result)


def process_single_domain(domain: str):
    result = query_target(domain)
    if result["ok"] and result["matches"]:
        save_domain_result(domain, result)


def run_ip_batch_once():
    ips = read_ip_targets(IP_INPUT_FILE)
    if not ips:
        print("[INFO ] no ip targets found")
        return

    print(f"[INFO ] start ip batch, count={len(ips)}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_single_ip, ip) for ip in ips]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"[WARN ] ip task error: {e}")

    print("[INFO ] ip batch done")


def ip_scheduler_loop():
    while True:
        try:
            run_ip_batch_once()
        except Exception as e:
            print(f"[ERROR] ip scheduler loop error: {e}")

        print(f"[INFO ] sleep {IP_SCAN_INTERVAL_SECONDS}s for next ip batch")
        time.sleep(IP_SCAN_INTERVAL_SECONDS)


def domain_scheduler_loop(domain: str, interval_sec: int):
    while True:
        try:
            process_single_domain(domain)
        except Exception as e:
            print(f"[ERROR] domain={domain} error={e}")

        print(f"[INFO ] domain={domain} sleep {interval_sec}s")
        time.sleep(interval_sec)


# =========================
# main
# =========================
def main():
    ensure_dir(OUTPUT_ROOT)

    ip_thread = threading.Thread(target=ip_scheduler_loop, daemon=True)
    ip_thread.start()

    domain_targets = read_domain_targets(DOMAIN_INPUT_FILE)
    domain_threads = []

    for item in domain_targets:
        domain = item["domain"]
        interval_sec = item["interval_sec"]

        t = threading.Thread(
            target=domain_scheduler_loop,
            args=(domain, interval_sec),
            daemon=True
        )
        t.start()
        domain_threads.append(t)

        print(f"[INFO ] started domain scheduler: domain={domain}, interval={interval_sec}s")

    print("[INFO ] all schedulers started")

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()