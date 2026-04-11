import os
import re
import json
import time
from typing import Dict, Optional, Tuple

# =========================
# 配置
# =========================
CONFIG = {
    # 之前监控脚本的输出根目录
    "output_root": r"./tron_monitor_output",

    # 要修改的已有 config.conf
    "config_conf_path": r"/root/java-tron-listen/config.conf",

    # 是否扫描 IP 输出
    "enable_ip_scan": True,

    # 是否扫描域名输出
    "enable_domain_scan": True,

    # IP 端口映射文件，每行: ip;port
    # 为空或文件不存在时，对所有 IP 默认使用 18888
    "ip_port_file": r"ip_port.txt",

    # nodeId -> ip,port 映射文件，每行: nodeid,ip,port
    "nodeid_mapping_file": r"nodeid_ip_port.txt",

    # 默认端口
    "default_port": 18888,

    # 执行周期（秒）
    "interval_seconds": 60,

    # 是否按“仅增大”方式更新 value
    # True: 只有新值 > 旧值时才更新
    # False: 直接覆盖
    "only_update_if_greater": True,
}


# =========================
# 基础工具
# =========================
def log_info(msg: str):
    print(f"[INFO ] {msg}")


def log_warn(msg: str):
    print(f"[WARN ] {msg}")


def log_error(msg: str):
    print(f"[ERROR] {msg}")


def log_skip(msg: str):
    print(f"[SKIP ] {msg}")


def safe_read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def safe_write_text(path: str, content: str):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def safe_read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_warn(f"read json failed: {path}, err={e}")
        return None


def is_json_file(name: str) -> bool:
    return name.lower().endswith(".json")


def get_latest_json_file_by_name(folder: str) -> Optional[str]:
    """
    按文件名字典序选最新。
    因为你的文件名是 UTC 时间戳格式，如 20260330T210000Z.json
    所以字典序即可表示时间先后。
    """
    if not os.path.isdir(folder):
        return None

    files = [x for x in os.listdir(folder) if is_json_file(x)]
    if not files:
        return None

    files.sort()
    return os.path.join(folder, files[-1])


def get_max_connect_time_from_json_file(path: str) -> Optional[int]:
    """
    JSON 格式来自你前一个脚本：
    {
      "matchCount": 3,
      "matches": [
        {"connectTime": 1774673055575},
        ...
      ],
      "machineInfo": {...}
    }
    """
    data = safe_read_json(path)
    if not isinstance(data, dict):
        return None

    matches = data.get("matches")
    if not isinstance(matches, list):
        return None

    connect_times = []
    for item in matches:
        if isinstance(item, dict):
            ct = item.get("connectTime")
            if isinstance(ct, int):
                connect_times.append(ct)

    if not connect_times:
        return None

    return max(connect_times)


# =========================
# 读取映射文件
# =========================
def load_ip_port_mapping(path: str) -> Dict[str, int]:
    """
    每行格式:
      ip;port
    """
    result: Dict[str, int] = {}

    if not path or not os.path.exists(path):
        log_warn(f"ip_port_file not found, will use default port for all IPs: {path}")
        return result

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            parts = [x.strip() for x in s.split(";")]
            if len(parts) != 2:
                log_warn(f"invalid ip_port line {lineno}: {s}")
                continue

            ip, port_str = parts
            try:
                port = int(port_str)
            except ValueError:
                log_warn(f"invalid port at line {lineno}: {s}")
                continue

            result[ip] = port

    return result


def load_nodeid_mapping(path: str) -> Dict[str, Tuple[str, int]]:
    """
    每行格式:
      nodeid,ip,port
    """
    result: Dict[str, Tuple[str, int]] = {}

    if not path or not os.path.exists(path):
        log_warn(f"nodeid_mapping_file not found: {path}")
        return result

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            parts = [x.strip() for x in s.split(",")]
            if len(parts) != 3:
                log_warn(f"invalid nodeid mapping line {lineno}: {s}")
                continue

            nodeid, ip, port_str = parts
            try:
                port = int(port_str)
            except ValueError:
                log_warn(f"invalid port at line {lineno}: {s}")
                continue

            result[nodeid] = (ip, port)

    return result


# =========================
# 扫描输出目录，生成 address -> connectTime
# =========================
def collect_updates_from_ip(output_root: str, ip_port_map: Dict[str, int], default_port: int) -> Dict[str, int]:
    updates: Dict[str, int] = {}
    ip_root = os.path.join(output_root, "ip")

    if not os.path.isdir(ip_root):
        log_warn(f"ip output dir not found: {ip_root}")
        return updates

    for ip in os.listdir(ip_root):
        ip_dir = os.path.join(ip_root, ip)
        if not os.path.isdir(ip_dir):
            continue

        latest_file = get_latest_json_file_by_name(ip_dir)
        if not latest_file:
            continue

        max_ct = get_max_connect_time_from_json_file(latest_file)
        if max_ct is None:
            continue

        port = ip_port_map.get(ip, default_port)
        address = f"{ip}:{port}"

        prev = updates.get(address)
        if prev is None or max_ct > prev:
            updates[address] = max_ct

        log_info(f"IP update candidate: {address} -> {max_ct} from {os.path.basename(latest_file)}")

    return updates


def collect_updates_from_domain(output_root: str, nodeid_map: Dict[str, Tuple[str, int]]) -> Dict[str, int]:
    updates: Dict[str, int] = {}
    domain_root = os.path.join(output_root, "domain")

    if not os.path.isdir(domain_root):
        log_warn(f"domain output dir not found: {domain_root}")
        return updates

    for domain in os.listdir(domain_root):
        domain_dir = os.path.join(domain_root, domain)
        if not os.path.isdir(domain_dir):
            continue

        for nodeid in os.listdir(domain_dir):
            nodeid_dir = os.path.join(domain_dir, nodeid)
            if not os.path.isdir(nodeid_dir):
                continue

            latest_file = get_latest_json_file_by_name(nodeid_dir)
            if not latest_file:
                continue

            max_ct = get_max_connect_time_from_json_file(latest_file)
            if max_ct is None:
                continue

            mapping = nodeid_map.get(nodeid)
            if mapping is None:
                log_skip(f"NO NODEID MAPPING: domain={domain}, nodeId={nodeid}, latest={latest_file}")
                continue

            ip, port = mapping
            address = f"{ip}:{port}"

            prev = updates.get(address)
            if prev is None or max_ct > prev:
                updates[address] = max_ct

            log_info(f"Domain update candidate: nodeId={nodeid}, address={address}, value={max_ct}")

    return updates


# =========================
# 解析和更新 config.conf 中的 node.myAddressTimeMap
# =========================
ENTRY_PATTERN = re.compile(
    r'''
    \{
        \s*address\s*=\s*"(?P<address>[^"]+)"
        \s*value\s*=\s*(?P<value>\d+)
        \s*
    \}
    ''',
    re.VERBOSE | re.DOTALL
)

BLOCK_PATTERN = re.compile(
    r'(?P<prefix>\bnode\.myAddressTimeMap\s*=\s*\[)(?P<body>.*?)(?P<suffix>\])',
    re.DOTALL
)


def parse_existing_entries(block_body: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for m in ENTRY_PATTERN.finditer(block_body):
        address = m.group("address")
        value = int(m.group("value"))
        result[address] = value
    return result


def render_entries(entries: Dict[str, int]) -> str:
    """
    统一渲染为:
      {
        address = "ip:port"
        value = 123
      },
    """
    lines = []
    for address in sorted(entries.keys()):
        value = entries[address]
        lines.append("  {")
        lines.append(f'    address = "{address}"')
        lines.append(f"    value = {value}")
        lines.append("  },")
        lines.append("")
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def update_config_my_address_time_map(
    config_text: str,
    new_updates: Dict[str, int],
    only_update_if_greater: bool
) -> str:
    m = BLOCK_PATTERN.search(config_text)
    if not m:
        raise ValueError("Cannot find 'node.myAddressTimeMap = [ ... ]' block in config file")

    old_body = m.group("body")
    existing = parse_existing_entries(old_body)

    for address, new_value in new_updates.items():
        old_value = existing.get(address)
        if old_value is None:
            existing[address] = new_value
            log_info(f"ADD    {address} -> {new_value}")
        else:
            if only_update_if_greater:
                if new_value > old_value:
                    existing[address] = new_value
                    log_info(f"UPDATE {address}: {old_value} -> {new_value}")
                else:
                    log_info(f"KEEP   {address}: existing={old_value}, new={new_value}")
            else:
                existing[address] = new_value
                log_info(f"UPDATE {address}: {old_value} -> {new_value}")

    new_body = "\n" + render_entries(existing)
    replacement = f"{m.group('prefix')}{new_body}]"

    return config_text[:m.start()] + replacement + config_text[m.end():]


# =========================
# 单次执行
# =========================
def run_once():
    output_root = CONFIG["output_root"]
    config_conf_path = CONFIG["config_conf_path"]
    enable_ip_scan = CONFIG["enable_ip_scan"]
    enable_domain_scan = CONFIG["enable_domain_scan"]
    default_port = CONFIG["default_port"]
    only_update_if_greater = CONFIG["only_update_if_greater"]

    ip_port_map = load_ip_port_mapping(CONFIG["ip_port_file"])
    nodeid_map = load_nodeid_mapping(CONFIG["nodeid_mapping_file"])

    updates: Dict[str, int] = {}

    if enable_ip_scan:
        ip_updates = collect_updates_from_ip(output_root, ip_port_map, default_port)
        for k, v in ip_updates.items():
            old = updates.get(k)
            if old is None or v > old:
                updates[k] = v

    if enable_domain_scan:
        domain_updates = collect_updates_from_domain(output_root, nodeid_map)
        for k, v in domain_updates.items():
            old = updates.get(k)
            if old is None or v > old:
                updates[k] = v

    if not updates:
        log_info("No updates collected in this round")
        return

    config_text = safe_read_text(config_conf_path)
    new_text = update_config_my_address_time_map(
        config_text=config_text,
        new_updates=updates,
        only_update_if_greater=only_update_if_greater
    )

    safe_write_text(config_conf_path, new_text)
    log_info(f"config updated: {config_conf_path}")


# =========================
# 主循环
# =========================
def main():
    interval = int(CONFIG["interval_seconds"])
    log_info(f"Updater started, interval={interval}s")

    while True:
        try:
            run_once()
        except Exception as e:
            log_error(f"run_once failed: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    main()
