#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import argparse
from datetime import datetime, date, time, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional

IP_PATTERN = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)


def parse_line(line: str) -> Optional[Tuple[str, str]]:
    """
    支持两种格式：
    1) timestamp<TAB>neighbors
    2) timestamp,neighbors   （只在第一个逗号处分割）
    """
    line = line.strip()
    if not line:
        return None

    if "\t" in line:
        ts, neighbors = line.split("\t", 1)
    elif "," in line:
        ts, neighbors = line.split(",", 1)
    else:
        return None

    ts = ts.strip()
    neighbors = neighbors.strip()

    if ts.lower() == "timestamp":
        return None

    return ts, neighbors


def parse_timestamp_series(ts_list: List[str]) -> List[datetime]:
    """
    支持：
    1) YYYY-MM-DD HH:MM:SS.mmm
    2) HH:MM:SS.mmm

    对于只有时分秒的情况：
    - 默认从一个虚拟日期开始
    - 如果后一个时间小于前一个时间，视为跨天，日期 +1
    """
    results: List[datetime] = []

    has_full_date = any(len(ts) >= 23 and "-" in ts[:10] for ts in ts_list)

    if has_full_date:
        for ts in ts_list:
            ts = ts.strip()
            try:
                results.append(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f"))
            except ValueError:
                # 兼容没有毫秒的情况
                results.append(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S"))
        return results

    # 仅有时间
    base_day = date(2000, 1, 1)
    day_offset = 0
    prev_t: Optional[time] = None

    for ts in ts_list:
        ts = ts.strip()
        try:
            t = datetime.strptime(ts, "%H:%M:%S.%f").time()
        except ValueError:
            t = datetime.strptime(ts, "%H:%M:%S").time()

        if prev_t is not None and t < prev_t:
            day_offset += 1

        dt = datetime.combine(base_day + timedelta(days=day_offset), t)
        results.append(dt)
        prev_t = t

    return results


def format_seconds(seconds: float) -> str:
    seconds = float(seconds)
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)

    ms = int(round((seconds - int(seconds)) * 1000))
    total = int(seconds)

    h = total // 3600
    m = (total % 3600) // 60
    s = total % 60

    if ms == 1000:
        s += 1
        ms = 0
    if s == 60:
        m += 1
        s = 0
    if m == 60:
        h += 1
        m = 0

    return f"{sign}{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


def midpoint(t1: datetime, t2: datetime) -> datetime:
    return t1 + (t2 - t1) / 2


def load_snapshots(file_path: Path) -> List[Dict]:
    raw_rows = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            parsed = parse_line(line)
            if parsed is None:
                continue
            ts_str, neighbors_str = parsed
            neighbors = set(IP_PATTERN.findall(neighbors_str))
            raw_rows.append({
                "line_no": line_no,
                "ts_str": ts_str,
                "neighbors": neighbors,
            })

    if not raw_rows:
        return []

    dt_list = parse_timestamp_series([row["ts_str"] for row in raw_rows])

    snapshots = []
    for row, dt in zip(raw_rows, dt_list):
        snapshots.append({
            "line_no": row["line_no"],
            "ts_str": row["ts_str"],
            "dt": dt,
            "neighbors": row["neighbors"],
        })

    return snapshots


def analyze_ip(snapshots: List[Dict], target_ip: str):
    if not snapshots:
        return [], []

    present = [target_ip in snap["neighbors"] for snap in snapshots]
    n = len(snapshots)

    sessions = []
    i = 0
    while i < n:
        if not present[i]:
            i += 1
            continue

        start_idx = i
        while i + 1 < n and present[i + 1]:
            i += 1
        end_idx = i

        # 忽略没有前文或后文的连接段
        if start_idx == 0 or end_idx == n - 1:
            i += 1
            continue

        prev_absent_idx = start_idx - 1
        next_absent_idx = end_idx + 1

        start_est = midpoint(snapshots[prev_absent_idx]["dt"], snapshots[start_idx]["dt"])
        end_est = midpoint(snapshots[end_idx]["dt"], snapshots[next_absent_idx]["dt"])
        duration = (end_est - start_est).total_seconds()

        sessions.append({
            "start_idx": start_idx,
            "end_idx": end_idx,
            "first_seen": snapshots[start_idx]["ts_str"],
            "last_seen": snapshots[end_idx]["ts_str"],
            "start_est": start_est,
            "end_est": end_est,
            "duration_sec": duration,
        })

        i += 1

    downtimes = []
    for k in range(len(sessions) - 1):
        cur = sessions[k]
        nxt = sessions[k + 1]

        gap = (nxt["start_est"] - cur["end_est"]).total_seconds()
        downtimes.append({
            "from_disconnect": cur["end_est"],
            "to_reconnect": nxt["start_est"],
            "duration_sec": gap,
            "prev_last_seen": cur["last_seen"],
            "next_first_seen": nxt["first_seen"],
        })

    return sessions, downtimes


def print_report(target_ip: str, sessions: List[Dict], downtimes: List[Dict]):
    print(f"目标 IP: {target_ip}")
    print()

    if not sessions:
        print("没有找到可分析的完整连接段。")
        print("可能原因：")
        print("1. 这个 IP 从未出现过")
        print("2. 只出现了文件开头/结尾的残缺连接段，按要求被忽略了")
        return

    total_connected = sum(x["duration_sec"] for x in sessions)
    avg_connected = total_connected / len(sessions)

    print("=== 连接段统计 ===")
    print(f"完整连接段数量: {len(sessions)}")
    print(f"总连接时长: {format_seconds(total_connected)} ({total_connected:.3f} 秒)")
    print(f"平均每次连接时长: {format_seconds(avg_connected)} ({avg_connected:.3f} 秒)")
    print()

    for idx, s in enumerate(sessions, 1):
        print(
            f"[连接段 {idx}] "
            f"首次观测到连接={s['first_seen']} | "
            f"最后一次观测到连接={s['last_seen']} | "
            f"估计持续={format_seconds(s['duration_sec'])} ({s['duration_sec']:.3f} 秒)"
        )

    print()
    print("=== 断连后到下次重连统计 ===")

    if downtimes:
        total_down = sum(x["duration_sec"] for x in downtimes)
        avg_down = total_down / len(downtimes)
        print(f"断连区间数量: {len(downtimes)}")
        print(f"平均断连时长: {format_seconds(avg_down)} ({avg_down:.3f} 秒)")
        print()

        for idx, d in enumerate(downtimes, 1):
            print(
                f"[断连段 {idx}] "
                f"上次连接末次观测={d['prev_last_seen']} | "
                f"下次连接首次观测={d['next_first_seen']} | "
                f"估计断连持续={format_seconds(d['duration_sec'])} ({d['duration_sec']:.3f} 秒)"
            )
    else:
        print("没有可分析的断连后重连区间。")
        print("通常表示只有 1 段完整连接，无法形成“断开再重连”的间隔。")


def main():
    parser = argparse.ArgumentParser(
        description="分析 output_nodes.csv 中某个 IP 的连接持续时间与断连间隔"
    )
    parser.add_argument("input_file", help="例如 output_nodes.csv")
    parser.add_argument("target_ip", help="要分析的目标 IP")
    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在: {input_path}")

    snapshots = load_snapshots(input_path)
    sessions, downtimes = analyze_ip(snapshots, args.target_ip)
    print_report(args.target_ip, sessions, downtimes)


if __name__ == "__main__":
    main()