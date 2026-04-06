#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import gzip
import argparse
from pathlib import Path
from typing import Iterator, Tuple, List


IP_PATTERN = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)

IP_LINE_PATTERN = re.compile(
    r'^(?P<ts>(?:\d{4}-\d{2}-\d{2}\s+)?\d{2}:\d{2}:\d{2}\.\d{3})\s+ip\s+(?P<body>.*)$'
)


def open_text_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")

LOG_NAME_PATTERN = re.compile(
    r'^stdout-(\d{4}-\d{2}-\d{2})\.(\d+)\.log(?:\.gz)?$'
)


def parse_log_sort_key(path: Path):
    """
    解析类似：
      stdout-2026-04-06.28.log.gz
      stdout-2026-04-06.28.log
    返回排序 key: (date_str, seq_int, filename)
    """
    m = LOG_NAME_PATTERN.match(path.name)
    if m:
        date_str = m.group(1)
        seq = int(m.group(2))
        return (0, date_str, seq, path.name)

    # 不匹配标准命名的文件放后面，按文件名排序
    return (1, "", 0, path.name)

def collect_input_files(input_dir: Path, include_latest_plain: bool = False) -> List[Path]:
    all_files = [p for p in input_dir.iterdir() if p.is_file()]

    gz_files = [p for p in all_files if p.suffix == ".gz"]
    plain_files = [p for p in all_files if p.suffix != ".gz"]

    if plain_files and not include_latest_plain:
        latest_plain = max(plain_files, key=lambda p: p.stat().st_mtime)
        plain_files = [p for p in plain_files if p != latest_plain]
        print(f"[INFO] 已忽略最新未压缩日志: {latest_plain.name}")

    files = gz_files + plain_files
    files.sort(key=parse_log_sort_key)
    return files


def parse_ip_line(line: str) -> Tuple[str, str] | None:
    m = IP_LINE_PATTERN.match(line.strip())
    if not m:
        return None

    timestamp = m.group("ts")
    body = m.group("body")

    ips = IP_PATTERN.findall(body)
    if not ips:
        return None

    ip_list_str = ",".join(ips)
    return timestamp, ip_list_str


def extract_from_file(path: Path) -> Iterator[Tuple[str, str]]:
    with open_text_file(path) as f:
        for line in f:
            parsed = parse_ip_line(line)
            if parsed is None:
                continue
            yield parsed


def main():
    parser = argparse.ArgumentParser(
        description="从日志目录中提取所有 'ip' 定时输出行，整理为每个时间点一行。"
    )
    parser.add_argument("input_dir", help="输入日志目录")
    parser.add_argument("output_file", help="输出文件路径")
    parser.add_argument(
        "--include-latest-plain",
        action="store_true",
        help="包含最新未压缩日志（默认忽略，因为它通常仍在持续写入）"
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output_file)

    if not input_dir.is_dir():
        raise NotADirectoryError(f"输入路径不是目录: {input_dir}")

    files = collect_input_files(
        input_dir=input_dir,
        include_latest_plain=args.include_latest_plain
    )

    if not files:
        print("[WARN] 没有找到可处理的日志文件")
        return

    file_count = 0
    record_count = 0

    with open(output_file, "w", encoding="utf-8") as fout:
        fout.write("timestamp\tneighbors\n")

        for path in files:
            file_count += 1
            current_count = 0

            for timestamp, ip_list_str in extract_from_file(path):
                fout.write(f"{timestamp}\t{ip_list_str}\n")
                current_count += 1
                record_count += 1

            print(f"[OK] {path.name}: 提取 {current_count} 条")

    print()
    print(f"处理完成")
    print(f"文件数: {file_count}")
    print(f"总记录数: {record_count}")
    print(f"输出文件: {output_file}")


if __name__ == "__main__":
    main()