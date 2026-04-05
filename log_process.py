#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import gzip
import os
import re
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

IP_PART = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
IP_RE_STR = rf'(?:{IP_PART}\.){{3}}{IP_PART}'

TIME_RE = re.compile(r'^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(.*)$')
INV_RE = re.compile(rf'^INV\s+({IP_RE_STR})\s+(\d+)\s*$')
TX_RE = re.compile(rf'^({IP_RE_STR})\s+([0-9a-fA-F]{{32,128}})\s*$')
IP_LIST_RE = re.compile(rf'^{IP_RE_STR}(?:,{IP_RE_STR})+(?:\s.*)?$')

ROTATED_RE = re.compile(r'^stdout-(\d{4}-\d{2}-\d{2})\.(\d+)\.log(?:\.gz)?$')
CURRENT_RE = re.compile(r'^stdout\.log(?:\.gz)?$')


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Merge java-tron stdout logs from local and remote folders by tx hash.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--local-dir", required=True, help="本地日志目录")
    parser.add_argument("--remote-dir", required=True, help="远程同步下来的日志目录")
    parser.add_argument("--output-dir", required=True, help="输出目录")
    parser.add_argument("--part-size-mb", type=int, default=100, help="每个输出分片大小(MB)")
    parser.add_argument("--db-path", default=None, help="中间 SQLite 数据库路径；默认放在 output-dir 下")
    return parser.parse_args()


def get_file_date_and_order(path: Path):
    name = path.name
    m = ROTATED_RE.match(name)
    if m:
        return m.group(1), int(m.group(2)), False

    if CURRENT_RE.match(name):
        # 当前 stdout.log 没有日期，只能按 mtime 推断
        dt = datetime.fromtimestamp(path.stat().st_mtime)
        return dt.strftime("%Y-%m-%d"), 10**9, True

    return None, None, None


def discover_log_files(folder: Path):
    files = []
    for p in folder.iterdir():
        if not p.is_file():
            continue
        date_str, order_idx, is_current = get_file_date_and_order(p)
        if date_str is None:
            continue
        files.append((date_str, order_idx, 1 if is_current else 0, p))

    files.sort(key=lambda x: (x[0], x[1], x[2], x[3].name))
    return files


def open_text_maybe_gz(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    cur.execute("PRAGMA temp_store=MEMORY;")
    cur.execute("PRAGMA cache_size=-200000;")  # 约 200MB cache

    cur.execute("""
        CREATE TABLE IF NOT EXISTS records (
            tx_hash   TEXT NOT NULL,
            ts_sort   TEXT NOT NULL,
            peer_ip   TEXT NOT NULL,
            inv_size  INTEGER NOT NULL
        );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_records_tx_ts ON records(tx_hash, ts_sort);")
    conn.commit()


def flush_batch(conn: sqlite3.Connection, batch):
    if not batch:
        return
    conn.executemany(
        "INSERT INTO records(tx_hash, ts_sort, peer_ip, inv_size) VALUES (?, ?, ?, ?)",
        batch
    )
    conn.commit()
    batch.clear()


def process_folder(conn: sqlite3.Connection, folder: Path, source_name: str):
    files = discover_log_files(folder)
    if not files:
        eprint(f"[WARN] {source_name} 目录没有发现可解析日志: {folder}")
        return

    eprint(f"[INFO] 开始处理 {source_name}: {folder}")
    eprint(f"[INFO] {source_name} 共发现 {len(files)} 个日志文件")

    stats = {
        "inv_lines": 0,
        "tx_lines_matched": 0,
        "tx_lines_unmatched": 0,
        "ignored_iplist_lines": 0,
        "ignored_other_lines": 0,
        "bad_lines": 0,
    }

    # 关键逻辑：
    # 每个来源目录分别维护：peer_ip -> 最近一条 INV 的 size
    # 交易哈希行出现时，绑定到该来源目录中、该 peer_ip 最近出现的 INV。
    last_inv_by_peer = {}

    batch = []
    batch_size = 10000

    for date_str, _, is_current, path in files:
        if is_current:
            eprint(f"[INFO] {source_name} 使用 mtime 推断当前文件日期: {path.name} -> {date_str}")

        with open_text_maybe_gz(path) as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")
                m = TIME_RE.match(line)
                if not m:
                    stats["bad_lines"] += 1
                    continue

                time_str = m.group(1)
                rest = m.group(2).strip()

                # 忽略以大量 IP 列表开头的行
                if IP_LIST_RE.match(rest):
                    stats["ignored_iplist_lines"] += 1
                    continue

                inv_m = INV_RE.match(rest)
                if inv_m:
                    peer_ip = inv_m.group(1)
                    inv_size = int(inv_m.group(2))
                    last_inv_by_peer[peer_ip] = inv_size
                    stats["inv_lines"] += 1
                    continue

                tx_m = TX_RE.match(rest)
                if tx_m:
                    peer_ip = tx_m.group(1)
                    tx_hash = tx_m.group(2).lower()

                    inv_size = last_inv_by_peer.get(peer_ip)
                    if inv_size is None:
                        stats["tx_lines_unmatched"] += 1
                        continue

                    full_ts = f"{date_str} {time_str}"
                    batch.append((tx_hash, full_ts, peer_ip, inv_size))
                    stats["tx_lines_matched"] += 1

                    if len(batch) >= batch_size:
                        flush_batch(conn, batch)
                    continue

                stats["ignored_other_lines"] += 1

    flush_batch(conn, batch)

    eprint(
        f"[INFO] {source_name} 处理完成 | "
        f"INV={stats['inv_lines']} | "
        f"TX匹配={stats['tx_lines_matched']} | "
        f"TX未匹配={stats['tx_lines_unmatched']} | "
        f"忽略IP列表={stats['ignored_iplist_lines']} | "
        f"其他忽略={stats['ignored_other_lines']} | "
        f"坏行={stats['bad_lines']}"
    )


def build_first_seen_table(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS tx_first_seen;")
    cur.execute("""
        CREATE TABLE tx_first_seen AS
        SELECT tx_hash, MIN(ts_sort) AS first_seen
        FROM records
        GROUP BY tx_hash;
    """)
    cur.execute("CREATE INDEX idx_tx_first_seen ON tx_first_seen(first_seen, tx_hash);")
    conn.commit()


class SplitWriter:
    def __init__(self, output_dir: Path, limit_bytes: int):
        self.output_dir = output_dir
        self.limit_bytes = limit_bytes
        self.part_no = 0
        self.cur_fp = None
        self.cur_path = None
        self.cur_size = 0
        self.generated_files = []

    def _open_new(self):
        self.part_no += 1
        self.cur_path = self.output_dir / f"merged_tx_blocks.part{self.part_no:04d}.txt"
        self.cur_fp = open(self.cur_path, "w", encoding="utf-8", newline="")
        self.cur_size = 0
        self.generated_files.append(self.cur_path)

    def write_block(self, block_text: str):
        if self.cur_fp is None:
            self._open_new()

        data = block_text.encode("utf-8")
        if self.cur_size > 0 and (self.cur_size + len(data) > self.limit_bytes):
            self.cur_fp.close()
            self._open_new()

        self.cur_fp.write(block_text)
        self.cur_size += len(data)

    def close(self):
        if self.cur_fp is not None:
            self.cur_fp.close()
            self.cur_fp = None


def export_blocks(conn: sqlite3.Connection, output_dir: Path, part_size_mb: int):
    output_dir.mkdir(parents=True, exist_ok=True)
    writer = SplitWriter(output_dir, part_size_mb * 1024 * 1024)

    query = """
        SELECT r.tx_hash, r.ts_sort, r.peer_ip, r.inv_size
        FROM records r
        JOIN tx_first_seen f
          ON r.tx_hash = f.tx_hash
        ORDER BY f.first_seen, r.tx_hash, r.ts_sort, r.rowid;
    """

    cur = conn.cursor()
    cur.execute(query)

    current_tx = None
    current_lines = []

    block_count = 0
    row_count = 0

    def flush_current():
        nonlocal block_count
        if current_tx is None:
            return
        block_text = current_tx + "\n" + "".join(current_lines) + ".\n"
        writer.write_block(block_text)
        block_count += 1

    for tx_hash, ts_sort, peer_ip, inv_size in cur:
        row_count += 1
        if current_tx is None:
            current_tx = tx_hash

        if tx_hash != current_tx:
            flush_current()
            current_tx = tx_hash
            current_lines = []

        current_lines.append(f"{ts_sort} {peer_ip} {inv_size}\n")

    if current_tx is not None:
        flush_current()

    writer.close()

    eprint(f"[INFO] 导出完成 | 交易块数={block_count} | 记录数={row_count}")
    eprint("[INFO] 输出文件：")
    for p in writer.generated_files:
        eprint(f"  - {p} ({p.stat().st_size} bytes)")


def main():
    args = parse_args()

    local_dir = Path(args.local_dir)
    remote_dir = Path(args.remote_dir)
    output_dir = Path(args.output_dir)

    if not local_dir.is_dir():
        raise SystemExit(f"本地目录不存在: {local_dir}")
    if not remote_dir.is_dir():
        raise SystemExit(f"远程目录不存在: {remote_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = Path(args.db_path) if args.db_path else (output_dir / "merge_tron_tx_logs.sqlite")

    eprint(f"[INFO] SQLite 中间库: {db_path}")

    conn = sqlite3.connect(str(db_path))
    try:
        init_db(conn)
        process_folder(conn, local_dir, "local")
        process_folder(conn, remote_dir, "remote")
        build_first_seen_table(conn)
        export_blocks(conn, output_dir, args.part_size_mb)
    finally:
        conn.close()

    eprint("[INFO] 全部完成")


if __name__ == "__main__":
    main()