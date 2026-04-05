#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
高性能版本：解析本地与远程 java-tron stdout 日志，按交易哈希聚合输出。

核心思路：
1. 不再使用 SQLite。
2. 解析阶段按 tx_hash 前缀分桶落盘（bucket）。
3. 排序阶段使用系统 sort 做外排序。
4. 导出阶段按 tx_hash 聚合为文本块，并按文件大小切分。
5. 解析阶段支持“文件级断点续跑”：
   - 每个 source(local/remote) 严格按时间顺序处理文件。
   - 每处理完一个文件，就原子化保存 progress.json，记录：
       * 已完成文件前缀 completed_keys
       * 当前 last_inv_by_peer 状态
   - 下次启动时，如果已完成前缀未变化，则从断点继续。

输出块格式：
TX_HASH
YYYY-MM-DD HH:MM:SS.mmm ip inv_size
YYYY-MM-DD HH:MM:SS.mmm ip inv_size
.

注意：
- 块内记录按时间排序。
- 块之间的全局顺序为 bucket 顺序 + tx_hash 顺序，不保证按“全局首次出现时间”排序。
- 这是为了换取更高吞吐。
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# -----------------------------
# 基础工具
# -----------------------------

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding=encoding) as f:
        f.write(text)
    os.replace(tmp, path)


@dataclass(frozen=True)
class FileMeta:
    source: str                  # local / remote
    path: Path
    date_str: str                # 从文件名或 mtime 推出的日期
    order_idx: int               # 轮转序号；stdout.log 用很大值
    is_current: bool             # 是否 stdout.log / stdout.log.gz
    size: int
    mtime_ns: int
    file_key: str                # 用于断点续跑校验


def make_file_key(path: Path, size: int, mtime_ns: int) -> str:
    raw = f"{path.resolve()}|{size}|{mtime_ns}".encode("utf-8", errors="replace")
    return hashlib.sha1(raw).hexdigest()[:24]


def safe_stem(path: Path) -> str:
    # 用于生成更可读的 shard 文件名
    name = path.name.replace(os.sep, "_")
    return name.replace(" ", "_")


# -----------------------------
# 文件发现与排序
# -----------------------------

def get_file_date_and_order(path: Path) -> Tuple[Optional[str], Optional[int], Optional[bool]]:
    """
    支持：
      stdout-2026-04-04.35.log
      stdout-2026-04-04.35.log.gz
      stdout.log
      stdout.log.gz
    """
    name = path.name

    if name.startswith("stdout-") and ".log" in name:
        # 形如 stdout-YYYY-MM-DD.N.log(.gz)
        # 尽量不用 regex，减少开销
        try:
            # 去掉开头 stdout-
            rest = name[len("stdout-"):]
            # 拆成 YYYY-MM-DD.N.log(.gz)
            first_dot = rest.find(".")
            if first_dot == -1:
                return None, None, None
            date_str = rest[:first_dot]
            remain = rest[first_dot + 1:]
            second_dot = remain.find(".")
            if second_dot == -1:
                return None, None, None
            order_str = remain[:second_dot]
            order_idx = int(order_str)
            # 简单校验日期长度
            if len(date_str) != 10 or date_str[4] != "-" or date_str[7] != "-":
                return None, None, None
            return date_str, order_idx, False
        except Exception:
            return None, None, None

    if name == "stdout.log" or name == "stdout.log.gz":
        dt = time.localtime(path.stat().st_mtime)
        date_str = time.strftime("%Y-%m-%d", dt)
        return date_str, 10**9, True

    return None, None, None


def discover_log_files(folder: Path, source: str) -> List[FileMeta]:
    metas: List[FileMeta] = []
    for p in folder.iterdir():
        if not p.is_file():
            continue
        date_str, order_idx, is_current = get_file_date_and_order(p)
        if date_str is None:
            continue
        st = p.stat()
        metas.append(
            FileMeta(
                source=source,
                path=p,
                date_str=date_str,
                order_idx=order_idx,
                is_current=is_current,
                size=st.st_size,
                mtime_ns=st.st_mtime_ns,
                file_key=make_file_key(p, st.st_size, st.st_mtime_ns),
            )
        )
    metas.sort(key=lambda m: (m.date_str, m.order_idx, m.path.name))
    return metas


# -----------------------------
# 快速解析辅助
# -----------------------------

@lru_cache(maxsize=65536)
def is_ipv4(text: str) -> bool:
    parts = text.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p or not p.isdigit():
            return False
        # 拒绝前导正负号、空串；允许 0
        if len(p) > 1 and p[0] == '0':
            # 允许类似 01 吗？通常 IP 日志不会有；这里直接允许以避免误判成本
            pass
        try:
            v = int(p)
        except ValueError:
            return False
        if v < 0 or v > 255:
            return False
    return True


_HEX_CHARS = set("0123456789abcdefABCDEF")


@lru_cache(maxsize=65536)
def is_hex_hash(text: str) -> bool:
    n = len(text)
    if n < 32 or n > 128:
        return False
    for ch in text:
        if ch not in _HEX_CHARS:
            return False
    return True


@lru_cache(maxsize=65536)
def bucket_of_tx(tx_hash: str, bucket_digits: int) -> str:
    return tx_hash[:bucket_digits].lower()


def open_text_maybe_gz(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


# -----------------------------
# Source 解析阶段（严格顺序，支持断点续跑）
# -----------------------------

def load_progress(progress_path: Path) -> Optional[dict]:
    if not progress_path.exists():
        return None
    with open(progress_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_progress(progress_path: Path, progress: dict) -> None:
    atomic_write_text(progress_path, json.dumps(progress, ensure_ascii=False, sort_keys=False))


def validate_resume_prefix(current_files: List[FileMeta], completed_keys: List[str], source: str) -> int:
    if len(completed_keys) > len(current_files):
        raise RuntimeError(f"[{source}] 当前文件数量少于已完成前缀，无法安全续跑")
    current_prefix = [m.file_key for m in current_files[:len(completed_keys)]]
    if current_prefix != completed_keys:
        raise RuntimeError(
            f"[{source}] 已完成文件前缀与当前目录内容不一致，无法安全续跑。\n"
            f"请检查日志文件是否被替换/删除/重命名，或使用 --reset 重新开始。"
        )
    return len(completed_keys)


def parse_one_source(
    source: str,
    folder: str,
    workdir: str,
    bucket_digits: int,
    flush_every: int,
    progress_lines: int,
    resume: bool,
) -> dict:
    """
    每个 source(local/remote) 在独立进程中顺序处理，保持跨文件的 last_inv_by_peer 正确性。
    """
    t0 = time.time()
    folder_p = Path(folder)
    workdir_p = Path(workdir)

    files = discover_log_files(folder_p, source)
    if not files:
        eprint(f"[WARN] [{source}] 未发现可解析日志: {folder_p}")
        return {"source": source, "files": 0, "matched": 0, "unmatched": 0, "inv": 0}

    eprint(f"[INFO] [{source}] 开始处理目录: {folder_p}")
    eprint(f"[INFO] [{source}] 共发现 {len(files)} 个日志文件")

    state_dir = workdir_p / "state" / source
    parsed_dir = workdir_p / "parsed" / source
    tmp_dir = workdir_p / "tmp" / source
    state_dir.mkdir(parents=True, exist_ok=True)
    parsed_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    progress_path = state_dir / "progress.json"

    completed_keys: List[str] = []
    last_inv_by_peer: Dict[str, int] = {}
    start_idx = 0

    if resume and progress_path.exists():
        progress = load_progress(progress_path)
        if progress is not None:
            completed_keys = list(progress.get("completed_keys", []))
            start_idx = validate_resume_prefix(files, completed_keys, source)
            last_inv_by_peer = {k: int(v) for k, v in progress.get("last_inv_by_peer", {}).items()}
            eprint(f"[INFO] [{source}] 从断点续跑，已完成文件数={start_idx}")
    else:
        eprint(f"[INFO] [{source}] 从头开始处理")

    total_stats = {
        "files": len(files),
        "processed_files": start_idx,
        "inv": 0,
        "matched": 0,
        "unmatched": 0,
        "ignored_iplist": 0,
        "ignored_other": 0,
        "bad": 0,
        "lines": 0,
    }

    # 若从断点续跑，则 total_stats 只统计本次新增处理量；日志里单独说明已完成数量即可。

    for idx in range(start_idx, len(files)):
        meta = files[idx]
        file_start = time.time()
        eprint(f"[INFO] [{source}] 开始处理文件 {idx + 1}/{len(files)}: {meta.path.name}")
        if meta.is_current:
            eprint(f"[INFO] [{source}] 当前文件使用 mtime 推断日期: {meta.path.name} -> {meta.date_str}")

        file_stats = {
            "lines": 0,
            "inv": 0,
            "matched": 0,
            "unmatched": 0,
            "ignored_iplist": 0,
            "ignored_other": 0,
            "bad": 0,
        }

        # 每个文件独立写临时 shard；文件完成后再原子 rename，避免中断产生重复数据。
        file_tag = f"{idx:06d}__{meta.file_key}__{safe_stem(meta.path)}"
        local_tmp_dir = tmp_dir / file_tag
        local_tmp_dir.mkdir(parents=True, exist_ok=True)

        handles: Dict[str, object] = {}
        buffers: Dict[str, List[str]] = {}

        def flush_bucket(bucket: str) -> None:
            buf = buffers.get(bucket)
            if not buf:
                return
            fp = handles[bucket]
            fp.write(''.join(buf))
            buf.clear()

        def write_record(tx_hash: str, full_ts: str, peer_ip: str, inv_size: int) -> None:
            bucket = bucket_of_tx(tx_hash, bucket_digits)
            if bucket not in handles:
                tmp_file = local_tmp_dir / f"{file_tag}.{bucket}.tsv.tmp"
                handles[bucket] = open(tmp_file, "w", encoding="utf-8", newline="")
                buffers[bucket] = []
            buffers[bucket].append(f"{tx_hash}\t{full_ts}\t{peer_ip}\t{inv_size}\n")
            if len(buffers[bucket]) >= flush_every:
                flush_bucket(bucket)

        try:
            with open_text_maybe_gz(meta.path) as f:
                for raw in f:
                    file_stats["lines"] += 1
                    total_stats["lines"] += 1

                    line = raw.rstrip("\n")
                    sp = line.find(' ')
                    if sp <= 0:
                        file_stats["bad"] += 1
                        total_stats["bad"] += 1
                        continue

                    time_str = line[:sp]
                    # 轻量校验 HH:MM:SS.mmm
                    if len(time_str) != 12 or time_str[2] != ':' or time_str[5] != ':' or time_str[8] != '.':
                        file_stats["bad"] += 1
                        total_stats["bad"] += 1
                        continue

                    rest = line[sp + 1:].strip()
                    if not rest:
                        file_stats["bad"] += 1
                        total_stats["bad"] += 1
                        continue

                    # INV 行：INV ip size
                    if rest.startswith("INV "):
                        parts = rest.split()
                        if len(parts) >= 3 and parts[0] == "INV" and is_ipv4(parts[1]) and parts[2].isdigit():
                            last_inv_by_peer[parts[1]] = int(parts[2])
                            file_stats["inv"] += 1
                            total_stats["inv"] += 1
                        else:
                            file_stats["ignored_other"] += 1
                            total_stats["ignored_other"] += 1
                        continue

                    # 以 ip 开头的非交易行（例如逗号分隔 ip 列表）优先忽略
                    first_space = rest.find(' ')
                    first_token = rest if first_space == -1 else rest[:first_space]
                    if first_token and first_token[0].isdigit():
                        if ',' in first_token:
                            file_stats["ignored_iplist"] += 1
                            total_stats["ignored_iplist"] += 1
                            continue

                        parts = rest.split()
                        if len(parts) >= 2 and is_ipv4(parts[0]) and is_hex_hash(parts[1]):
                            peer_ip = parts[0]
                            tx_hash = parts[1].lower()
                            inv_size = last_inv_by_peer.get(peer_ip)
                            if inv_size is None:
                                file_stats["unmatched"] += 1
                                total_stats["unmatched"] += 1
                            else:
                                full_ts = f"{meta.date_str} {time_str}"
                                write_record(tx_hash, full_ts, peer_ip, inv_size)
                                file_stats["matched"] += 1
                                total_stats["matched"] += 1
                        else:
                            file_stats["ignored_other"] += 1
                            total_stats["ignored_other"] += 1
                    else:
                        file_stats["ignored_other"] += 1
                        total_stats["ignored_other"] += 1

                    if progress_lines > 0 and file_stats["lines"] % progress_lines == 0:
                        eprint(
                            f"[INFO] [{source}] 文件进行中: {meta.path.name} | "
                            f"lines={file_stats['lines']} | INV={file_stats['inv']} | "
                            f"TX匹配={file_stats['matched']} | TX未匹配={file_stats['unmatched']}"
                        )

            # flush + close
            for b in list(buffers.keys()):
                flush_bucket(b)
            for fp in handles.values():
                fp.close()

            # 原子 rename 到 parsed_dir
            created_shards = 0
            for tmp_file in sorted(local_tmp_dir.glob("*.tsv.tmp")):
                final_name = tmp_file.name[:-4]  # 去掉 .tmp
                final_path = parsed_dir / final_name
                os.replace(tmp_file, final_path)
                created_shards += 1

            shutil.rmtree(local_tmp_dir, ignore_errors=True)

            completed_keys.append(meta.file_key)
            progress = {
                "version": 1,
                "source": source,
                "folder": str(folder_p.resolve()),
                "completed_keys": completed_keys,
                "last_inv_by_peer": last_inv_by_peer,
                "updated_at": time.time(),
            }
            save_progress(progress_path, progress)

            total_stats["processed_files"] += 1
            elapsed = time.time() - file_start
            eprint(
                f"[INFO] [{source}] 文件完成 {idx + 1}/{len(files)}: {meta.path.name} | "
                f"耗时={elapsed:.2f}s | shards={created_shards} | 行数={file_stats['lines']} | "
                f"INV={file_stats['inv']} | TX匹配={file_stats['matched']} | TX未匹配={file_stats['unmatched']} | "
                f"忽略IP列表={file_stats['ignored_iplist']} | 其他忽略={file_stats['ignored_other']} | 坏行={file_stats['bad']}"
            )

        except Exception:
            # 尽量清理临时文件，避免误用
            try:
                for fp in handles.values():
                    fp.close()
            except Exception:
                pass
            shutil.rmtree(local_tmp_dir, ignore_errors=True)
            raise

    elapsed_all = time.time() - t0
    eprint(
        f"[INFO] [{source}] 全部完成 | 文件数={total_stats['files']} | 已处理到={total_stats['processed_files']} | "
        f"总行数={total_stats['lines']} | INV={total_stats['inv']} | TX匹配={total_stats['matched']} | "
        f"TX未匹配={total_stats['unmatched']} | 忽略IP列表={total_stats['ignored_iplist']} | "
        f"其他忽略={total_stats['ignored_other']} | 坏行={total_stats['bad']} | 总耗时={elapsed_all:.2f}s"
    )
    return {"source": source, **total_stats, "elapsed": elapsed_all}


# -----------------------------
# 排序阶段（bucket 级别，可并行）
# -----------------------------

def iter_bucket_names(bucket_digits: int) -> Iterable[str]:
    total = 16 ** bucket_digits
    for i in range(total):
        yield f"{i:0{bucket_digits}x}"


def list_bucket_shards(workdir: Path, bucket: str) -> List[Path]:
    files: List[Path] = []
    for source in ("local", "remote"):
        p = workdir / "parsed" / source
        if p.exists():
            files.extend(sorted(p.glob(f"*.{bucket}.tsv")))
    return files


def needs_resort(sorted_path: Path, inputs: List[Path]) -> bool:
    if not sorted_path.exists():
        return True
    out_mtime = sorted_path.stat().st_mtime_ns
    for p in inputs:
        if p.stat().st_mtime_ns > out_mtime:
            return True
    return False


def sort_one_bucket(
    bucket: str,
    workdir: str,
    sort_mem: str,
    sort_parallel: int,
    force_sort: bool,
) -> Tuple[str, int, str]:
    workdir_p = Path(workdir)
    sorted_dir = workdir_p / "sorted"
    sorted_dir.mkdir(parents=True, exist_ok=True)
    out_path = sorted_dir / f"bucket_{bucket}.sorted.tsv"

    inputs = list_bucket_shards(workdir_p, bucket)
    if not inputs:
        return bucket, 0, "empty"

    if (not force_sort) and (not needs_resort(out_path, inputs)):
        return bucket, len(inputs), "skip"

    # 优先用系统 sort。字段：
    # 1 tx_hash
    # 2 full_ts(YYYY-MM-DD HH:MM:SS.mmm)
    # 3 ip
    # 4 inv_size
    cmd = [
        "sort",
        "-t", "\t",
        "-k1,1",
        "-k2,2",
        "--stable",
        "--parallel", str(max(1, sort_parallel)),
        "-S", sort_mem,
        "-o", str(out_path),
        *[str(p) for p in inputs],
    ]
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    subprocess.run(cmd, check=True, env=env)
    return bucket, len(inputs), "sorted"


# -----------------------------
# 导出阶段：把 sorted bucket 转成最终块文本并切分
# -----------------------------

class SplitWriter:
    def __init__(self, output_dir: Path, limit_bytes: int, prefix: str):
        self.output_dir = output_dir
        self.limit_bytes = limit_bytes
        self.prefix = prefix
        self.part_no = 0
        self.fp = None
        self.cur_path: Optional[Path] = None
        self.cur_size = 0
        self.generated: List[Path] = []

    def _open_new(self):
        self.part_no += 1
        self.cur_path = self.output_dir / f"{self.prefix}.part{self.part_no:04d}.txt"
        self.fp = open(self.cur_path, "w", encoding="utf-8", newline="")
        self.cur_size = 0
        self.generated.append(self.cur_path)

    def write_text(self, text: str):
        data = text.encode("utf-8")
        if self.fp is None:
            self._open_new()
        if self.cur_size > 0 and self.cur_size + len(data) > self.limit_bytes:
            self.fp.close()
            self._open_new()
        self.fp.write(text)
        self.cur_size += len(data)

    def close(self):
        if self.fp is not None:
            self.fp.close()
            self.fp = None


def export_blocks(workdir: Path, output_dir: Path, part_size_mb: int, bucket_digits: int, prefix: str) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    # 清理旧输出，避免混淆
    for old in output_dir.glob(f"{prefix}.part*.txt"):
        old.unlink()

    writer = SplitWriter(output_dir, part_size_mb * 1024 * 1024, prefix)

    total_blocks = 0
    total_rows = 0
    for bucket in iter_bucket_names(bucket_digits):
        sorted_path = workdir / "sorted" / f"bucket_{bucket}.sorted.tsv"
        if not sorted_path.exists():
            continue

        eprint(f"[INFO] [export] 导出 bucket={bucket}: {sorted_path.name}")
        current_tx: Optional[str] = None
        current_lines: List[str] = []

        with open(sorted_path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                total_rows += 1
                parts = raw.rstrip("\n").split("\t")
                if len(parts) != 4:
                    continue
                tx_hash, full_ts, peer_ip, inv_size = parts

                if current_tx is None:
                    current_tx = tx_hash

                if tx_hash != current_tx:
                    block_text = current_tx + "\n" + "".join(current_lines) + ".\n"
                    writer.write_text(block_text)
                    total_blocks += 1
                    current_tx = tx_hash
                    current_lines = []

                current_lines.append(f"{full_ts} {peer_ip} {inv_size}\n")

        if current_tx is not None:
            block_text = current_tx + "\n" + "".join(current_lines) + ".\n"
            writer.write_text(block_text)
            total_blocks += 1

    writer.close()
    eprint(f"[INFO] [export] 导出完成 | blocks={total_blocks} | rows={total_rows} | parts={len(writer.generated)}")
    for p in writer.generated:
        eprint(f"[INFO] [export] 输出文件: {p} ({p.stat().st_size} bytes)")
    return writer.generated


# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    cpu = os.cpu_count() or 4
    parser = argparse.ArgumentParser(
        description="高性能合并 java-tron 本地/远程 stdout 日志，按交易哈希输出块文本",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--local-dir", required=True, help="本地日志目录")
    parser.add_argument("--remote-dir", required=True, help="远程同步下来的日志目录")
    parser.add_argument("--workdir", required=True, help="中间工作目录（分桶文件、状态文件、排序结果）")
    parser.add_argument("--output-dir", required=True, help="最终输出目录")
    parser.add_argument("--part-size-mb", type=int, default=100, help="最终输出切分大小")
    parser.add_argument("--bucket-digits", type=int, default=2, choices=[1, 2, 3], help="按 tx_hash 前几位分桶；2=256 桶")
    parser.add_argument("--flush-every", type=int, default=5000, help="每个 bucket 缓冲多少行后落盘")
    parser.add_argument("--progress-lines", type=int, default=200000, help="单文件内每处理多少行输出一次进度；0 表示关闭")
    parser.add_argument("--sort-jobs", type=int, default=min(4, cpu), help="并行排序 bucket 的任务数")
    parser.add_argument("--sort-parallel", type=int, default=max(1, min(4, cpu // 2 or 1)), help="传给单个 sort 命令的 --parallel")
    parser.add_argument("--sort-mem", default="1G", help="传给 sort 的 -S 内存参数，例如 512M / 1G / 2G")
    parser.add_argument("--force-sort", action="store_true", help="即便 sorted 文件已存在且较新，也强制重新排序")
    parser.add_argument("--reset", action="store_true", help="删除 workdir 中的中间结果和断点状态，从头开始")
    parser.add_argument("--no-resume", action="store_true", help="不读取断点，直接从头处理 source 解析阶段")
    parser.add_argument("--output-prefix", default="merged_tx_blocks", help="输出文件名前缀")
    return parser.parse_args()


def maybe_reset_workdir(workdir: Path, do_reset: bool) -> None:
    if do_reset and workdir.exists():
        eprint(f"[INFO] 删除旧 workdir: {workdir}")
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)


def main() -> int:
    args = parse_args()

    local_dir = Path(args.local_dir)
    remote_dir = Path(args.remote_dir)
    workdir = Path(args.workdir)
    output_dir = Path(args.output_dir)

    if not local_dir.is_dir():
        raise SystemExit(f"本地日志目录不存在: {local_dir}")
    if not remote_dir.is_dir():
        raise SystemExit(f"远程日志目录不存在: {remote_dir}")

    maybe_reset_workdir(workdir, args.reset)
    output_dir.mkdir(parents=True, exist_ok=True)

    overall_start = time.time()

    # 1) 解析阶段：local / remote 两个 source 并行，各自内部严格顺序，保证 carry-over 正确。
    parse_start = time.time()
    with cf.ProcessPoolExecutor(max_workers=2) as ex:
        futs = [
            ex.submit(
                parse_one_source,
                "local",
                str(local_dir),
                str(workdir),
                args.bucket_digits,
                args.flush_every,
                args.progress_lines,
                not args.no_resume,
            ),
            ex.submit(
                parse_one_source,
                "remote",
                str(remote_dir),
                str(workdir),
                args.bucket_digits,
                args.flush_every,
                args.progress_lines,
                not args.no_resume,
            ),
        ]
        parse_results = [f.result() for f in futs]
    eprint(f"[INFO] [main] 解析阶段完成 | 耗时={time.time() - parse_start:.2f}s")
    for r in parse_results:
        eprint(f"[INFO] [main] parse_result={r}")

    # 2) 排序阶段：bucket 级别并行
    sort_start = time.time()
    buckets = list(iter_bucket_names(args.bucket_digits))
    done = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.sort_jobs)) as ex:
        fut_map = {
            ex.submit(sort_one_bucket, b, str(workdir), args.sort_mem, args.sort_parallel, args.force_sort): b
            for b in buckets
        }
        for fut in cf.as_completed(fut_map):
            bucket, n_inputs, status = fut.result()
            done += 1
            eprint(f"[INFO] [sort] bucket={bucket} | inputs={n_inputs} | status={status} | progress={done}/{len(buckets)}")
    eprint(f"[INFO] [main] 排序阶段完成 | 耗时={time.time() - sort_start:.2f}s")

    # 3) 导出阶段
    export_start = time.time()
    generated = export_blocks(workdir, output_dir, args.part_size_mb, args.bucket_digits, args.output_prefix)
    eprint(f"[INFO] [main] 导出阶段完成 | 耗时={time.time() - export_start:.2f}s")

    eprint(f"[INFO] [main] 全部完成 | 总耗时={time.time() - overall_start:.2f}s | 输出文件数={len(generated)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
