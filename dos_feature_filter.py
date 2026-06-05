#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dos_feature_filter.py — Module lọc đặc trưng chuyên biệt cho phát hiện tấn công DoS.

Nhận file CSV chứa toàn bộ đặc trưng mạng (40+ cột), loại bỏ các trường nhiễu,
chỉ giữ lại các trường chuyên biệt dùng để phát hiện tấn công DoS dựa trên
nghiên cứu chuẩn, sau đó xuất ra file CSV mới tối ưu hơn.

Cách sử dụng:
    python dos_feature_filter.py input.csv
    python dos_feature_filter.py input.csv -o output.csv
"""

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd
import numpy as np

# ---------------------------------------------------------------------------
# Cấu hình logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Danh sách các cột cần giữ lại — phân nhóm theo chức năng
# ---------------------------------------------------------------------------
KEEP_COLUMNS: list[str] = [
    # Nhóm định danh (Metadata — phục vụ truy vết)
    "srcip", "dstip", "sport", "dport", "ltime",
    # Nhóm 1: TTL & Trạng thái
    "sttl", "ct_state_ttl", "dttl",
    # Nhóm 2: Lưu lượng
    "sbytes", "dbytes", "smean", "dmean", "rate",
    # Nhóm 3: Băng thông
    "sload", "dload",
    # Nhóm 4: Mất gói
    "sloss", "dloss",
    # Nhóm 5: TCP Timing
    "tcprtt", "synack",
    # Nhóm 6: Connection Tracking
    "ct_srv_dst", "ct_dst_src_ltm", "ct_dst_sport_ltm",
    "ct_src_dport_ltm", "ct_srv_src",
    # Nhóm 7: Số lượng gói
    "spkts", "dpkts",
    # Nhóm 8: Categorical
    "proto", "state", "service",
]

# Các cột categorical cần chuẩn hoá
CATEGORICAL_COLUMNS: list[str] = ["proto", "state", "service"]

# Các cột nên ép kiểu số nguyên nhỏ gọn
INTEGER_COLUMNS: list[str] = [
    "sport", "dport",
    "sttl", "ct_state_ttl", "dttl",
    "sbytes", "dbytes", "smean", "dmean",
    "sloss", "dloss",
    "ct_srv_dst", "ct_dst_src_ltm", "ct_dst_sport_ltm",
    "ct_src_dport_ltm", "ct_srv_src",
    "spkts", "dpkts",
]


# ---------------------------------------------------------------------------
# Hàm tiện ích
# ---------------------------------------------------------------------------

def _fmt_bytes(n_bytes: int) -> str:
    """Chuyển số byte thành chuỗi dễ đọc (KB / MB / GB)."""
    if n_bytes < 1024:
        return f"{n_bytes} B"
    elif n_bytes < 1024 ** 2:
        return f"{n_bytes / 1024:.2f} KB"
    elif n_bytes < 1024 ** 3:
        return f"{n_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{n_bytes / 1024 ** 3:.2f} GB"


def _downcast_integers(df: pd.DataFrame) -> pd.DataFrame:
    """Ép kiểu các cột số nguyên về int16/int32 nếu phạm vi cho phép."""
    for col in INTEGER_COLUMNS:
        if col not in df.columns:
            continue
        # Bỏ qua nếu cột chứa giá trị NaN (không ép int được)
        if df[col].isna().any():
            logger.warning("Cột '%s' chứa giá trị NaN — bỏ qua ép kiểu nguyên.", col)
            continue
        try:
            col_min = df[col].min()
            col_max = df[col].max()
            # Thử int16 trước (-32768 → 32767)
            if col_min >= np.iinfo(np.int16).min and col_max <= np.iinfo(np.int16).max:
                df[col] = df[col].astype(np.int16)
            # Thử int32 (-2 147 483 648 → 2 147 483 647)
            elif col_min >= np.iinfo(np.int32).min and col_max <= np.iinfo(np.int32).max:
                df[col] = df[col].astype(np.int32)
            else:
                # Giữ nguyên int64
                df[col] = df[col].astype(np.int64)
        except (ValueError, TypeError):
            logger.warning("Không thể ép kiểu cột '%s' — giữ nguyên.", col)
    return df


def _normalize_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    """Chuẩn hoá các cột categorical: strip + lowercase."""
    for col in CATEGORICAL_COLUMNS:
        if col not in df.columns:
            continue
        df[col] = df[col].astype(str).str.strip().str.lower()
    return df


# ---------------------------------------------------------------------------
# Hàm chính
# ---------------------------------------------------------------------------

def filter_dos_features(input_path: str, output_path: str) -> pd.DataFrame:
    """
    Đọc file CSV gốc, lọc giữ lại các cột DoS chuyên biệt, tối ưu bộ nhớ
    và xuất file CSV kết quả.

    Parameters
    ----------
    input_path : str
        Đường dẫn tới file CSV đầu vào.
    output_path : str
        Đường dẫn file CSV kết quả.

    Returns
    -------
    pd.DataFrame
        DataFrame đã được lọc và tối ưu.
    """
    # --- 1. Đọc dữ liệu ---------------------------------------------------
    input_file = Path(input_path)
    if not input_file.is_file():
        logger.error("File đầu vào không tồn tại: %s", input_file)
        sys.exit(1)

    logger.info("Đang đọc file: %s", input_file)
    df = pd.read_csv(input_file, low_memory=False)

    # Chuẩn hoá tên cột: strip + lowercase
    df.columns = df.columns.str.strip().str.lower()

    n_rows = len(df)
    n_cols_original = len(df.columns)
    mem_before = df.memory_usage(deep=True).sum()

    logger.info("Dữ liệu gốc : %d dòng × %d cột | Bộ nhớ: %s",
                n_rows, n_cols_original, _fmt_bytes(mem_before))

    # --- 2. Lọc cột --------------------------------------------------------
    available = [c for c in KEEP_COLUMNS if c in df.columns]
    missing = [c for c in KEEP_COLUMNS if c not in df.columns]

    if missing:
        logger.warning("⚠  Các cột sau KHÔNG có trong file đầu vào (bỏ qua): %s",
                        ", ".join(missing))

    df = df[available].copy()
    n_cols_filtered = len(df.columns)
    logger.info("Sau lọc       : %d cột giữ lại / %d cột loại bỏ",
                n_cols_filtered, n_cols_original - n_cols_filtered)

    # --- 3. Tối ưu bộ nhớ --------------------------------------------------
    df = _normalize_categoricals(df)
    df = _downcast_integers(df)

    mem_after = df.memory_usage(deep=True).sum()
    saved = mem_before - mem_after
    pct = (saved / mem_before * 100) if mem_before > 0 else 0

    logger.info("Bộ nhớ sau tối ưu: %s (tiết kiệm %s — %.1f%%)",
                _fmt_bytes(mem_after), _fmt_bytes(saved), pct)

    # --- 4. Xuất dữ liệu ---------------------------------------------------
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)

    file_size = out.stat().st_size
    logger.info("✅ Đã lưu kết quả: %s (%s)", out, _fmt_bytes(file_size))

    return df


# ---------------------------------------------------------------------------
# Đường dẫn mặc định
# ---------------------------------------------------------------------------
DEFAULT_INPUT_DIR = r"D:\1LearnandStudy\Program_Language\Python\CSV\CSV_Full_feature"
DEFAULT_OUTPUT_DIR = r"D:\1LearnandStudy\Program_Language\Python\CSV\Filter_DoS_feature"


# ---------------------------------------------------------------------------
# Xử lý hàng loạt — quét tất cả file CSV trong thư mục
# ---------------------------------------------------------------------------

def process_directory(input_dir: str, output_dir: str) -> None:
    """
    Quét thư mục input_dir, tìm tất cả file .csv và chạy
    filter_dos_features cho từng file. Kết quả được lưu vào output_dir
    với tên file giữ nguyên.
    """
    in_path = Path(input_dir)
    out_path = Path(output_dir)

    if not in_path.is_dir():
        logger.error("Thư mục đầu vào không tồn tại: %s", in_path)
        sys.exit(1)

    csv_files = sorted(in_path.glob("*.csv"))
    if not csv_files:
        logger.warning("⚠  Không tìm thấy file .csv nào trong: %s", in_path)
        sys.exit(0)

    out_path.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Tìm thấy %d file CSV trong: %s", len(csv_files), in_path)
    logger.info("Thư mục xuất: %s", out_path)
    logger.info("=" * 60)

    for i, csv_file in enumerate(csv_files, 1):
        output_file = out_path / f"feature_for_DoS_{i}.csv" if len(csv_files) > 1 else out_path / "feature_for_DoS.csv"
        logger.info("")
        logger.info("─── [%d/%d] %s ───", i, len(csv_files), csv_file.name)
        filter_dos_features(str(csv_file), str(output_file))

    logger.info("")
    logger.info("=" * 60)
    logger.info("✅ Hoàn tất! Đã xử lý %d file.", len(csv_files))
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Lọc đặc trưng chuyên biệt cho phát hiện tấn công DoS. "
            "Giữ lại các cột quan trọng, loại bỏ nhiễu, tối ưu bộ nhớ. "
            "Hỗ trợ xử lý file đơn lẻ hoặc cả thư mục chứa nhiều file CSV."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default=DEFAULT_INPUT_DIR,
        help=(
            "Đường dẫn file CSV hoặc thư mục chứa file CSV. "
            f"(mặc định: {DEFAULT_INPUT_DIR})"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help=(
            "Đường dẫn file CSV kết quả (nếu input là file) "
            "hoặc thư mục xuất (nếu input là thư mục). "
            f"(mặc định: {DEFAULT_OUTPUT_DIR})"
        ),
    )

    args = parser.parse_args()
    input_path = Path(args.input)

    if input_path.is_dir():
        # --- Chế độ xử lý thư mục ---
        output_dir = args.output if args.output else DEFAULT_OUTPUT_DIR
        process_directory(str(input_path), output_dir)
    elif input_path.is_file():
        # --- Chế độ xử lý file đơn lẻ ---
        if args.output:
            output_path = args.output
        else:
            out_dir = Path(DEFAULT_OUTPUT_DIR)
            out_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(out_dir / "feature_for_DoS.csv")
        filter_dos_features(str(input_path), output_path)
    else:
        logger.error("Đường dẫn không tồn tại: %s", input_path)
        sys.exit(1)


if __name__ == "__main__":
    main()
