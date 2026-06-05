#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dos_classifier.py — Module phân loại DoS và cảnh báo thông minh.

Đóng vai trò là lõi phân loại (Classification Engine) cho hệ thống IDS.
- Đầu vào: File CSV chứa các flow mạng đã được lọc và thư mục chứa file http.log của Zeek.
- Cơ chế: Vectorized scoring bằng Pandas, truy ngược context User từ Zeek log.
- Cảnh báo: In dòng cảnh báo màu đỏ trên Terminal khi phát hiện DoS.
"""

import os
import sys
import argparse
import logging
import ctypes
import re
import pandas as pd
import numpy as np
from typing import Dict, Tuple, Optional

# Hỗ trợ mã hóa trên Windows để tránh lỗi UnicodeEncodeError khi in emoji
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Cấu hình Baseline (Dictionary)
# ---------------------------------------------------------------------------
BASELINE_CONFIG = {
    'thresholds': {
        'sttl_high': 200,
        'ct_state_ttl_min': 2,
        'dmean_max': 10,
        'rate_min': 50.0,
        'sload_min': 50000000.0,
        'dload_max': 10000.0,
        'ct_dst_src_ltm_min': 3,
        'ct_dst_sport_ltm_min': 1,
        'ct_src_dport_ltm_min': 1,
        'spkts_max': 3,
    },
    'scores': {
        'sttl_high': 20,            # sttl >= sttl_high
        'ct_state_ttl': 10,         # ct_state_ttl >= ct_state_ttl_min
        'dttl_zero': 10,            # dttl == 0 (hoặc missing/NaN)
        'dbytes_zero': 10,          # dbytes == 0
        'dmean_low': 10,            # dmean < dmean_max
        'rate_high': 10,            # rate > rate_min
        'sload_high': 10,           # sload > sload_min
        'dload_low': 10,            # dload < dload_max
        'tcp_no_handshake': 10,     # tcprtt == 0 hoặc synack == 0
        'sloss_zero': 5,            # sloss == 0
        'ct_dst_src_ltm': 5,        # ct_dst_src_ltm > ct_dst_src_ltm_min
        'ct_dst_sport_ltm': 5,      # ct_dst_sport_ltm > ct_dst_sport_ltm_min
        'ct_src_dport_ltm': 5,      # ct_src_dport_ltm > ct_src_dport_ltm_min
        'dpkts_zero': 10,           # dpkts == 0
        'spkts_low': 5,             # spkts <= spkts_max
        'proto_unas': 30,           # proto == 'unas'
        'state_int': 20,            # state == 'int' (case-insensitive)
        'service_none': 5,          # service == '-' hoặc rỗng
    },
    'alert_threshold': 50           # Điểm cắt để quyết định là DoS
}

# ---------------------------------------------------------------------------
# Cấu hình Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hỗ trợ màu Terminal trên Windows
# ---------------------------------------------------------------------------
def enable_ansi_support() -> None:
    """Kích hoạt hỗ trợ mã màu ANSI trên Windows Terminal."""
    if sys.platform.startswith("win"):
        try:
            kernel32 = ctypes.windll.kernel32
            hOut = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            if hOut != -1:
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
                    # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                    kernel32.SetConsoleMode(hOut, mode.value | 0x0004)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Hàm truy ngược thông tin User (Cross-reference Zeek Log)
# ---------------------------------------------------------------------------
def load_zeek_http_log(zeek_dir: str) -> Dict[Tuple[str, str], str]:
    """
    Đọc http.log và xây dựng bảng lookup O(1) theo (id.orig_h, id.orig_p).
    Tối ưu hóa: Load file duy nhất 1 lần lúc khởi động.

    Args:
        zeek_dir: Đường dẫn đến thư mục chứa file http.log hoặc đường dẫn trực tiếp.

    Returns:
        Dict với key là (orig_ip, orig_port) dạng chuỗi, value là User Agent / Username.
    """
    lookup_dict = {}
    http_log_path = None

    if not zeek_dir:
        return lookup_dict

    # Xác định đường dẫn chính xác tới http.log
    if os.path.isfile(zeek_dir):
        if os.path.basename(zeek_dir) == "http.log":
            http_log_path = zeek_dir
    else:
        # Tìm trong thư mục trực tiếp
        candidate = os.path.join(zeek_dir, "http.log")
        if os.path.isfile(candidate):
            http_log_path = candidate
        else:
            # Tìm trong thư mục con zeek_logs
            candidate_sub = os.path.join(zeek_dir, "zeek_logs", "http.log")
            if os.path.isfile(candidate_sub):
                http_log_path = candidate_sub
            else:
                # Quét đệ quy tìm http.log
                for root, _, files in os.walk(zeek_dir):
                    if "http.log" in files:
                        http_log_path = os.path.join(root, "http.log")
                        break

    if not http_log_path:
        logger.warning("Không tìm thấy file http.log. Sẽ bỏ qua phần truy ngược User.")
        return lookup_dict

    logger.info("Đang nạp file log: %s", http_log_path)
    try:
        with open(http_log_path, "r", encoding="utf-8") as f:
            headers = []
            separator = "\t"  # Mặc định của Zeek log
            
            for line in f:
                line = line.rstrip("\n\r")
                if not line:
                    continue
                
                # Parse cấu hình separator của Zeek
                if line.startswith("#separator"):
                    parts = line.split(" ")
                    if len(parts) > 1:
                        sep_str = parts[1]
                        if sep_str == "\\x09":
                            separator = "\t"
                        elif sep_str == " ":
                            separator = " "
                    continue
                
                # Parse danh sách trường
                if line.startswith("#fields"):
                    headers = line.split(separator)[1:]  # Bỏ qua phần '#fields'
                    continue
                
                # Bỏ qua các dòng comment khác
                if line.startswith("#"):
                    continue
                
                # Xử lý dòng dữ liệu
                if not headers:
                    continue
                
                parts = line.split(separator)
                if len(parts) < len(headers):
                    continue
                
                # Ánh xạ trường sang giá trị
                record = dict(zip(headers, parts))
                
                orig_h = record.get("id.orig_h")
                orig_p = record.get("id.orig_p")
                
                if not orig_h or not orig_p:
                    continue
                
                # Lấy user_agent và username
                user_agent = record.get("user_agent", "-")
                username = record.get("username", "-")
                
                # Chuẩn hoá các giá trị rỗng/mặc định của Zeek
                if user_agent in ("-", "", "(empty)"):
                    user_agent = ""
                if username in ("-", "", "(empty)"):
                    username = ""
                
                # Hợp nhất thông tin
                user_info = ""
                if user_agent and username:
                    user_info = f"{username} ({user_agent})"
                elif user_agent:
                    user_info = user_agent
                elif username:
                    user_info = username
                
                if user_info:
                    # Key dạng tuple (str, str)
                    key = (str(orig_h).strip(), str(orig_p).strip())
                    
                    # Ưu tiên ghi nhận log có dữ liệu đầy đủ nhất
                    if key not in lookup_dict or len(user_info) > len(lookup_dict[key]):
                        lookup_dict[key] = user_info
                        
        logger.info("Đã nạp thành công %d bản ghi HTTP để lookup.", len(lookup_dict))
    except Exception as exc:
        logger.error("Lỗi khi đọc file http.log: %s", exc)

    return lookup_dict

# ---------------------------------------------------------------------------
# Logic Chấm Điểm Vectorized
# ---------------------------------------------------------------------------
def evaluate_dos_scores(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """
    Tính tổng điểm rủi ro (dos_score) cho các flow mạng bằng Pandas Vectorization.
    Giúp xử lý nhanh chóng hàng triệu dòng.

    Args:
        df: DataFrame chứa dữ liệu flow mạng.
        config: baseline config chứa thresholds và scores.

    Returns:
        DataFrame gốc kèm thêm cột 'dos_score'.
    """
    # Khởi tạo cột điểm rủi ro bằng 0
    scores_series = pd.Series(0.0, index=df.index)
    
    thresholds = config['thresholds']
    scores = config['scores']

    # 1. Nhóm TTL & Trạng thái
    if 'sttl' in df.columns:
        scores_series += np.where(df['sttl'] >= thresholds['sttl_high'], scores['sttl_high'], 0)
    
    if 'ct_state_ttl' in df.columns:
        scores_series += np.where(df['ct_state_ttl'] >= thresholds['ct_state_ttl_min'], scores['ct_state_ttl'], 0)
        
    if 'dttl' in df.columns:
        # dttl == 0 hoặc dttl bị khuyết/NaN
        dttl_cond = (df['dttl'] == 0) | (df['dttl'].isna())
        scores_series += np.where(dttl_cond, scores['dttl_zero'], 0)

    # 2. Nhóm Lưu lượng
    if 'dbytes' in df.columns:
        scores_series += np.where(df['dbytes'] == 0, scores['dbytes_zero'], 0)
        
    if 'dmean' in df.columns:
        scores_series += np.where(df['dmean'] < thresholds['dmean_max'], scores['dmean_low'], 0)
        
    if 'rate' in df.columns:
        scores_series += np.where(df['rate'] > thresholds['rate_min'], scores['rate_high'], 0)
        
    if 'sload' in df.columns:
        scores_series += np.where(df['sload'] > thresholds['sload_min'], scores['sload_high'], 0)
        
    if 'dload' in df.columns:
        scores_series += np.where(df['dload'] < thresholds['dload_max'], scores['dload_low'], 0)

    # 3. Nhóm Mất gói & Timing
    # tcprtt == 0 hoặc synack == 0
    if 'tcprtt' in df.columns and 'synack' in df.columns:
        tcp_cond = (df['tcprtt'] == 0) | (df['synack'] == 0)
        scores_series += np.where(tcp_cond, scores['tcp_no_handshake'], 0)
    elif 'tcprtt' in df.columns:
        scores_series += np.where(df['tcprtt'] == 0, scores['tcp_no_handshake'], 0)
    elif 'synack' in df.columns:
        scores_series += np.where(df['synack'] == 0, scores['tcp_no_handshake'], 0)
        
    if 'sloss' in df.columns:
        scores_series += np.where(df['sloss'] == 0, scores['sloss_zero'], 0)

    # 4. Nhóm Connection Tracking
    if 'ct_dst_src_ltm' in df.columns:
        scores_series += np.where(df['ct_dst_src_ltm'] > thresholds['ct_dst_src_ltm_min'], scores['ct_dst_src_ltm'], 0)
        
    if 'ct_dst_sport_ltm' in df.columns:
        scores_series += np.where(df['ct_dst_sport_ltm'] > thresholds['ct_dst_sport_ltm_min'], scores['ct_dst_sport_ltm'], 0)
        
    if 'ct_src_dport_ltm' in df.columns:
        scores_series += np.where(df['ct_src_dport_ltm'] > thresholds['ct_src_dport_ltm_min'], scores['ct_src_dport_ltm'], 0)
        
    if 'dpkts' in df.columns:
        scores_series += np.where(df['dpkts'] == 0, scores['dpkts_zero'], 0)
        
    if 'spkts' in df.columns:
        scores_series += np.where(df['spkts'] <= thresholds['spkts_max'], scores['spkts_low'], 0)

    # 5. Nhóm Categorical
    if 'proto' in df.columns:
        proto_norm = df['proto'].astype(str).str.strip().str.lower()
        scores_series += np.where(proto_norm == 'unas', scores['proto_unas'], 0)
        
    if 'state' in df.columns:
        state_norm = df['state'].astype(str).str.strip().str.lower()
        scores_series += np.where(state_norm == 'int', scores['state_int'], 0)
        
    if 'service' in df.columns:
        service_norm = df['service'].astype(str).str.strip().str.lower()
        service_cond = (service_norm == '-') | (service_norm == '') | (df['service'].isna())
        scores_series += np.where(service_cond, scores['service_none'], 0)

    # Gán vào dataframe
    df['dos_score'] = scores_series.astype(int)
    return df

# ---------------------------------------------------------------------------
# Phát Xuất Cảnh Báo
# ---------------------------------------------------------------------------
def process_and_alert(df: pd.DataFrame, http_lookup: dict, alert_threshold: int) -> int:
    """
    Duyệt qua các flow bị đánh dấu là DoS và xuất cảnh báo màu đỏ.

    Args:
        df: DataFrame đã được chấm điểm.
        http_lookup: Bảng tra cứu User từ http.log.
        alert_threshold: Ngưỡng điểm để coi là DoS.

    Returns:
        Số lượng flow DoS phát hiện được.
    """
    # Lọc ra các dòng thoả mãn ngưỡng DoS
    dos_flows = df[df['dos_score'] >= alert_threshold]
    alert_count = len(dos_flows)
    
    if alert_count == 0:
        logger.info("Không phát hiện cuộc tấn công DoS nào vượt ngưỡng.")
        return 0

    # Tìm cột MAC nguồn khả dụng
    mac_col = None
    for col in ['src_mac', 'srcmac', 'smac', 'orig_l2_addr']:
        if col in df.columns:
            mac_col = col
            break

    # Mã màu ANSI màu đỏ sáng
    RED_COLOR = "\033[91m"
    RESET_COLOR = "\033[0m"

    for _, row in dos_flows.iterrows():
        srcip = str(row.get('srcip', 'N/A')).strip()
        proto = row.get('proto', 'N/A')
        
        # Đảm bảo port hiển thị dạng số nguyên sạch
        sport = row.get('sport', 0)
        dport = row.get('dport', 0)
        sport_str = str(int(sport)) if pd.notna(sport) else 'N/A'
        dport_str = str(int(dport)) if pd.notna(dport) else 'N/A'
        
        dos_score = int(row['dos_score'])
        src_mac = str(row.get(mac_col, 'N/A')).strip() if (mac_col and pd.notna(row.get(mac_col))) else 'N/A'
        
        # Tự động chuẩn hóa hiển thị nếu srcip chứa định dạng địa chỉ MAC
        mac_pattern = re.compile(r'^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$')
        if mac_pattern.match(srcip):
            if src_mac == 'N/A' or src_mac == '' or not mac_pattern.match(src_mac):
                src_mac = srcip
            srcip = "N/A (L2 Frame)"
            
        service = str(row.get('service', '')).strip().lower()

        # Truy ngược thông tin User
        user_agent = "N/A (L3/L4 Attack)"
        if service == 'http':
            key = (srcip, sport_str)
            user_agent = http_lookup.get(key, "N/A (L3/L4 Attack)")

        # In cảnh báo đỏ ra Terminal
        alert_line = (
            f"[🚨 CẢNH BÁO DoS] IP Kẻ tấn công: {srcip} | MAC: {src_mac} | "
            f"Protocol: {proto} | Port: {sport_str} -> {dport_str} | "
            f"Risk Score: {dos_score} | Info/User: {user_agent}"
        )
        print(f"{RED_COLOR}{alert_line}{RESET_COLOR}")

    return alert_count

# ---------------------------------------------------------------------------
# Hàm Main
# ---------------------------------------------------------------------------
def main() -> None:
    enable_ansi_support()

    parser = argparse.ArgumentParser(
        description="IDS Classification Engine - Phân loại DoS & Cảnh báo thông minh.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="Đường dẫn đến file CSV chứa dải flow mạng đã lọc."
    )
    parser.add_argument(
        "--zeek-dir",
        default="",
        help="Thư mục chứa file http.log của Zeek để truy xuất context User."
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help=f"Ngưỡng điểm để quyết định DoS. Nếu không truyền sẽ lấy mặc định là {BASELINE_CONFIG['alert_threshold']}."
    )

    args = parser.parse_args()

    # Xác thực đường dẫn file CSV
    if not os.path.isfile(args.csv):
        logger.error("File CSV đầu vào không tồn tại: %s", args.csv)
        sys.exit(1)

    # Đọc cấu hình ngưỡng
    alert_threshold = args.threshold if args.threshold is not None else BASELINE_CONFIG['alert_threshold']
    logger.info("IDS Engine khởi tạo. Threshold quyết định DoS: %d", alert_threshold)

    # 1. Load http.log Zeek (Lookup O(1))
    http_lookup = {}
    if args.zeek_dir:
        http_lookup = load_zeek_http_log(args.zeek_dir)
    else:
        logger.info("Không truyền --zeek-dir. Chế độ bỏ qua truy ngược User-Agent.")

    # 2. Đọc file CSV
    logger.info("Đang đọc và phân tích file: %s", args.csv)
    try:
        df = pd.read_csv(args.csv, low_memory=False)
    except Exception as exc:
        logger.error("Không thể đọc file CSV: %s", exc)
        sys.exit(1)

    # Tối ưu hoá bộ nhớ nếu DataFrame lớn
    if len(df) > 0:
        logger.info("Đã nạp %d dòng dữ liệu.", len(df))
    else:
        logger.warning("File CSV rỗng.")
        sys.exit(0)

    # 3. Tính toán điểm rủi ro sử dụng Pandas Vectorization
    logger.info("Đang tính toán Risk Score bằng Vectorization...")
    df = evaluate_dos_scores(df, BASELINE_CONFIG)

    # 4. Trích xuất cảnh báo
    logger.info("Đang quét và phát xuất cảnh báo DoS...")
    total_alerts = process_and_alert(df, http_lookup, alert_threshold)
    
    logger.info("Hoàn thành! Tổng cộng phát hiện %d cuộc tấn công DoS.", total_alerts)

if __name__ == "__main__":
    main()
