# 🛡️ DoS Feature Filter

> **Module lọc đặc trưng chuyên biệt cho phát hiện tấn công từ chối dịch vụ (DoS)**

---

## 📖 Tổng quan

`dos_feature_filter.py` là một pipeline xử lý dữ liệu mạng viết bằng Python, dùng để **lọc và tối ưu** các file CSV chứa đặc trưng lưu lượng mạng (40+ cột). Module chỉ giữ lại **28 đặc trưng then chốt** phục vụ phát hiện tấn công DoS dựa trên các nghiên cứu chuẩn, đồng thời thực hiện tối ưu bộ nhớ tự động thông qua kỹ thuật downcast kiểu dữ liệu.

### Điểm nổi bật

| Tính năng | Mô tả |
|---|---|
| 🎯 **Lọc chọn lọc** | Giữ lại 28 cột thiết yếu, loại bỏ toàn bộ cột nhiễu |
| ⚡ **Tối ưu bộ nhớ** | Downcast `int64` → `int16`/`int32` tự động theo phạm vi giá trị |
| 📁 **Xử lý hàng loạt** | Quét toàn bộ thư mục CSV, xử lý tuần tự |
| 🔤 **Chuẩn hoá dữ liệu** | Strip whitespace + lowercase cho cả tên cột và dữ liệu categorical |
| 📊 **Logging chi tiết** | Báo cáo kích thước, bộ nhớ tiết kiệm, cột thiếu tại mỗi bước |
| 🖥️ **CLI linh hoạt** | Hỗ trợ cả file đơn lẻ và thư mục qua `argparse` |

---

## 🧬 Các nhóm đặc trưng được giữ lại

Module chọn lọc 28 cột, phân thành **8 nhóm chức năng** + 1 nhóm metadata:

### Nhóm định danh (Metadata — phục vụ truy vết)

| Cột | Ý nghĩa |
|---|---|
| `srcip` | Địa chỉ IP nguồn |
| `dstip` | Địa chỉ IP đích |
| `sport` | Cổng nguồn |
| `dport` | Cổng đích |
| `ltime` | Thời gian kết thúc kết nối |

### Nhóm 1: TTL & Trạng thái

| Cột | Ý nghĩa |
|---|---|
| `sttl` | Time-to-Live gói tin nguồn |
| `dttl` | Time-to-Live gói tin đích |
| `ct_state_ttl` | Số kết nối cùng trạng thái và TTL |

### Nhóm 2: Lưu lượng (Traffic Volume)

| Cột | Ý nghĩa |
|---|---|
| `sbytes` | Tổng số byte từ nguồn đến đích |
| `dbytes` | Tổng số byte từ đích đến nguồn |
| `smean` | Kích thước trung bình gói tin nguồn |
| `dmean` | Kích thước trung bình gói tin đích |
| `rate` | Tốc độ gói tin (packets/second) |

### Nhóm 3: Băng thông (Bandwidth)

| Cột | Ý nghĩa |
|---|---|
| `sload` | Tải nguồn (bits/second) |
| `dload` | Tải đích (bits/second) |

### Nhóm 4: Mất gói (Packet Loss)

| Cột | Ý nghĩa |
|---|---|
| `sloss` | Số gói tin bị mất từ nguồn |
| `dloss` | Số gói tin bị mất từ đích |

### Nhóm 5: TCP Timing

| Cột | Ý nghĩa |
|---|---|
| `tcprtt` | TCP Round Trip Time |
| `synack` | Thời gian SYN → SYN-ACK |

### Nhóm 6: Connection Tracking

| Cột | Ý nghĩa |
|---|---|
| `ct_srv_dst` | Số kết nối cùng dịch vụ và IP đích |
| `ct_dst_src_ltm` | Số kết nối cùng IP đích-nguồn trong khoảng thời gian |
| `ct_dst_sport_ltm` | Số kết nối cùng IP đích và cổng nguồn trong khoảng thời gian |
| `ct_src_dport_ltm` | Số kết nối cùng IP nguồn và cổng đích trong khoảng thời gian |
| `ct_srv_src` | Số kết nối cùng dịch vụ và IP nguồn |

### Nhóm 7: Số lượng gói (Packet Counts)

| Cột | Ý nghĩa |
|---|---|
| `spkts` | Tổng số gói tin nguồn → đích |
| `dpkts` | Tổng số gói tin đích → nguồn |

### Nhóm 8: Categorical

| Cột | Ý nghĩa |
|---|---|
| `proto` | Giao thức (tcp, udp, icmp, ...) |
| `state` | Trạng thái kết nối (FIN, CON, ...) |
| `service` | Dịch vụ (http, dns, ftp, ...) |

---

## 🚀 Cài đặt & Yêu cầu

### Yêu cầu hệ thống

- **Python** ≥ 3.10
- **pip** (trình quản lý gói Python)

### Thư viện phụ thuộc

```bash
pip install pandas numpy
```

| Thư viện | Phiên bản tối thiểu | Vai trò |
|---|---|---|
| `pandas` | ≥ 1.5 | Đọc/ghi CSV, xử lý DataFrame |
| `numpy` | ≥ 1.23 | Hỗ trợ downcast kiểu dữ liệu (`int16`, `int32`) |

> **Lưu ý:** `argparse`, `logging`, `sys`, `pathlib` là thư viện chuẩn — không cần cài thêm.

---

## 💻 Cách sử dụng

### 1. Xử lý file đơn lẻ

```bash
# Cơ bản — output lưu vào thư mục mặc định
python dos_feature_filter.py data.csv

# Chỉ định file output
python dos_feature_filter.py data.csv -o filtered_output.csv
```

### 2. Xử lý cả thư mục

```bash
# Quét tất cả file .csv trong thư mục
python dos_feature_filter.py D:\CSV\CSV_Full_feature

# Chỉ định thư mục output
python dos_feature_filter.py D:\CSV\CSV_Full_feature -o D:\CSV\Filtered
```

### 3. Sử dụng đường dẫn mặc định

```bash
# Không truyền đối số — dùng đường dẫn mặc định
python dos_feature_filter.py
```

**Đường dẫn mặc định:**

| Tham số | Giá trị |
|---|---|
| Input | `D:\1LearnandStudy\Program_Language\Python\CSV\CSV_Full_feature` |
| Output | `D:\1LearnandStudy\Program_Language\Python\CSV\Filter_DoS_feature` |

### CLI Arguments

```
usage: dos_feature_filter.py [-h] [-o OUTPUT] [input]

positional arguments:
  input                 Đường dẫn file CSV hoặc thư mục chứa file CSV

optional arguments:
  -h, --help            Hiển thị trợ giúp
  -o, --output OUTPUT   Đường dẫn file/thư mục kết quả
```

---

## 🔧 API Reference

### `filter_dos_features(input_path, output_path) → pd.DataFrame`

Hàm chính — lọc đặc trưng DoS từ file CSV.

```python
from dos_feature_filter import filter_dos_features

df = filter_dos_features("raw_traffic.csv", "dos_features.csv")
print(df.shape)   # (n_rows, 28)
print(df.dtypes)  # Các cột integer đã được downcast
```

**Tham số:**

| Tham số | Kiểu | Mô tả |
|---|---|---|
| `input_path` | `str` | Đường dẫn file CSV đầu vào |
| `output_path` | `str` | Đường dẫn file CSV kết quả |

**Trả về:** `pd.DataFrame` — DataFrame đã lọc và tối ưu bộ nhớ.

---

### `process_directory(input_dir, output_dir) → None`

Xử lý hàng loạt tất cả file `.csv` trong thư mục.

```python
from dos_feature_filter import process_directory

process_directory(
    "D:/CSV/CSV_Full_feature",
    "D:/CSV/Filter_DoS_feature"
)
```

**Quy tắc đặt tên file output:**
- Nếu thư mục chỉ có **1 file** → `feature_for_DoS.csv`
- Nếu có **nhiều file** → `feature_for_DoS_1.csv`, `feature_for_DoS_2.csv`, ...

---

## ⚙️ Pipeline xử lý

Luồng xử lý dữ liệu qua 4 giai đoạn:

```
┌─────────────────┐
│   Đọc CSV gốc   │ ← pd.read_csv()
│  (40+ cột)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Chuẩn hoá tên  │ ← strip() + lower() trên tên cột
│     cột         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Lọc 28 cột     │ ← Chỉ giữ KEEP_COLUMNS
│  chuyên biệt    │   Cảnh báo cột thiếu
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│      Tối ưu bộ nhớ             │
│  ┌─────────────────────────┐   │
│  │ Chuẩn hoá categorical   │   │ ← strip + lower giá trị
│  │ (proto, state, service) │   │
│  └─────────────────────────┘   │
│  ┌─────────────────────────┐   │
│  │ Downcast integer        │   │ ← int64 → int16/int32
│  │ (17 cột số nguyên)     │   │
│  └─────────────────────────┘   │
└────────┬───────────────────────┘
         │
         ▼
┌─────────────────┐
│  Xuất CSV mới   │ ← to_csv(index=False)
│  + Báo cáo      │
└─────────────────┘
```

---

## 🧮 Chiến lược tối ưu bộ nhớ

### Integer Downcasting

Module kiểm tra **min/max** của từng cột số nguyên và chọn kiểu nhỏ nhất phù hợp:

| Kiểu | Phạm vi | Bộ nhớ/giá trị |
|---|---|---|
| `int16` | −32,768 → 32,767 | 2 bytes |
| `int32` | −2,147,483,648 → 2,147,483,647 | 4 bytes |
| `int64` | Phạm vi đầy đủ | 8 bytes (giữ nguyên) |

**17 cột được downcast:** `sport`, `dport`, `sttl`, `ct_state_ttl`, `dttl`, `sbytes`, `dbytes`, `smean`, `dmean`, `sloss`, `dloss`, `ct_srv_dst`, `ct_dst_src_ltm`, `ct_dst_sport_ltm`, `ct_src_dport_ltm`, `ct_srv_src`, `spkts`, `dpkts`.

> **An toàn:** Cột chứa `NaN` sẽ tự động bỏ qua downcast và ghi log cảnh báo.

---

## 📋 Ví dụ output log

```
2026-06-05 16:00:00 | INFO    | Đang đọc file: D:\CSV\raw_traffic.csv
2026-06-05 16:00:02 | INFO    | Dữ liệu gốc : 250000 dòng × 49 cột | Bộ nhớ: 95.37 MB
2026-06-05 16:00:02 | WARNING | ⚠  Các cột sau KHÔNG có trong file đầu vào (bỏ qua): ltime
2026-06-05 16:00:02 | INFO    | Sau lọc       : 27 cột giữ lại / 22 cột loại bỏ
2026-06-05 16:00:03 | INFO    | Bộ nhớ sau tối ưu: 31.12 MB (tiết kiệm 64.25 MB — 67.4%)
2026-06-05 16:00:03 | INFO    | ✅ Đã lưu kết quả: D:\CSV\feature_for_DoS.csv (18.45 MB)
```

---

## 📁 Cấu trúc thư mục

```
PhanLoai/
├── dos_feature_filter.py    # Module chính
├── README.md                # Tài liệu này
└── __pycache__/             # Cache bytecode Python
```

---

## 🗺️ Lộ trình phát triển

- [ ] Thêm cột `label` / `attack_cat` để phục vụ huấn luyện mô hình phân loại
- [ ] Tích hợp xử lý song song (`multiprocessing`) cho thư mục lớn
- [ ] Hỗ trợ đọc file Parquet ngoài CSV
- [ ] Thêm unit test với `pytest`
- [ ] Export báo cáo thống kê mô tả (describe) sau khi lọc

---

## 📄 Giấy phép

Dự án phục vụ mục đích học tập và nghiên cứu.

---

<p align="center">
  <i>Được xây dựng phục vụ nghiên cứu phát hiện tấn công DoS trên dữ liệu lưu lượng mạng 🔬</i>
</p>
