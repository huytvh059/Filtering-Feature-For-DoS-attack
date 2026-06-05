# 🛡️ DoS Feature Filter

> **Module lọc và tối ưu hóa đặc trưng cho phát hiện tấn công từ chối dịch vụ (DoS)**

`dos_feature_filter.py` là công cụ tối ưu hóa dữ liệu mạng CSV bằng cách lọc giữ lại **28 đặc trưng then chốt** phục vụ phát hiện tấn công DoS 
---

## 🚀 Cài đặt & Yêu cầu

### Thư viện yêu cầu:
- **Python** ≥ 3.10
- **Pandas** ≥ 1.5
- **NumPy** ≥ 1.23

Cài đặt nhanh:
```bash
pip install pandas numpy
```

---

## 💻 Cách sử dụng

Chương trình hỗ trợ cả chế độ xử lý file đơn lẻ và xử lý hàng loạt toàn bộ file `.csv` trong thư mục.

### 1. Chạy với đường dẫn mặc định
Nếu không truyền tham số, chương trình sẽ tự động quét thư mục đầu vào mặc định:
```bash
python dos_feature_filter.py
```
* **Thư mục đầu vào mặc định:** `D:\1LearnandStudy\Program_Language\Python\CSV\CSV_Full_feature`
* **Thư mục kết quả mặc định:** `D:\1LearnandStudy\Program_Language\Python\CSV\Filter_DoS_feature`

### 2. Chạy với tham số tùy chọn
```bash
# Xử lý một file cụ thể
python dos_feature_filter.py path/to/input.csv -o path/to/output.csv

# Xử lý toàn bộ file CSV trong một thư mục
python dos_feature_filter.py path/to/input_dir -o path/to/output_dir
```

---

## 🧬 28 Đặc trưng giữ lại

Bộ lọc giữ lại 28 đặc trưng quan trọng chia theo nhóm chức năng sau:

* **Metadata (Định danh):** `srcip`, `dstip`, `sport`, `dport`, `ltime`
* **Trạng thái & TTL:** `sttl`, `dttl`, `ct_state_ttl`
* **Lưu lượng (Volume):** `sbytes`, `dbytes`, `smean`, `dmean`, `rate`
* **Băng thông & Mất gói:** `sload`, `dload`, `sloss`, `dloss`
* **TCP Timing:** `tcprtt`, `synack`
* **Connection Tracking:** `ct_srv_dst`, `ct_dst_src_ltm`, `ct_dst_sport_ltm`, `ct_src_dport_ltm`, `ct_srv_src`
* **Số lượng gói tin:** `spkts`, `dpkts`
* **Phân loại (Categorical):** `proto`, `state`, `service`

---

## ⚙️ Cơ chế hoạt động & Tối ưu bộ nhớ

1. **Chuẩn hóa chuỗi:** Cắt bỏ khoảng trắng và chuyển tên cột cùng dữ liệu phân loại (`proto`, `state`, `service`) về chữ thường.
2. **Lọc đặc trưng:** Loại bỏ các cột không liên quan, chỉ giữ lại các cột cần thiết cho việc phân tích DoS.
3. **Downcast dữ liệu:** Kiểm tra phạm vi giá trị các cột số nguyên để hạ kiểu dữ liệu tự động (`int64` → `int16`/`int32`), giảm thiểu đáng kể dung lượng bộ nhớ.
