# 🛡️ DoS Feature Filter & Classifier Engine

> **Hệ thống lọc đặc trưng và phân loại cảnh báo tấn công từ chối dịch vụ (DoS)**

Hệ thống bao gồm hai module chính được thiết kế để chuẩn bị dữ liệu mạng và phát hiện cảnh báo tấn công DoS một cách tối ưu và nhanh chóng.

1. **`dos_feature_filter.py`**: Lọc giữ lại **hơn 28 đặc trưng quan trọng** (bao gồm `src_mac`, `dst_mac`) và tự động hạ kiểu dữ liệu số nguyên (downcasting) giúp tiết kiệm tới 60%+ bộ nhớ RAM.
2. **`dos_classifier.py`**: Phân tích dữ liệu đã lọc, chấm điểm rủi ro bằng cơ chế Pandas Vectorization tốc độ cao và phát xuất cảnh báo DoS có màu sắc trực quan kèm địa chỉ MAC thực tế (và xử lý chuẩn hóa gói tin L2).

---

## 🚀 Cài đặt & Yêu cầu

### Thư viện yêu cầu:
- **Python** ≥ 3.10
- **Pandas** ≥ 1.5
- **NumPy** ≥ 1.23

Cài đặt thư viện:
```bash
pip install pandas numpy
```

*(Lưu ý trên Windows nếu bạn cài nhiều bản Python, hãy sử dụng lệnh `py` thay vì `python` để đảm bảo gọi đúng môi trường đã cài thư viện).*

---

## 💻 Hướng dẫn sử dụng

### 1. Bộ lọc đặc trưng (`dos_feature_filter.py`)
Hỗ trợ cả chế độ xử lý một file đơn lẻ và xử lý hàng loạt tất cả file `.csv` trong thư mục.

* **Chạy với đường dẫn mặc định:**
  ```bash
  py dos_feature_filter.py
  ```
  * *Thư mục đầu vào mặc định:* `D:\1LearnandStudy\Program_Language\Python\CSV\CSV_Full_feature`
  * *Thư mục kết quả mặc định:* `D:\1LearnandStudy\Program_Language\Python\CSV\Filter_DoS_feature`

* **Chạy với tham số tùy chọn:**
  ```bash
  # Xử lý một file cụ thể
  py dos_feature_filter.py path/to/input.csv -o path/to/output.csv

  # Xử lý toàn bộ thư mục
  py dos_feature_filter.py path/to/input_dir -o path/to/output_dir
  ```

### 2. Bộ phân loại cảnh báo (`dos_classifier.py`)
Đọc file CSV đặc trưng đã được lọc ở trên, tính điểm rủi ro và xuất cảnh báo màu đỏ trực quan.

* **Chạy phân loại với ngưỡng mặc định (Threshold = 50):**
  ```bash
  py dos_classifier.py --csv "D:\1LearnandStudy\Program_Language\Python\CSV\Filter_DoS_feature\feature_for_DoS_2.csv"
  ```

* **Chạy phân loại với ngưỡng tùy chỉnh để xem cảnh báo rủi ro cao (ví dụ: Threshold = 80):**
  ```bash
  py dos_classifier.py --csv "D:\1LearnandStudy\Program_Language\Python\CSV\Filter_DoS_feature\feature_for_DoS_2.csv" --threshold 80
  ```

* **Truy ngược thông tin User-Agent từ Zeek log (nếu có file `http.log`):**
  ```bash
  py dos_classifier.py --csv "path/to/filtered.csv" --zeek-dir "path/to/zeek_logs_directory"
  ```

---

## ⚙️ Cơ chế hoạt động & Tính năng nổi bật

1. **Chuẩn hóa dữ liệu:** Chuyển đổi toàn bộ tên cột và dữ liệu phân loại (`proto`, `state`, `service`) về dạng chữ thường không có khoảng trắng dư thừa.
2. **Downcast dữ liệu:** Tự động tối ưu kiểu dữ liệu số (`int64` → `int16`/`int32`) để giảm dung lượng file xuất ra và tiết kiệm RAM khi xử lý số lượng dòng lớn.
3. **Chấm điểm Vectorized:** Sử dụng vectorization của thư viện Pandas để thực thi quy tắc tính điểm rủi ro trên hàng triệu dòng dữ liệu chỉ trong vài giây.
4. **Tự động chuẩn hóa MAC & L2 Frame:** 
   * Trích xuất thông tin MAC từ cột `src_mac` gốc để hiển thị thay vì `N/A`.
   * Nhận dạng nếu cột `srcip` chứa địa chỉ MAC (các gói tin tầng 2 như ARP/EAPOL), chương trình tự động đưa địa chỉ này sang cột hiển thị MAC và chuyển IP thành `N/A (L2 Frame)` giúp màn hình cảnh báo sạch và chính xác.
