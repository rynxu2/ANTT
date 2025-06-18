# ANTT - Hệ Thống Chuyển File Bảo Mật

ANTT là hệ thống chuyển file bảo mật, hỗ trợ lưu trữ cục bộ và Google Drive, sử dụng mã hóa đầu-cuối, chữ ký số, xác thực và cập nhật trạng thái theo thời gian thực.

## Tính Năng Nổi Bật

### Bảo Mật
- Tạo cặp khóa RSA 2048-bit cho từng IP/host.
- Mã hóa file bằng AES-256-CBC, khóa phiên sinh ngẫu nhiên.
- Chữ ký số RSA-PSS với SHA-512.
- Xác thực toàn vẹn file và người gửi.
- Quản lý khóa phiên, trao đổi khóa an toàn (OAEP).

### Chuyển File
- Tải lên file cục bộ (drag & drop).
- Tích hợp Google Drive, tự động tạo thư mục host.
- Tải xuống file an toàn, kiểm tra toàn vẹn.
- Theo dõi trạng thái, tiến trình chuyển file.
- Tổ chức file theo host.

### Quản Lý Host
- Hỗ trợ nhiều host, lưu trữ tách biệt.
- Quản lý khóa riêng cho từng host.
- Hệ thống yêu cầu tham gia, phê duyệt, kiểm soát truy cập.

### Thời Gian Thực
- Cập nhật trạng thái qua WebSocket (Socket.IO).
- Thông báo sự kiện, tiến trình chuyển file trực tiếp.

## Kiến Trúc & Công Nghệ

- **Backend:** Flask, SQLAlchemy ORM, Flask-SocketIO, Eventlet.
- **Bảo mật:** cryptography (RSA, AES, SHA-512, OAEP, PSS).
- **Lưu trữ:** File hệ thống & Google Drive API v3.
- **Frontend:** HTML5, CSS3, Bootstrap 5, JavaScript (ES6+), Socket.IO client.

## Cài Đặt & Khởi Động

### Yêu Cầu
- Python 3.9+
- pip
- Node.js (nếu phát triển frontend)
- Google Cloud Project (bật Drive API, tải file client_secret_*.json)

### Hướng Dẫn

1. **Clone dự án:**
   ```powershell
   git clone <repository-url>
   cd ANTT
   ```
2. **Tạo và kích hoạt môi trường ảo:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate
   ```
3. **Cài đặt phụ thuộc:**
   ```powershell
   pip install -r requirements.txt
   ```
4. **Cấu hình Google Drive:**
   - Tạo project trên Google Cloud Console, bật Drive API.
   - Tạo OAuth 2.0 credentials, tải file client_secret_*.json về thư mục gốc dự án.
5. **Chạy server:**
   ```powershell
   python main.py
   ```

## Sử Dụng
- Truy cập `http://localhost:5000` để sử dụng giao diện web.
- Đăng ký host, gửi/nhận file, theo dõi trạng thái chuyển file theo thời gian thực.

## Cấu Trúc Dự Án
```
ANTT/
├── app.py              # Điểm khởi động
├── main.py             # Khởi chạy app
├── routes.py           # API endpoints
├── models.py           # Database models
├── crypto_utils.py     # Hàm mã hóa
├── drive_utils.py      # Google Drive
├── storage_utils.py    # Lưu trữ file
├── events.py           # WebSocket events
├── static/             # Tài nguyên frontend
│   ├── js/
│   └── css/
└── templates/          # HTML templates
```