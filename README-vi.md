# 🔐 Trình Quản Lý Mật Khẩu Ngoại Tuyến Bảo Mật & Tiện Lợi

Một ứng dụng quản lý thông tin đăng nhập, tài khoản và mật khẩu bảo mật cao, hoạt động **100% ngoại tuyến (offline-first)** trên trình duyệt, lấy cảm hứng từ cấu trúc thiết kế của KeeWeb kết hợp cùng ngôn ngữ thiết kế Material You / Material 3 hiện đại.

Dự án được xây dựng tối giản, tối ưu hóa hiệu năng bằng các công nghệ web thuần túy (**HTML5**, **Tailwind CSS v4** và **TypeScript**), mang lại tốc độ tải tức thì, dung lượng bundle siêu nhẹ và khả năng tương thích tối đa trên mọi thiết bị.

---

## ✨ Các Tính Năng Nổi Bật

### 📱 1. Thiết Kế Giao Diện Tùy Biến Thẩm Mỹ Cao (Material You)
- **Bảng Màu Thích Ứng Động**: Khách hàng có thể tải lên hình nền yêu thích hoặc nhập mã màu HEX để ứng dụng tự động trích xuất tông màu chủ đạo, tính toán cường độ bão hòa màu và áp dụng thiết kế Material 3 đồng nhất ngay lập tức.
- **Tùy Chọn Độ Tương Phản Đa Dạng**: Hỗ trợ đầy đủ ba mức độ tương phản: Tiêu chuẩn (Standard), Trung bình (Medium) và Cao (High) nhằm tuân thủ nghiêm ngặt các quy chuẩn tiếp cận nội dung WCAG (A11y).
- **Chuyển Động Trực Quan Mượt Mà**: Sở hữu hiệu ứng tải danh bạ lướt nhẹ, hiệu ứng chuyển màu mềm mại và khả năng hỗ trợ mượt mà cho các thiết bị di động.

### 🛡️ 2. Bảo Mật và Tự Chủ Dữ Liệu Tuyệt Đối
- **Xem và Thao Tác Hoàn Toàn Ngoại Tuyến**: Không có bất kỳ kết nối mạng nào bị bắt buộc để truyền tải dữ liệu mật khẩu của bạn. Toàn bộ tên đăng nhập, mã khóa bí mật, nhãn lưu trữ đều được xử lý cục bộ trên thiết bị của bạn.
- **Hỗ Trợ Định Dạng Vault JSON Linh Hoạt**: Cho phép khởi tạo kho khóa mới, mở các kho khóa hiện có hoặc xuất dữ liệu tức thời. Hỗ trợ cả định dạng lưu trữ file JSON thông thường lẫn mã hóa AES-GCM 256-bit sử dụng Mật khẩu chính (Master Password) cực kỳ an toàn.
- **Công Cụ Gộp & Trộn Kho Khóa**: Dễ dàng gộp các file sao lưu cơ sở dữ liệu mật khẩu từ các thiết bị khác nhau với thuật toán kiểm soát trùng lặp thông minh.

### 🔑 3. Tiện Ích Bảo Mật Nâng Cao Tích Hợp
- **Bộ Mã Hóa OTP Theo Thời Gian (TOTP)**: Tích hợp sẵn module giải mã khóa Base32 và thuật toán băm chữ ký số HMAC-SHA1. Liên tục cập nhật và hiển thị vòng xoay đếm ngược 30 giây để tự động tạo và sao chép mã 2FA không cần internet.
- **Bộ Tạo Mật Khẩu Mạnh Mẽ**: Tùy chỉnh độ dài, ký tự viết hoa, viết thường, chữ số, biểu tượng đặc biệt hoặc từ đồng âm dễ đọc. Thanh màu trực quan giúp đánh giá mức độ bảo mật/entropy của mật khẩu theo thời gian thực.
- **Xóa Vết Bộ Nhớ Đệm (Safe Clipboard)**: Tự động dọn dẹp và làm rỗng Clipboard sau đúng 15 giây kể từ khi sao chép mật khẩu, giúp loại bỏ tối đa nguy cơ rò rỉ thông tin từ các phần mềm theo dõi bộ nhớ đệm bên thứ ba.

### 🌐 4. Bản Địa Hóa Hệ Thống Hoàn Chỉnh (i18n)
Hệ thống hiển thị đa ngôn ngữ dịch nội dung hoàn toàn tự động:
- 🇺🇸 Tiếng Anh (Mặc định)
- 🇻🇳 Tiếng Việt 
- 🇪🇸 Tiếng Tây Ban Nha
- 🇫🇷 Tiếng Pháp

---

## 🏗️ Kiến Trúc Hệ Thống & Đặc Tả Kỹ Thuật

### 1. Định Nghĩa Cấu Trúc Dữ Liệu
Các thực thể dữ liệu trong cơ sở dữ liệu lưu trữ được mô hình hóa nghiêm ngặt trong file `src/types.ts` để đảm bảo an toàn kiểu dữ liệu (Type-Safety) trong suốt chu kỳ chạy của ứng dụng:
```typescript
interface VaultData {
  vaultName: string;
  lastModified: string;
  groups: Group[];
  entries: Entry[];
}

interface Group {
  id: string;
  name: string;
  icon: string; // Tên định danh biểu tượng Lucide
}

interface Entry {
  id: string;
  groupId: string; // Khóa học liên kết tới nhóm thư mục tùy chỉnh
  title: string;
  username: string;
  password?: string;
  url: string;
  notes: string;
  totpSecret?: string; // Chuỗi khóa bảo mật Base32 tiêu chuẩn cho 2FA
  tags: string[];
  modified: string;
}
```

### 2. Cơ Chế Tạo OTP (TOTP)
TOTP hoạt động bằng cách giải mã chuỗi Base32 đại diện thành cấu trúc mảng byte, tính toán chỉ số khối thời gian Unix hiện hành ($T = \lfloor \text{currentTime} / 30 \rfloor$), băm bằng mã HMAC-SHA1 và thực hiện cắt phân đoạn động (Dynamic Truncation):
1. **Giải mã Base-32**:
   Chuyển đổi các khóa bí mật của ứng dụng được mã hóa dạng chuỗi Base-32 thành mảng nhị phân `Uint8Array`.
2. **Ký Số HMAC-SHA1**:
   Thực thi việc băm chữ ký số bảo mật với thông điệp là khối số nguyên đại diện cho chu kỳ thời gian ($T$).
3. **Cắt Phân Đoạn & Trích Xuất**:
   Cắt lấy 4 byte từ mã hash nhận được, sử dụng giá trị modulo $10^6$ để xuất ra dãy số PIN 6 chữ số đại diện chính xác.

### 3. Tiến Trình Clipboard Daemon Bảo Vệ Clipboard
Khi người dùng kích hoạt sao chép một bí mật, một bộ đếm thời gian an toàn sẽ bắt đầu theo dõi. Sau 15 giây, tiến trình thực thi tác vụ xóa dữ liệu bộ nhớ đệm nếu chuỗi ký tự trong clipboard khớp với nội dung được sao chép ban đầu.

---

## 📂 Tổ Chức Thư Mục Mã Nguồn

Dự án sở hữu sơ đồ thư mục khoa học và mạch lạc:
- **`index.html`**: Giao diện ứng dụng chính hỗ trợ responsive, định hình các ô chứa bên trái, giữa và khung thông tin chi tiết bên phải cùng modal.
- **`src/main.ts`**: Điểm khởi chạy của ứng dụng, tải instance điều khiển chính.
- **`src/index.css`**: Nơi nhúng các lớp tiện ích của Tailwind CSS v4, khai báo các biến Material You trong thẻ `:root` và `:root.dark`.
- **`src/app.ts`**: Bộ não điều khiển trung tâm quản lý trạng thái, vòng đời ứng dụng, đa ngôn ngữ, mã hóa mật khẩu, dọn dẹp clipboard, đồng bộ hóa lịch sử và phím tắt.
- **`public/translations/`**: Các tài liệu JSON chứa định nghĩa bản dịch ngôn ngữ tương ứng (`en.json`, `vi.json`, v.v.).

---

## 🚀 Khởi Chạy Dự Án Cục Bộ

Hãy chắc chắn rằng máy tính của bạn đã được cài đặt sẵn **Node.js** (phiên bản v18 trở lên).

### 1. Cài Đặt Thư Viện
Tải toàn bộ các thư viện cần thiết phục vụ quá trình biên dịch thông qua câu lệnh:
```bash
npm install
```

### 2. Chạy Chế Độ Phát Triển (Development)
Khởi chạy máy chủ Vite cục bộ với hiệu năng cao giúp bạn xem thử thay đổi ngay lập tức:
```bash
npm run dev
```

---

## 🎨 Hướng Dẫn Tùy Chỉnh Giao Diện

Bạn có thể chỉnh sửa giao diện bằng cách vào **Settings (Biểu tượng Bánh răng) -> Theme**:
1. **Chọn Giao Diện Đã Có**: Lựa chọn giữa các tổ hợp màu trang nhã đã được phối sẵn (Teal, Blue, Ruby, Amber).
2. **Nhập Mã Màu Tùy Chọn**: Gõ trực tiếp mã màu HEX hoặc nhấp chuột vào vòng tròn chọn màu tự động của hệ điều hành.
3. **Trích Xuất Mã Màu Từ Hình Nền**: Kéo thả tấm hình nền phong cảnh của bạn vào mục Wallpaper Upload. Hệ thống xử lý thông số pixel của tấm ảnh, trích xuất cấu trúc dải màu sáng tối và phối màu cho toàn bộ không gian làm việc của bạn ngay lập tức!
