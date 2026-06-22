# TÀI LIỆU PHÂN TÍCH VÀ PHÁT TRIỂN DỰ ÁN: WEB-BASED PASSWORD MANAGER

## 1. Tầm nhìn sản phẩm (Product Vision)

### Bối cảnh thị trường

Thị trường quản lý mật khẩu hiện nay đang bị chia rẽ giữa hai thái cực, và cả hai đều bộc lộ những điểm yếu chí mạng:

* **Trình quản lý mật khẩu trên Cloud (1Password, Bitwarden, LastPass):** Phụ thuộc hoàn toàn vào kết nối mạng, bắt buộc phải đăng nhập mới có thể sử dụng và không hỗ trợ chế độ ngoại tuyến (Offline) thực sự. Ngoài ra, việc lưu trữ tập trung luôn đi kèm nguy cơ rò rỉ dữ liệu diện rộng từ máy chủ trung tâm.
* **Cực đoan đối lập - KeePass và các công cụ Local:** Dù đảm bảo được tính riêng tư tại chỗ nhưng kiến trúc lại quá phức tạp. Nhiều ứng dụng trong hệ sinh thái KeePass hoàn toàn không hỗ trợ đồng bộ trực tuyến. Đáng ngại hơn, nhiều dự án kết hợp cả On/Offline đầy triển vọng trước đây nay đã bị bỏ hoang, hoặc đang sử dụng cấu trúc dữ liệu không hợp chuẩn, lỗi thời và dần ngừng hỗ trợ các giao thức Cloud (như WebDAV, Dropbox, Google Drive).

### Tầm nhìn

> "Trở thành một giải pháp quản lý mật khẩu **Tối giản – Riêng tư tuyệt đối – Truy cập vạn năng**."

Dự án hướng tới việc bắc một cây cầu hoàn hảo giữa sự an toàn của Local và sự tiện lợi của Cloud, tái định nghĩa cách người dùng bảo vệ danh tính số:

* **Hybrid On/Offline hoàn chỉnh:** Giải quyết triệt để bài toán của các dự án bị bỏ hoang. Ứng dụng hỗ trợ cơ chế hoạt động Offline thuần túy nhưng vẫn tích hợp khả năng đồng bộ Cloud chuẩn hóa, hiện đại, giúp người dùng không bị cô lập dữ liệu trên một thiết bị.
* **Quyền sở hữu dữ liệu tuyệt đối:** Không có khái niệm "máy chủ của bên thứ ba" giữ master key. Người dùng là chủ nhân duy nhất nắm giữ chìa khóa và file dữ liệu mã hóa của họ theo các chuẩn mở, hiện đại.
* **Không rào cản lắp đặt:** Chạy trực tiếp trên trình duyệt web thông qua công nghệ web thuần mà không cần cài đặt extension, không cần cài phần mềm cấu hình phức tạp.
* **Mượt mà và Hiện đại:** Giao diện tối giản, lấy cảm hứng từ triết lý thiết kế của KeeWeb nhưng tối ưu hơn về kiến trúc, mang lại trải nghiệm UI/UX kéo thả trực quan, mượt mà như một ứng dụng Native cao cấp.

---

## 2. Đơn giản hóa Kiến trúc & Công nghệ (Simplified Architecture & Tech Stack)

Dù dự án được mở rộng sâu về tính năng, cấu trúc cốt lõi vẫn tuân thủ nguyên tắc tinh gọn và không phụ thuộc vào framework (No-Framework Architecture).

### Công nghệ sử dụng

* **Front-end Core:** HTML5 (Semantic tags để tối ưu SEO/Accessibility), CSS3 (Sử dụng CSS Variables để làm giao diện Dynamic Theme), JavaScript thuần (ES6+ Module để chia tách mã nguồn sạch sẽ).


* **Định dạng dữ liệu:** Cấu trúc cây phân cấp dựa trên định dạng chuẩn JSON (`.json`).


* **Thư viện bổ trợ (Optional cho Phase sau):** Thư viện mã hóa Crypto-JS (cho AES) và một thư viện nhỏ để tính toán thuật toán mã OTP (TOTP).



### Sơ đồ luồng dữ liệu đơn giản (Data Flow)

```
[Giao diện Người dùng (UI Layer)] 
       │               ▲
       ▼ (Thao tác)    │ (Cập nhật UI)
[Lớp Xử lý Logic (Logic Layer: CRUD, OTP, i18n)]
       │               ▲
       ▼ (Đọc/Ghi)     │ (Tải dữ liệu)
[Lớp Lưu trữ (Storage Layer: Đọc/Xuất file .json)] ◄──► [Máy tính của Người dùng]

```

### Định hướng mở rộng: Máy chủ đồng bộ tương lai

Để giải quyết bài toán đồng bộ hóa đa thiết bị mà không làm phức tạp hóa hệ thống, dự án định hướng phát triển một **Sync Server** gọn nhẹ với tư duy kiến trúc:
* **Lưu trữ Core (SQLite):** Sử dụng SQLite làm cơ sở dữ liệu trung tâm trên server. SQLite lý tưởng vì tính chất "zero-configuration" (không cần cài đặt/quản trị phức tạp), lưu trữ toàn bộ data trong một file duy nhất, giúp việc sao lưu (backup) và di chuyển server cực kỳ dễ dàng. SQLite sẽ quản lý thông tin tài khoản, metadata của các phiên đồng bộ, lịch sử thay đổi (versioning) và các file dữ liệu đã mã hóa.
* **Cấu trúc lưu trữ dạng Thư mục (Directory-based Storage):** Thay vì đẩy toàn bộ file blob lớn vào database, server sử dụng cấu trúc thư mục phân cấp vật lý để lưu trữ các file dữ liệu mã hóa của người dùng (được định danh bằng Hash/UUID). Cách tiếp cận này giúp tối ưu hóa hiệu năng đọc/ghi, tận dụng tối đa hệ thống quản lý file của OS và giảm tải cho SQLite.
* **Kiến trúc tinh gọn:** Sync Server đóng vai trò là một "vùng đệm trung chuyển" (Stateless/Storage Relay). Server không giữ Master Key và không có quyền giải mã dữ liệu; nó chỉ tiếp nhận, kiểm tra tính toàn vẹn (Etag/Timestamp) và đồng bộ các gói dữ liệu đã mã hóa giữa các thiết bị.

```
[ Client App ] (Ứng dụng chạy trên Trình duyệt / Web App)
             │
             ▼ (1. Mã hóa Client-side: Pack dữ liệu thành File JSON bảo mật)
       [ Encrypted File (.json) ]
             │
             ▼ (2. Sync qua API / HTTPS)
========================================================================
[ SYNC SERVER ] (Máy chủ đồng bộ tinh gọn)
========================================================================
             │
             ├─► [ Lớp Database: SQLite ] ──► (Quản lý User Session, Metadata, Versioing)
             │
             └─► [ Lớp File System ] ──────► (Lưu trữ vật lý File mã hóa theo Thư mục)
             
```

---

## 3. Danh sách Tính năng chi tiết (Detailed Feature Specifications)

### 3.1. Nhóm tính năng cốt lõi (Core MVP Features)

* **Hệ thống Quản lý File dữ liệu (Vault Management):**
* *Khởi tạo:* Cho phép tạo mới một file dữ liệu trống với cấu trúc JSON chuẩn hóa.


* *Đọc dữ liệu:* Hỗ trợ người dùng chọn file hoặc kéo thả (Drag & Drop) file `.json` trực tiếp vào trình duyệt để giải nén dữ liệu lên giao diện.


* *Ghi dữ liệu:* Cơ chế "Save" tự động kích hoạt lệnh tải xuống (Download) file `.json` phiên bản mới nhất về máy.




* **Quản lý danh mục tài khoản (Mô hình CRUD):**
* Hỗ trợ tạo, đọc, cập nhật và xóa (CRUD) một Entry. Mỗi Entry bao gồm các trường dữ liệu bắt buộc: *Title (Tiêu đề), Username (Tên đăng nhập), Password (Mật khẩu), URL (Địa chỉ trang web), Notes (Ghi chú thêm)* và *OTP Secret (Khóa bí mật để tạo mã 2FA)*.




* **Trình tạo mật khẩu an toàn (Password Generator):**
* Công cụ tích hợp cho phép tùy chỉnh độ dài mật khẩu (từ 8 đến 64 ký tự).
* Tùy chọn bộ ký tự: Chữ hoa, chữ thường, số, và ký tự đặc biệt.
* Tích hợp nút sao chép nhanh (Copy to Clipboard) kèm tính năng tự động xóa bộ nhớ tạm sau 30 giây để đảm bảo an toàn.




* **Bộ tạo mã xác thực 2 lớp (Mã OTP/TOTP):**
* Giải mã chuỗi `OTP Secret` để tự động tính toán mã xác thực 6 chữ số theo thời gian thực (Time-based One-Time Password).


* Hiển thị một thanh đếm ngược (Countdown bar) hoặc vòng tròn thời gian 30 giây. Khi hết thời gian, mã tự động làm mới.




* **Bố cục Giao diện Chuẩn (3-Column Layout):**
* *Cột 1 (Sidebar):* Hiển thị danh mục nhóm (Ví dụ: Công việc, Cá nhân, Mạng xã hội, Ngân hàng).


* *Cột 2 (List View):* Danh sách các Entry thuộc nhóm đang chọn, hiển thị tiêu đề và username để tìm kiếm nhanh.


* *Cột 3 (Detail Panel):* Hiển thị toàn bộ thông tin chi tiết của Entry đang được click chọn.




* **Bảng lịch sử hoạt động (History Panel):**
* Một khu vực riêng ghi lại nhật ký thao tác trong phiên làm việc (Ví dụ: "Đã copy mật khẩu Facebook", "Đã cập nhật Entry Gmail lúc 14:00").




* **Hệ thống Đa ngôn ngữ (i18n):**
* Tách biệt toàn bộ chuỗi hiển thị (String) ra các file JSON ngôn ngữ riêng biệt (e.g., `en.json`, `vi.json`). Người không biết lập trình chỉ cần dịch file JSON này là có thể tích hợp ngôn ngữ mới vào hệ thống.





### 3.2. Nhóm tính năng nâng cao & Bảo mật (Phase 2)

* **Mã hóa đầu cuối (AES Encryption):** Tùy chọn đặt Master Password. Nếu có, file `.json` xuất ra sẽ được mã hóa bằng thuật toán AES, biến toàn bộ nội dung thành chuỗi ký tự vô nghĩa nếu bị mở bằng Notepad thông thường.


* **Giao diện Dynamic Material You:** Tự động thay đổi màu sắc chủ đạo của ứng dụng dựa trên hình nền người dùng chọn hoặc dựa trên hệ thống (Dark/Light mode).


* **Tự động khóa (Auto-lock):** Hệ thống theo dõi hành vi chuột/bàn phím. Nếu người dùng không hoạt động sau một thời gian cấu hình (ví dụ: 5 phút), ứng dụng tự động xóa dữ liệu trên màn hình và yêu cầu tải lại file hoặc nhập lại Master Password.



---

## 4. Tình huống sử dụng chi tiết (Scenarios)

### Tình huống 1: Thiết lập và lưu trữ dữ liệu lần đầu tiên (Onboarding & Initialization)

* **Bối cảnh:** Nguyễn Văn A là một người dùng mới, anh ấy muốn tìm một nơi an toàn để lưu trữ toàn bộ mật khẩu của mình mà không muốn đưa lên đám mây.
* **Các bước diễn ra:**
1. A truy cập vào địa chỉ website của ứng dụng. Giao diện chào mừng hiện ra với hai lựa chọn: "Tạo Vault mới" hoặc "Mở Vault có sẵn".


2. A chọn **"Tạo Vault mới"**. Hệ thống thiết lập một không gian làm việc trống bên trong bộ nhớ tạm của trình duyệt.


3. A bấm vào nút **"Thêm Entry"**, điền các thông tin cho tài khoản Facebook của mình (Username: `anv`, Password: `Click chọn nút tự động tạo mật khẩu mạnh`, URL: `facebook.com`).


4. Sau khi điền xong, A bấm nút **"Lưu thay đổi (Save)"** trên thanh công cụ.


5. Trình duyệt ngay lập tức kích hoạt tính năng tải tệp xuống và lưu một file tên là `my_vault.json` vào thư mục *Downloads* trên máy tính của A. A tắt trình duyệt, dữ liệu hoàn toàn biến mất khỏi website nhưng đã được lưu an toàn trong máy anh ấy.





### Tình huống 2: Đăng nhập hàng ngày và sử dụng mã OTP (Daily Usage & 2FA)

* **Bối cảnh:** Ngày hôm sau, anh A cần đăng nhập vào tài khoản Github đã lưu từ trước để làm việc. Tài khoản Github này yêu cầu cả mật khẩu lẫn mã xác thực 2 lớp (2FA).
* **Các bước diễn ra:**
1. A mở lại trang web ứng dụng.
2. Anh thực hiện thao tác **kéo thả tệp `my_vault.json**` từ máy tính vào vùng chỉ định trên màn hình trình duyệt.


3. Hệ thống đọc file JSON, phân tích cấu trúc dữ liệu và ngay lập tức hiển thị lại toàn bộ danh sách tài khoản của A ở cột danh sách.


4. A gõ từ khóa "Github" vào thanh tìm kiếm. Hệ thống lọc nhanh và hiển thị Entry Github ở cột giữa.
5. A click chọn "Github", bảng chi tiết bên phải xuất hiện.


6. A bấm vào biểu tượng **"Copy"** ngay cạnh ô mật khẩu để sao chép mật khẩu vào bộ nhớ tạm và dán vào trang đăng nhập Github.


7. Tại trang Github yêu cầu mã 2FA, A quay lại ứng dụng web, nhìn vào ô OTP thấy mã số `849 201` đang hiển thị kèm theo vòng tròn đếm ngược còn 12 giây. Anh lấy mã này điền vào Github và đăng nhập thành công.

---

## 5. PERSONA

### 1. Sinh viên / Học sinh
- **Tuổi:** 18 - 24
- **Nghề nghiệp:** Sinh viên đại học hoặc học sinh cấp 3
- **Nhu cầu:** Quản lý mật khẩu mạng xã hội, email học tập, tài khoản học online, ngân hàng số.
- **Điểm đau:** Hay quên mật khẩu, không muốn dùng dịch vụ đám mây.
- **Lý do chọn VaultGuard:** Miễn phí, offline, giao diện đơn giản, hỗ trợ tiếng Việt và OTP.

### 2. Freelancer / Người làm việc tự do
- **Tuổi:** 25 - 35
- **Nghề nghiệp:** Designer, Developer, Content Creator, Marketer
- **Nhu cầu:** Quản lý nhiều tài khoản khách hàng, nền tảng freelance, ngân hàng.
- **Điểm đau:** Nhiều mật khẩu khác nhau, thường xuyên thay đổi thiết bị.
- **Lý do chọn VaultGuard:** Dễ backup file .json, mã hóa mạnh, không phụ thuộc internet.

### 3. Nhân viên văn phòng
- **Tuổi:** 28 - 45
- **Nghề nghiệp:** Kế toán, hành chính, marketing, lập trình viên công ty
- **Nhu cầu:** Lưu mật khẩu công việc + cá nhân, tài khoản ngân hàng, phần mềm nội bộ.
- **Điểm đau:** Công ty hạn chế dùng password manager đám mây.
- **Lý do chọn VaultGuard:** Hoàn toàn offline, bảo mật cao, dễ sử dụng.

### 4. Developer / IT Professional
- **Tuổi:** 22 - 40
- **Nghề nghiệp:** Lập trình viên, System Admin, Security Researcher
- **Nhu cầu:** Quản lý API key, SSH, database credentials, tài khoản cloud.
- **Điểm đau:** Cần hỗ trợ OTP mạnh và custom fields.
- **Lý do chọn VaultGuard:** Mã nguồn rõ ràng, hỗ trợ TOTP tốt, có thể tùy chỉnh.

### 5. Người dùng lớn tuổi
- **Tuổi:** 50+
- **Nghề nghiệp:** Nội trợ, nghỉ hưu, kinh doanh nhỏ
- **Nhu cầu:** Lưu mật khẩu ngân hàng online, Facebook, Zalo, Shopee.
- **Điểm đau:** Giao diện phức tạp, sợ công nghệ.
- **Lý do chọn VaultGuard:** Giao diện sạch, dễ nhìn, hỗ trợ tiếng Việt đầy đủ.

### 6. Security & Privacy Enthusiast
- **Tuổi:** 20 - 35
- **Nghề nghiệp:** Sinh viên an ninh mạng, lập trình viên, người quan tâm bảo mật
- **Nhu cầu:** Kiểm soát hoàn toàn dữ liệu cá nhân.
- **Điểm đau:** Không tin tưởng các dịch vụ thương mại.
- **Lý do chọn VaultGuard:** Mã hóa client-side, không lưu dữ liệu trên server.

---

## 6. Danh sách User Stories (Kiến trúc hóa theo chuẩn Agile)

### 6.1. Phân hệ Quản lý Tệp tin (Vault Management)

* **User Story 1: Khởi tạo dữ liệu nhanh**
* *Là một* người dùng mới sử dụng hệ thống lần đầu,
* *Tôi muốn* có thể tạo nhanh một cơ sở dữ liệu trống chỉ bằng một cú click chuột,
* *Để* tôi có thể bắt đầu tổ chức và thêm các tài khoản cá nhân của mình ngay lập tức mà không phải qua các bước đăng ký rườm rà.




* **User Story 2: Tải và tiếp tục làm việc**
* *Là một* người dùng quay trở lại sử dụng ứng dụng,
* *Tôi muốn* có thể kéo và thả tệp dữ liệu `.json` cũ của mình vào giao diện web,
* *Để* hệ thống tự động tải và hiển thị lại toàn bộ các mật khẩu tôi đã lưu trước đó một cách nhanh chóng.





### 6.2. Phân hệ Thao tác Dữ liệu Tài khoản (Account Entry Management)

* **User Story 3: Thêm mới tài khoản chi tiết**
* *Là một* người dùng có nhiều tài khoản mạng xã hội,
* *Tôi muốn* tạo mới một mục lưu trữ chứa đầy đủ thông tin từ Tiêu đề, Tên đăng nhập, Mật khẩu, Đường dẫn Web cho tới các ghi chú riêng tư,
* *Để* tôi không bao giờ bị quên các thông tin phụ liên quan đến tài khoản đó.




* **User Story 4: Sinh mật khẩu ngẫu nhiên độ an toàn cao**
* *Là một* người dùng chuẩn bị đăng ký tài khoản ngân hàng mới,
* *Tôi muốn* hệ thống tự động gợi ý một chuỗi mật khẩu ngẫu nhiên bao gồm cả ký tự đặc biệt và chữ số với độ dài tùy chọn,
* *Để* tôi đảm bảo tài khoản mới của mình có độ bảo mật cao nhất mà không cần vắt óc tự nghĩ mật khẩu.





### 6.3. Phân hệ Tiện ích & Trải nghiệm Người dùng (Utilities & UX)

* **User Story 5: Tích hợp mã xác thực hai lớp (2FA)**
* *Là một* người dùng coi trọng bảo mật lớp kép,
* *Tôi muốn* ứng dụng tự động hiển thị mã OTP 6 số và đếm ngược thời gian từ chuỗi mã Secret tôi đã cung cấp,
* *Để* tôi có thể hoàn tất đăng nhập hai lớp trực tiếp trên một màn hình mà không cần mở ứng dụng điện thoại (như Google Authenticator).




* **User Story 6: Bản địa hóa ngôn ngữ**
* *Là một* người dùng không thành thạo tiếng Anh,
* *Tôi muốn* có thể chuyển đổi toàn bộ giao diện sang các ngôn ngữ khác một cách dễ dàng,
* *Để* tôi có thể hiểu chính xác chức năng của từng nút bấm và thao tác không bị nhầm lẫn.


Dưới đây là bảng **Product Backlog** hoàn chỉnh, được thiết kế theo chuẩn Agile/Scrum. Mỗi hạng mục (Backlog Item) đều có đầy đủ mô tả, tiêu chí nghiệm thu (Acceptance Criteria), độ ưu tiên và được phân chia rõ ràng theo các Phase đã định hình từ file `pre.md`.

---


# PRODUCT BACKLOG: WEB-BASED PASSWORD MANAGER

| Mã ID | Tính năng / Hạng mục | Mô tả ngắn gọn | Tiêu chí nghiệm thu cốt lõi | Độ ưu tiên |
| :--- | :--- | :--- | :--- | :--- |
| P1-01 | Khung UI 3 cột | Dựng giao diện thuần theo cảm hứng KeeWeb | \- Hiển thị đủ Sidebar, Danh sách và Panel chi tiết.&lt;br&gt;- Giao diện Responsive trên PC bằng CSS thuần. | Bắt buộc |
| P1-02 | Đọc/Ghi file JSON | Tạo mới, import và xuất tệp dữ liệu cục bộ | \- Kéo thả file .json để tải dữ liệu lên web.&lt;br&gt;- Bấm “Save” kích hoạt tải file .json mới về máy. | Bắt buộc |
| P1-03 | CRUD tài khoản | Xử lý các thao tác tương tác với mật khẩu | \- Thêm, sửa, xóa thành công một mục tài khoản.&lt;br&gt;- Click chọn mục nào hiển thị đúng chi tiết mục đó. | Bắt buộc |
| P1-04 | Tiện ích Mật khẩu | Bộ công cụ hỗ trợ xử lý chuỗi mật khẩu | \- Tự sinh mật khẩu mạnh ngẫu nhiên theo yêu cầu.&lt;br&gt;- Có nút ẩn/hiện (\*) và nút sao chép nhanh. | Bắt buộc |
| P1-05 | Bộ đếm mã OTP | Tự động sinh mã 2FA từ khóa Secret | \- Hiển thị chính xác mã OTP 6 số theo thời gian thực.&lt;br&gt;- Tự làm mới mã sau mỗi 30 giây. | Bắt buộc |
| P1-06 | Đa ngôn ngữ & Lịch sử | Tích hợp i18n và bảng nhật ký hoạt động | \- Đổi ngôn ngữ (Anh/Việt) không cần tải lại trang.&lt;br&gt;- Bảng History hiện đúng nhật ký thao tác vừa làm. | Bắt buộc |
| P2-01 | Mã hóa file AES | Bảo vệ file JSON bằng Master Password | \- File tải về được mã hóa thành chuỗi ký tự vô nghĩa.&lt;br&gt;- Yêu cầu nhập đúng Master Password để giải mã. | Bắt buộc |
| P2-02 | Tự động khóa | Tự khóa màn hình khi người dùng rời máy | \- Sau 5 phút không hoạt động chuột/phím, RAM tự xóa dữ liệu.&lt;br&gt;- Hiển thị màn hình khóa yêu cầu nhập lại mật khẩu. | Nên có |
| P2-03 | Theme Material You | Nâng cấp thẩm mỹ giao diện động hiện đại | \- Chuyển đổi mượt mà chế độ Sáng/Tối.&lt;br&gt;- Màu sắc giao diện thay đổi đồng bộ theo hệ thống. | Nên có |
| P2-04 | Kéo thả sắp xếp | Tối ưu hóa trải nghiệm điều hướng danh mục | \- Dùng chuột kéo thả tài khoản vào các nhóm ở Sidebar.&lt;br&gt;- Bảng Settings cho phép chỉnh thời gian tự khóa linh hoạt. | Nên có |
| P3-01 | Hệ thống Server Sync | Xây dựng máy chủ đồng bộ dữ liệu tập trung | \- Triển khai API đăng ký, đăng nhập và phân quyền trên SQLite.&lt;br&gt;- Hỗ trợ upload/download các tệp vault đã mã hóa lên máy chủ. | Bắt buộc |
| P3-02 | Bảo mật đường truyền | [DA phụ trách] Mã hóa gói tin và xác thực an toàn | \- Băm mật khẩu trước khi gửi lên mạng.&lt;br&gt;- Áp dụng mã hóa phiên và token JWT để chặn đánh chặn dữ liệu. | Có thể có |
| P3-03 | Responsive Mobile UI | Tối ưu hóa layout thích ứng với màn hình nhỏ | \- Tự động ẩn Sidebar thành menu trượt khi viewport thu nhỏ.&lt;br&gt;- Sắp xếp lại danh sách entry theo chiều dọc phù hợp với di động. | Bắt buộc |
| P3-04 | Gọt giũa cấu trúc GUI | Loại bỏ cấu phần thừa và tối ưu hóa điều hướng | \- Loại bỏ một sô nút thừa, thay đổi GUI để cùng lúc phù hợp với nhiều thiết bị khác nhau. | Bắt buộc |
