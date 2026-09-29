# Hướng dẫn cho đồng đội — Windows

Bản này dành cho người **viết code**, không phải người vận hành pipeline. Bạn không cài Docker, không cài Semgrep, không cài Python. Chỉ cần Git và tài khoản GitHub.

Việc kiểm tra bảo mật nằm **trên GitHub**, không nằm trên máy bạn. Bạn không phải bấm gì để nó chạy, và cũng không có cách nào né nó.

---

## 1. Cài một lần

1. Tải Git for Windows: https://git-scm.com/download/win — cài với mọi lựa chọn mặc định.
2. Mở **Command Prompt** (gõ `cmd` vào Start), khai tên và email dùng cho commit:

```
git config --global user.name "Ten Cua Ban"
git config --global user.email "email-ban-dung-tren-github@example.com"
git config --global core.editor notepad
```

Dòng cuối để Git mở Notepad thay vì Vim khi cần soạn nội dung — Vim không thoát được nếu chưa quen.

3. Nhận lời mời Collaborator trong email từ GitHub.

4. Kéo repo về:

```
cd C:\Users\<ten-ban>\Documents
git clone https://github.com/vhuy811/<TEN-REPO-APP>.git
cd <TEN-REPO-APP>
```

Lần đầu push, Windows sẽ mở cửa sổ đăng nhập GitHub. Đăng nhập một lần, những lần sau tự nhớ.

---

## 2. Quy trình hằng ngày — 5 lệnh

Không bao giờ làm việc trực tiếp trên `main`. Mỗi việc một nhánh.

```
git checkout main
git pull
git checkout -b tinh-nang/ten-viec-ban-lam
```

Sửa code. Rồi:

```
git add .
git commit -m "Mo ta ngan gon viec vua lam"
git push -u origin tinh-nang/ten-viec-ban-lam
```

Git sẽ in ra một đường link dạng `https://github.com/vhuy811/<repo>/pull/new/...` — mở link đó trong trình duyệt, bấm **Create pull request**.

**Mở PR là lúc pipeline chạy.** Push lên nhánh của bạn không tự quét — nên đừng chờ, mở PR ngay (chọn *Draft* nếu chưa xong). Từ đây bạn không làm gì nữa.

---

## 3. Đọc kết quả

Ở cuối trang Pull Request có một danh sách check. Bốn cái quan trọng:

| Check | Nghĩa | Chặn merge? |
|---|---|---|
| `security / scan` | pipeline chạy xong (build, quét, đẩy kết quả) | không — nó chỉ là "đã chạy" |
| **`Code scanning results / Semgrep-du-an`** | phân tích mã nguồn bằng rule của nhóm | **có** — khi có lỗi mức ERROR mới |
| **`Code scanning results / OWASP-ZAP`** | tấn công thử vào bản app dựng từ code của bạn | **có** — khi khai thác được lỗi mức High |
| **`security / dependency-review`** | thư viện bạn vừa thêm/nâng | **có** — khi gói mới dính CVE ≥ High |

| Bạn thấy | Làm gì |
|---|---|
| Vòng tròn vàng | đang quét, ~6 phút — chờ |
| Tất cả tick xanh, Merge xám | chưa ai approve — nhờ người trong nhóm review |
| Một check **đỏ** | xem mục 4 |

Chỉ chặn phần **bạn vừa thêm**. Lỗi có sẵn từ trước không đổ lên đầu bạn.

---

## 4. Khi bị đỏ

1. Bấm vào check `security / scan` → **Summary**. Có bảng: *ở đâu · lỗi gì · cách sửa*. Dòng có 🔥 là lỗi **đã bị khai thác thật** trên app — sửa cái đó trước.
2. Hoặc mở tab **Files changed** — chú thích đỏ nằm ngay trên dòng code bị báo, kèm cách sửa.
3. Sửa đúng chỗ đó. Ví dụ hay gặp nhất — SQL Injection:

```csharp
// SAI: nối chuỗi
cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = '" + ten + "'";

// ĐÚNG: tham số hoá
cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = @ten";
cmd.Parameters.AddWithValue("@ten", ten);
```

4. Commit và push lại lên **cùng nhánh** — pipeline tự chạy lại:

```
git add .
git commit -m "Sua SQL Injection o SanPham/Tim"
git push
```

Check đỏ vì thư viện: xem lý do trong check `dependency-review`, nâng gói lên bản đã vá (`dotnet add package <ten>`) hoặc chọn gói khác.

---

## 5. Báo nhầm thì sao

Có. Không sửa code để né, không thêm `// nosemgrep`. Làm thế này:

1. Tab **Security** của repo → **Code scanning** → mở alert đó.
2. Bấm **Dismiss alert** → chọn lý do: *False positive* / *Won't fix* / *Used in tests* → ghi một câu vì sao → Dismiss.
3. Check tự chạy lại xanh. Lần sau cùng chỗ đó không báo nữa.

GitHub ghi lại ai dismiss, lý do gì, lúc nào. Người review thấy được. Dismiss không có lý do thuyết phục thì reviewer mở lại alert.

Nếu một rule báo nhầm liên tục, nói với người giữ bộ công cụ — rule đó sẽ được hạ mức ở nguồn, cho cả nhóm, thay vì mỗi người dismiss một lần.

---

## 6. Ba quy ước

**Không push lên `main`.** GitHub từ chối với lỗi `GH013: Repository rule violations found`. Thấy lỗi đó là đang ở sai nhánh — `git checkout -b ten-nhanh-moi` rồi push lại.

**Không tự approve PR của mình.** Nhờ người khác trong nhóm.

**Không commit khoá API, mật khẩu, token.** GitHub chặn ngay lúc push. Nếu là khoá thật thì phải **thu hồi** ở nhà cung cấp — xoá commit không gỡ được nó khỏi lịch sử.

---

## 7. Khi được nhờ review

1. Mở PR, tab **Files changed**. Đọc phần đổi.
2. Nhìn ba check chặn ở cuối trang: xanh chưa. Nếu có alert bị dismiss trong PR này, lý do có thuyết phục không.
3. Bấm **Review changes** → **Approve** hoặc **Request changes** kèm nhận xét.

Bạn không phải triage cảnh báo bảo mật — máy đã làm. Bạn review logic, tên biến, test, và những gì máy không thấy.

---

## 8. Lỗi hay gặp

| Lỗi | Nguyên nhân | Sửa |
|---|---|---|
| `GH013: Repository rule violations found` | push thẳng lên main | `git checkout -b nhanh-moi` rồi push lại |
| PR treo ở *"Expected — waiting for status"* | cấu hình phía repo, không phải lỗi bạn | báo người quản lý repo |
| `fatal: not a git repository` | đang đứng sai thư mục | `cd` vào thư mục repo |
| Vim mở ra, không thoát được | chưa đặt `core.editor` | gõ `Esc` rồi `:q!` Enter; sau đó chạy lệnh `git config` ở mục 1 |
| `Your branch is behind` | main đã có commit mới | `git pull origin main` rồi giải quyết xung đột nếu có |
