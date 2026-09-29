# Hướng dẫn sử dụng

Quy trình DevSecOps năm tầng — dùng hằng ngày, cài lên máy mới, và áp cho dự án khác.

---

## 1. Ai kiểm tra, lúc nào, chặn gì

Bạn không tự chạy quét. Kiểm tra nằm trên GitHub, kích hoạt khi mở Pull Request; **khoá merge** cũng là GitHub làm — qua Code Scanning và ruleset — không phải pipeline tự chặn.

| Lúc nào | Cái gì chạy | Chặn gì |
|---|---|---|
| `git commit` (máy dev) | hook pre-commit, nếu có cài — Semgrep trên tệp đang sửa | không — chỉ tư vấn, bỏ qua được |
| `git push` | GitHub push protection quét secret | **chặn push** có khoá/mật khẩu |
| mở PR / push thêm vào PR | pipeline đủ 5 tầng trên máy ảo tạm; kết quả → Code Scanning | **khoá merge** khi có: cảnh báo ERROR mới của rule dự án · alert High mới của ZAP · gói mới dính CVE ≥ High |
| bấm Merge | GitHub kiểm ruleset: check xanh + 1 approve + nhánh cập nhật | **nút Merge khoá** nếu thiếu |
| commit vào `main` (sau merge) | pipeline chạy lại, làm mốc so sánh cho PR sau | không — không còn gì để chặn |
| 01:00 thứ Ba | quét định kỳ (repo dùng mẫu `vi-du-repo-khac.yml`) | không — alert mới hiện ở tab Security; CVE mới trên gói đang dùng thì Dependabot gửi email |

Dashboard cục bộ (`tools/webui.py`) không nằm trong luồng này. Nó để điều tra và trình diễn.

---

## 2. Tham gia một dự án có sẵn

### Làm một lần

```bash
git clone <repo-cua-du-an>
cd <ten-du-an>
python C:\path\to\VulnShop\tools\pre_commit_scan.py --install
```

Lệnh thứ ba cài hook vào **repo bạn đang đứng**, trỏ ngược về bộ công cụ. Mỗi repo cài một lần. Hook nằm trong `.git/hooks/` nên không đi theo git — người khác trong nhóm phải tự cài trên máy họ.

### Hằng ngày

```bash
# sửa code như bình thường
git add .
git commit -m "..."      # <- hook tự quét các tệp đang commit
git push                 # <- lên nhánh của bạn, chưa quét
```

Rồi mở Pull Request (link git in ra sau khi push). **Mở PR là lúc CI chạy đủ năm tầng.** Push lên nhánh phụ không tự quét — cố ý: mỗi PR chỉ có một check, so với một mốc là `main`. Muốn quét sớm thì mở PR dạng draft.

Không mở dashboard, không chạy lệnh quét nào.

Hook in ra một trong ba kết quả:

| Hook nói gì | Nghĩa là | Làm gì |
|---|---|---|
| `da quet, khong co loi muc ERROR` | đã quét, sạch | commit đi tiếp |
| `COMMIT BI CHAN - N loi muc ERROR` | tìm thấy lỗi trong phần bạn vừa sửa | sửa rồi commit lại |
| `KHONG QUET DUOC` | Docker tắt hoặc thiếu semgrep | commit vẫn qua, nhưng **chưa ai kiểm tra gì** — CI sẽ quét lại |

Dòng thứ ba quan trọng. Nó **không** nói mã nguồn sạch, nó nói chưa kiểm tra được. Hai chuyện đó khác nhau.

### Khi hook báo mà bạn chắc là báo nhầm

Hook chỉ tư vấn — commit vẫn đi tiếp nếu bạn muốn. Báo nhầm thật sự được xử lý **ở PR**, trong tab Security → Dismiss alert kèm lý do. Không thêm `// nosemgrep` vào code: pipeline không đọc nó, và nó giấu vấn đề khỏi người review.

---

## 3. Cài lên một máy khác

### Cần có sẵn

| Phần mềm | Dùng cho | Bắt buộc? |
|---|---|---|
| Docker Desktop | Semgrep, Trivy, ZAP, Gitleaks | có |
| Python 3.9+ | toàn bộ script | có |
| .NET SDK | tầng thư viện và build app | chỉ khi quét dự án .NET |
| Git | hook pre-commit | có |

### Các bước

```bash
git clone https://github.com/vhuy811/DevSecOps_VHNAT.git
cd DevSecOps_VHNAT
pip install requests
python kiem_tra_moi_truong.py
```

Lệnh cuối kiểm tra 9 điều kiện cùng lúc và in ra bảng kèm lệnh sửa cho từng mục còn thiếu. Chạy nó trước khi nghi ngờ bất cứ thứ gì khác.

Muốn dùng tầng động thì bật thêm ZAP:

```bash
docker run -d --name zap -p 8090:8090 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true
```

ZAP cần 20–40 giây mới sẵn sàng.

---

## 4. Cách 1 — Dashboard

Dùng khi muốn nhìn toàn cảnh một repo, so sánh hai dự án, hoặc trình diễn.

### Bước 1

```bash
cd C:\path\to\VulnShop
python tools\webui.py
```

Trình duyệt tự mở `http://localhost:8000`.

### Bước 2 — Tab Tổng quan

Xem bảng điều kiện. Mọi dòng phải xanh trước khi quét. Dòng nào đỏ thì bảng đã ghi sẵn cách sửa.

### Bước 3 — Tab Chạy quét

| Ô | Điền gì |
|---|---|
| Đường dẫn thư mục mã nguồn | đường dẫn tuyệt đối tới repo cần quét — **repo nào cũng được**, không cần là VulnShop |
| Tên hiển thị | tên đặt trên báo cáo |
| URL ứng dụng | `http://host.docker.internal:5000` — hoặc **để trống** nếu app không chạy |

Ô URL là địa chỉ **ZAP nhìn thấy**, không phải địa chỉ trên trình duyệt bạn. ZAP nằm trong container nên `localhost` với nó là chính nó.

App vẫn chạy bình thường ở `localhost:5000`, chỉ ô này điền khác.

Để trống ô URL thì tầng 5 bị bỏ qua — đó là lựa chọn hợp lệ khi app cần cơ sở dữ liệu mà bạn không dựng.

### Bước 4 — Tab Kết quả

Đọc nhãn ở tầng 5:

| Nhãn | Nghĩa |
|---|---|
| **CONFIRMED** | ZAP khai thác được thật trên app đang chạy |
| **FILTERED** | tìm thấy hàm khử độc nằm trên đúng luồng dữ liệu đó |
| **UNCONFIRMED** | chưa có bằng chứng theo chiều nào — **nợ kiểm thử, không phải an toàn** |

Ba nhãn này là cách **dashboard** trình bày kết quả đối chiếu để điều tra tại máy. Trên GitHub, cổng không dùng chúng: mọi cảnh báo ERROR mới của rule dự án đều chặn, ZAP chỉ thêm nhãn *đã khai thác được* để ưu tiên — không bao giờ để bỏ qua.

---

## 5. Cách 2 — CI trên GitHub

Dùng cho mọi dự án thật. Tự động, không cần ai nhớ bấm gì.

### Bước 1 — Tạo tệp gọi

Trong repo cần bảo vệ, tạo `.github/workflows/bao-mat.yml`:

```yaml
name: Bao mat
# Chi PR va main - quet moi push len nhanh phu thi mot commit co HAI check
# cung ten, so voi hai moc khac nhau.
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

# Bat buoc: workflow duoc goi xin security-events de day SARIF len Code
# Scanning. Thieu khoi nay thi lan chay bao "Startup failure" ngay lap tuc.
permissions:
  contents: read
  security-events: write

jobs:
  security:
    uses: vhuy811/DevSecOps_VHNAT/.github/workflows/devsecops-reusable.yml@main
    with:
      project-file: src/Web/Web.csproj
      run-dast: false
```

Chỉ vậy. Không copy `tools/`, không copy `semgrep-rules/` — pipeline tự kéo về lúc chạy.

### Bước 2 — Chọn tham số cho đúng dự án

| Tham số | Khi nào đổi |
|---|---|
| `project-file` | đường dẫn `.csproj`. Để `''` nếu không phải .NET |
| `run-dast` | `false` nếu app cần CSDL, không khởi động được trong CI |
| `health-path` | đường dẫn kiểm tra app đã lên chưa, ví dụ `/Product/List` |
| `semgrep-packs` | mặc định `p/csharp p/security-audit`. Thêm pack khác cho ngôn ngữ khác, hoặc để `''` khi cần tái lập đúng một con số đã công bố |
| `dockerfile` | tên Dockerfile dùng cho bước quét image |

`run-dast: false` là tham số hay cần nhất. Không có nó, repo cần CSDL sẽ đỏ ở bước khởi động app — đỏ vì thiếu SQL Server, không phải vì tìm ra lỗ hổng. Sai hoàn toàn về ý nghĩa.

### Bước 2b — Giá trị mồi cho DAST: `devsecops-seeds.json`

ZAP kết luận SQL injection bằng cách **so sánh phản hồi** giữa các payload. Nếu yêu cầu gốc đã trả về trang trống, thì `' AND 1=1` và `' AND 1=2` đều trống như nhau — không có gì để so, và ZAP báo "không thấy gì" dù lỗ hổng có thật.

Pipeline tự đoán giá trị mồi theo **kiểu** tham số: số → `1`, chuỗi → `a`. Với `WHERE Name LIKE '%a%'` thế là đủ. Với `WHERE Category = 'a'` thì không — không danh mục nào tên `a`.

Khi tự đoán không ra, chỉ cho nó bằng một tệp ở gốc repo:

```json
{
  "/Product/Filter": "Phu kien",
  "/Product/Detail": "3"
}
```

Khoá là đường dẫn endpoint, giá trị là mồi cho tham số đầu tiên. Tệp không bắt buộc; thiếu thì pipeline vẫn tự đoán.

Mồi vô dụng thì ZAP chỉ không gắn được nhãn *đã khai thác được* — cổng **vẫn chặn** vì rule SAST mức ERROR đã bắt. Trước khi đổi thiết kế, chính trường hợp này đã làm một SQL injection thật đi qua cổng (xem README, mục *Thiết kế đầu và vì sao đổi*).

### Bước 3 — Mở PR và xem

Trên trang PR, các check:

| Check | Chặn merge? | Đỏ nghĩa là |
|---|---|---|
| `security / scan` | không | pipeline không chạy xong — lỗi hạ tầng, xem log |
| `Code scanning results / Semgrep-du-an` | **có** | cảnh báo ERROR **mới** trong diff |
| `Code scanning results / OWASP-ZAP` | **có** | ZAP khai thác được lỗi High trên app dựng từ PR |
| `security / dependency-review` | **có** | gói mới thêm/nâng dính CVE ≥ High |
| `Code scanning results / Semgrep-cong-dong`, `/ gitleaks`, `/ Trivy` | không | tham khảo |

Trang **Summary** của `security / scan` có bảng CHẶN/QUA: ở đâu, lỗi gì, cách sửa, dòng nào 🔥 đã khai thác được. Tab **Files changed** có chú thích đỏ đúng dòng.

Lần đầu chuyển sang cơ chế này, chạy pipeline trên `main` một lần (Actions → Run workflow) trước khi mở PR — GitHub cần mốc trên `main` để tính alert nào là mới.

### Bước 4 — Bật cổng phía GitHub

Settings của repo:

**Rules → Rulesets → New branch ruleset**, tên `main`, Enforcement **Active**, target *default branch*, bypass list **trống**:

- ☑ Require a pull request before merging → Required approvals **1**
- ☑ Require code scanning results → Add tool `Semgrep-du-an` (Alerts: **Errors**, Security: **High or higher**) · Add tool `OWASP-ZAP` (Security: **High or higher**)
- ☑ Require status checks to pass → `security / dependency-review` · ☑ Require branches to be up to date
- ☑ Restrict deletions · ☑ Block force pushes

Tên công cụ chỉ hiện trong danh sách sau khi pipeline đã chạy trên `main` ít nhất một lần.

**Code security**: bật *Secret scanning* + *Push protection*; bật *Dependabot alerts* + *Dependabot security updates*.

### Bước 5 — Thông báo: email của GitHub, không cần cài gì

Dự án không dùng Telegram hay n8n. GitHub tự gửi email tới người liên quan:

- **Có lỗi trong PR** → `github-advanced-security[bot]` bình luận đúng dòng trên PR, email tới tác giả PR và người theo dõi
- **Job thất bại** (ví dụ `dependency-review` đỏ) → email "Some jobs were not successful" tới người kích hoạt lần chạy
- **CVE mới dính gói đang dùng** → Dependabot gửi email và mở PR nâng phiên bản

Chỉnh loại email nhận ở github.com/settings/notifications (mục *Actions*, *Dependabot alerts*).

---

## 6. Commit chỉ sửa tài liệu

**PR luôn được quét đầy đủ**, kể cả PR chỉ sửa README. Lý do: ruleset *Require code scanning results* đòi `Semgrep-du-an` và `OWASP-ZAP` có kết quả cho từng commit của PR. Bỏ qua hai tầng đó thì PR treo mãi ở "Code scanning is waiting for results" và không merge được.

Chỉ commit trên `main` (sau khi merge) mà toàn là `.md`, `.txt`, ảnh, `docs/`, `LICENSE` mới được rút gọn: CI bỏ qua các tầng cần build và chạy app, xong trong khoảng 20 giây. Gitleaks **vẫn chạy**, vì một tệp `.md` hoàn toàn có thể chứa token bị dán nhầm.

---

## 7. Xử lý sự cố

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| Tầng 5 báo `khong ket noi duoc ZAP o cong 8090` | ZAP chưa chạy hoặc sai cổng | `docker ps`, rồi chạy lại lệnh ZAP ở mục 3 |
| Tầng 5 báo ZAP trả về 500 | ô URL điền `localhost` | đổi thành `host.docker.internal` |
| Check Code scanning không hiện trên PR | SARIF chưa upload được, hoặc `main` chưa có lần quét nào | xem log bước "Code Scanning - ..." ; chạy workflow trên main một lần |
| PR đỏ vì lỗi có từ trước | `main` chưa được quét với công cụ cùng tên | chạy workflow trên `main` rồi push lại PR |
| Tầng 2 ra nhiều cảnh báo hơn lần trước dù không sửa code | rule cộng đồng kéo bản mới lúc chạy | đúng như thiết kế — sửa lỗi mới hoặc đặt `semgrep-packs: ''` nếu cần tái lập |
| Báo cáo thiếu một tầng | tầng đó bị bỏ qua | xem log để biết lý do — thiếu tệp nghĩa là **không có kết quả mới**, không phải sạch |
| PR treo ở *"waiting for status to be reported"* | required check ghi sai tên | dùng đúng `security / dependency-review`; check Code scanning cấu hình qua *Require code scanning results*, không qua status check |
| Kết quả không phản ánh bản sửa vừa nhận | tiến trình `webui.py` cũ vẫn chạy code cũ | **tắt hẳn** rồi chạy lại — Python nạp module một lần lúc khởi động |
| `UnicodeDecodeError` trên Windows | bảng mã console | đã vá — cập nhật `tools/` lên bản mới nhất |

Nghi ngờ bất cứ thứ gì thì chạy trước:

```bash
python kiem_tra_moi_truong.py
```

Nghi ngờ **bộ rule** thì chạy:

```bash
python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
```

Lệnh này bắn từng rule vào một tệp mã có lỗi cố ý và một tệp đã khử độc, rồi báo rule nào mù, rule nào báo nhầm. Sửa rule xong luôn chạy lại — rule hỏng im lặng y hệt tệp sạch.

---

## 8. Kịch bản kiểm thử hệ thống — 8 bước

Dùng cho chương Thực nghiệm và cho buổi bảo vệ. Cần 3 người và một repo ứng dụng đã gắn pipeline (xem `HUONG_DAN_DONG_DOI.md` để đồng đội cài). Mỗi bước là một bằng chứng; chụp màn hình kết quả từng bước.

Điều kiện trước: `main` của repo app **sạch** (bản có lỗ hổng nằm ở tag `ground-truth`), ruleset đã bật theo §5 bước 4, pipeline đã chạy trên `main` một lần.

| # | Ai | Làm gì | Kỳ vọng | Chứng minh |
|---|---|---|---|---|
| 1 | B | `git push origin main` trực tiếp | GitHub từ chối `GH013` (vi phạm ruleset) | Không có đường tắt vào main |
| 2 | A | Nhánh `tinh-nang/loc`, thêm action `Product/Filter?category=` nối chuỗi vào SQL, push, mở PR | `Code scanning results / Semgrep-du-an` **đỏ**; Summary: 1 vấn đề; chú thích đỏ đúng dòng. Merge khoá: *"Semgrep-du-an has detected 1 security relevant alert"*. ZAP chạy độc lập nhưng không khai thác được endpoint này — không ảnh hưởng việc chặn | SAST chặn theo rule tin cậy cao; DAST bỏ sót không mở đường cho lỗi lọt |
| 3 | A | Thêm `// nosemgrep` không lý do, push | Check **vẫn đỏ** — pipeline không đọc `nosemgrep` | Không tắt được cảnh báo bằng cách sửa code |
| 4 | A | Tab Security → Dismiss alert với lý do "false positive" bịa | Check xanh; B thấy dismiss trong PR, **mở lại alert**, Request changes | Dismiss có dấu vết, có người soát; qua máy không qua người |
| 5 | A | Vá thật bằng tham số hoá, push | Tất cả check xanh. Summary: QUA. Merge xám vì chưa approve | Sửa đúng thì qua — alert tự đóng "fixed" |
| 6 | B | Approve | Merge mở → A merge → `main` chạy lại, xanh | Hai chốt độc lập: máy và người |
| 7 | C | PR sạch trên nhánh khác, cùng lúc | Pipeline riêng, xanh, không dính PR của A | Không chặn nhầm người vô can |
| 8 | Minh | Thử merge PR đỏ bằng quyền admin | Không được — bypass list trống | Áp cả chủ repo |

Thêm hai tình huống chỉ pipeline mới bắt được, mỗi cái một PR ngắn: **(9)** dán một chuỗi giống khoá AWS vào `appsettings.json` → GitHub chặn ngay lúc `git push`; **(10)** thêm gói NuGet phiên bản cũ có CVE (ví dụ `Newtonsoft.Json 12.0.1`) → `security / dependency-review` đỏ.

Bước 2 và 3–4 là cốt lõi: cổng chặn **trước khi vào main**, và không có đường tắt nào không để lại dấu vết.

Muốn trình diễn *repo có sẵn nợ cũ*: mở PR sửa một dòng vô hại trên nhánh tạo từ tag `ground-truth`. Bốn lỗ hổng cũ hiện trong tab Security của nhánh nhưng **không chặn PR** — GitHub chỉ tính alert mới trong diff.

Lưu ý khi chọn action cho bước 2: action có **tham số GET** thì ZAP mới tới được và gắn được nhãn *đã khai thác*. Action POST thì SAST vẫn chặn, chỉ thiếu nhãn — đó là giới hạn của DAST, ghi ở mục 9.

---

## 9. Giới hạn cần biết

- Bộ rule của dự án là **C#** và phủ **12 mã CWE** mà ZAP xác nhận động được. Repo ngôn ngữ khác thì chỉ còn rule cộng đồng chạy.
- **28/31 rule dự án có quyền chặn** (mức ERROR); 3 rule bắt theo tên biến chỉ chú thích. Rule cộng đồng không chặn.
- Cảnh báo thuộc CWE **ngoài bảng ánh xạ** (deserialization, IDOR, mã hoá yếu…) hiện trong báo cáo ở mục riêng và **không tính vào cổng chặn** — không có công cụ nào kiểm chứng chúng được.
- Tầng 5 chỉ chạy với **ứng dụng tự chứa** — app cần SQL Server, Redis hay dịch vụ ngoài thì phải thêm service container vào CI.
- Tầng 5 chỉ phủ được endpoint có **tham số GET kiểu đơn giản**. VulnShop phủ 43%, eShopOnWeb phủ 9%. Tầng 3 đo và công bố con số này thay vì giấu.
- **DAST cần giá trị mồi sinh ra dữ liệu.** Mồi tự đoán theo kiểu tham số không biết gì về dữ liệu thật; với phép so bằng (`Category = ...`) nó trả về trang trống và ZAP mất mốc so sánh. Pipeline phát hiện mốc rỗng và không tính là đã kiểm chứng; muốn ZAP kiểm chứng được thì khai mồi thật trong `devsecops-seeds.json` (mục 5, bước 2b).
- **Không có nhãn "an toàn".** Check xanh nghĩa là *không có gì mới vượt ngưỡng*, không phải app không có lỗi. Lỗi logic và lỗi ngoài mẫu rule không công cụ nào bắt.
