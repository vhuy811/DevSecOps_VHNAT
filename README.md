# Quy trình DevSecOps — tích hợp kiểm thử SAST và DAST

Bộ công cụ quét bảo mật cho dự án .NET trên GitHub Actions, áp dụng cho **repo bất kỳ** bằng một tệp workflow 12 dòng — bộ công cụ đi theo pipeline, không sao chép vào từng dự án.

Bài toán nó giải: một nhóm dev nhỏ, không có chuyên gia bảo mật, làm sao đưa kiểm thử bảo mật vào luồng Pull Request sao cho lỗi nguy hiểm phổ biến bị chặn **trước khi vào main**, dev không bị chặn nhầm, báo nhầm và nợ cũ có nơi xử lý minh bạch, và mọi thứ đo được.

Đồ án môn học **An toàn Web và Cơ sở dữ liệu** — Trường Đại học Kinh tế – Tài chính TP.HCM (UEF).

---

## Nguyên tắc chi phối

> **Im lặng không phải là bằng chứng.**

Scanner không tìm thấy gì **không** đồng nghĩa với an toàn. Một tầng bị bỏ qua phải nói rõ lý do, một bước không chạy được phải ghi nhận là không có kết quả, và **không công cụ nào có quyền "cho qua" cảnh báo của công cụ khác** chỉ vì nó không tìm thấy gì.

Dòng cuối là bài học đắt nhất của đồ án — xem mục *Thiết kế đầu và vì sao đổi* ở dưới.

---

## Ai chặn, chặn gì

Pipeline **không tự chặn**. Nó đưa kết quả từng scanner lên GitHub Code Scanning dưới dạng SARIF; GitHub tự tính alert nào là **mới** trong PR, hiện chú thích ngay trên dòng code, và ruleset trên `main` khoá merge theo ngưỡng từng công cụ. Đây là cách các tổ chức dùng GitHub vận hành thật, không phải cổng tự viết.

| Nguồn | Chặn merge khi | Ngưỡng ruleset |
|---|---|---|
| **Semgrep-du-an** — 31 rule tự viết, tin cậy cao | cảnh báo mức ERROR **mới** trong PR | Alerts = Errors, Security ≥ High |
| **OWASP-ZAP** — quét toàn bộ app dựng từ code PR | alert risk High **mới** | Security ≥ High |
| **dependency-review** — job riêng của GitHub | PR **thêm hoặc nâng** gói dính CVE ≥ High | required check |
| **Push protection** của GitHub | secret trong commit — chặn ngay lúc `git push` | bật trong Settings |
| Semgrep-cong-dong, Trivy, Gitleaks | không chặn | tham khảo / theo dõi |

Bốn nguồn chặn **cộng dồn** — không nguồn nào gạt được nguồn khác. Cho qua chỉ theo hai cách, cả hai để lại dấu vết:

- **Dismiss alert** trong tab Security, chọn lý do (false positive / won't fix / used in tests) và ghi chú. GitHub ghi audit log; lần chạy sau không báo lại. Không sửa code để né, không `nosemgrep`.
- **Hạ rule** xuống WARNING ở cấp bộ công cụ, khi một rule bị dismiss quá ~10% (ngưỡng Google dùng để tắt analyzer). Sửa ở nguồn, không sửa từng PR.

Dev chỉ thấy hai trạng thái: **CHẶN** — tệp:dòng, lỗi gì, cách sửa, có nhãn *đã khai thác được* hay không; hoặc **QUA**.

---

## Năm tầng

| Tầng | Công cụ | Đầu vào | Đầu ra |
|---|---|---|---|
| 0 | Gitleaks | toàn bộ tệp | secret lộ trong mã nguồn |
| 1 | `sca.py` + dotnet; dependency-review | `*.csproj` | CVE trong gói NuGet; gói mới dính CVE |
| 2 | Semgrep — rule dự án + rule cộng đồng | `*.cs`, `*.cshtml` | cảnh báo theo CWE, tách hai mức tin cậy |
| 3 | `gen_routes_map.py` | Controller, Razor Pages | bản đồ (URL, tham số) và **phạm vi DAST tới được** |
| 4 | Trivy | Dockerfile, manifest | lỗi cấu hình, SBOM, CVE trong image |
| 5 | `dast_scan.py` + OWASP ZAP | app dựng từ code PR, chạy trong máy ảo tạm | alert DAST, **ánh xạ về Controller:dòng** qua bản đồ route |

Tầng 5 chạy **độc lập** với tầng 2: ZAP quét toàn bộ app, không đi theo chỉ tay của SAST, nên nó tìm được thứ SAST bỏ sót. Đối chiếu tầng 2 × tầng 5 — cùng CWE, cùng endpoint — chỉ để gắn nhãn **ĐÃ KHAI THÁC ĐƯỢC** vào cảnh báo SAST: xếp ưu tiên sửa trước. Không bao giờ dùng để bỏ qua.

Mỗi PR có một bản app riêng: GitHub tạo máy ảo, `dotnet build`, `dotnet run` ở `localhost:5000` của máy ảo đó, ZAP bắn vào, rồi máy ảo bị huỷ. Không server, không deploy.

---

## Bắt đầu

### Cần có sẵn

Docker Desktop, Python 3.9+, Git. Thêm .NET SDK nếu quét dự án .NET.

```bash
git clone https://github.com/vhuy811/DevSecOps_VHNAT.git
cd DevSecOps_VHNAT
pip install requests
python kiem_tra_moi_truong.py
```

### Áp cho một repo trên GitHub

Tạo `.github/workflows/bao-mat.yml` trong repo cần bảo vệ:

```yaml
name: Bao mat
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  security:
    uses: vhuy811/DevSecOps_VHNAT/.github/workflows/devsecops-reusable.yml@main
    with:
      project-file: src/Web/Web.csproj
      health-path: /
```

Chỉ quét khi **mở PR** và khi push vào `main` — mỗi PR một check, một mốc so sánh. Nhánh phụ muốn được quét thì mở PR (draft cũng được).

Rồi bật cổng phía GitHub — Settings của repo:

1. **Rules → Rulesets** → ruleset cho `main`: *Require a pull request* (1 approval) · *Require code scanning results* → thêm `Semgrep-du-an` (Alerts: Errors, Security: High or higher) và `OWASP-ZAP` (Security: High or higher) · *Require status checks* → `security / dependency-review` · bypass list **để trống**.
2. **Code security** → bật *Secret scanning* + *Push protection*, *Dependabot alerts* + *security updates*.

Tên công cụ trong ruleset chỉ xuất hiện sau khi pipeline đã chạy ít nhất một lần trên `main` — push một lần trước rồi mới cấu hình.

### Quét một thư mục tại máy

```bash
python tools/webui.py
```

Bảng điều khiển cục bộ để nhìn toàn cảnh một repo hoặc trình diễn. Không phải cổng.

Hướng dẫn thao tác đầy đủ: [`HUONG_DAN.md`](HUONG_DAN.md). Cho người viết code trong nhóm: [`HUONG_DAN_DONG_DOI.md`](HUONG_DAN_DONG_DOI.md).

---

## Tham số của pipeline

| Tham số | Mặc định | Khi nào đổi |
|---|---|---|
| `project-file` | `''` | đường dẫn `.csproj`; để trống thì bỏ tầng 1 và 5 |
| `run-dast` | `true` | `false` khi app cần CSDL, không khởi động được trong CI |
| `health-path` | `/` | đường dẫn kiểm tra app đã sẵn sàng |
| `app-url` | `http://localhost:5000` | địa chỉ ZAP nhìn thấy |
| `dockerfile` | `Dockerfile` | tên Dockerfile cho bước quét image |
| `run-image-scan` | `true` | `false` để tiết kiệm vài phút CI |
| `semgrep-packs` | `p/csharp p/security-audit` | bộ rule cộng đồng chạy kèm; kết quả vào `Semgrep-cong-dong`, không chặn |
| `dotnet-version` | `9.0.x` | phiên bản SDK |
| `toolkit-ref` | `main` | ghim tag khi dùng thật |

Không còn tham số bật/tắt cổng. Ngưỡng chặn nằm ở ruleset của GitHub — thay đổi được mà không sửa workflow, và có audit.

Tệp tuỳ chọn ở gốc repo đích: `devsecops-seeds.json` — giá trị mồi thật cho từng endpoint để DAST có mốc so sánh (`{"/Product/Filter": "Phu kien"}`). Không có thì pipeline tự đoán theo kiểu tham số.

---

## Cấu trúc repo

```
tools/
  sca.py                tầng 1 — đối chiếu NuGet với CSDL lỗ hổng
  gen_routes_map.py     tầng 3 — bản đồ endpoint, Controller và Razor Pages
  trivy.py              tầng 4 — cấu hình, SBOM, so sánh image trước/sau gia cố
  dast_scan.py          tầng 5 — ZAP quét toàn bộ app tạm
  sarif_tools.py        chuẩn hoá SARIF cho Code Scanning: tách rule dự án/cộng đồng,
                        ZAP → SARIF ánh xạ về mã nguồn, gắn nhãn đã khai thác
  gate.py               tóm tắt CHẶN/QUA cho dev trên trang Summary — không chặn
  correlate.py          bản đồ route + đối sánh (dùng bởi dashboard cục bộ)
  report.py             báo cáo HTML
  webui.py              bảng điều khiển cục bộ
  pre_commit_scan.py    hook pre-commit — tư vấn, không phải hàng rào

semgrep-rules/
  sast-detect.yaml      31 rule phát hiện, 12 CWE — ERROR chặn, WARNING tham khảo
  sanitizer-check.yaml  rule tìm bằng chứng khử độc (dashboard cục bộ)
  kiem-thu-rule/        fixture tự kiểm chứng bộ rule (mã có lỗi cố ý)

.github/workflows/
  devsecops-reusable.yml  pipeline dùng chung, repo khác gọi tới
  devsecops.yml           repo này tự gọi pipeline của chính mình

vi-du-repo-khac.yml     mẫu dán vào repo khác
kiem_tra_moi_truong.py  chẩn đoán 9 điều kiện
HUONG_DAN.md            vận hành + kịch bản kiểm thử
HUONG_DAN_DONG_DOI.md   cho người viết code — chỉ cần Git
```

### Bộ rule phủ tới đâu, và vì sao dừng ở đó

Rule của dự án **cố ý không phủ hết mọi loại lỗ hổng**. Nó phủ 12 mã CWE mà ZAP có active scan rule tương ứng — những mã có thể nhận nhãn *đã khai thác được*:

| Nhóm | CWE |
|---|---|
| Tiêm lệnh | 89 SQL · 78 OS command · 94 mã nguồn · 90 LDAP · 643 XPath · 91 XML/XSLT |
| Xử lý input | 79 XSS · 22 path traversal · 113 response splitting |
| Gọi ra ngoài | 918 SSRF · 601 open redirect · 611 XXE |

Trong 31 rule, 28 rule ở mức **ERROR** (có quyền chặn) và 3 rule bắt theo tên biến ở mức **WARNING** (chỉ chú thích) — vì rule bắt theo tên biến có tỉ lệ báo nhầm cao, và quy tắc là *chỉ chặn bằng thứ gần như không báo nhầm*.

Phần bề rộng — mã hoá yếu, mật khẩu cứng, deserialization, cấu hình sai — để `p/csharp` và `p/security-audit` lo; kết quả vào `Semgrep-cong-dong`, tham khảo. Viết lại chỉ tạo báo trùng, trong khi hai bộ đó được cập nhật hằng ngày.

### Tự kiểm chứng bộ rule

```bash
python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
```

Mỗi rule phát hiện phải bắt được case của nó, không rule nào báo nhầm mã đã khử độc. Rule chưa chạy thử thì chưa phải rule.

---

## Thiết kế đầu và vì sao đổi

Thiết kế ban đầu gán **ba nhãn** cho cảnh báo SAST — CONFIRMED (ZAP khai thác được), FILTERED (có bằng chứng khử độc), UNCONFIRMED — và cổng chỉ chặn CONFIRMED. Ý tưởng: dùng DAST để lọc bớt báo nhầm của SAST.

Nó bị bác bỏ bởi chính lần kiểm thử độc lập đầu tiên. PR #1 của `VulnShop-App` thêm một SQL injection thật vào `/Product/Filter`; SAST bắt đúng dòng; ZAP bắn vào đúng endpoint nhưng không khai thác được — giá trị mồi `a` không khớp danh mục nào, trang trống, không có gì để so — và cảnh báo mang nhãn UNCONFIRMED. **Cổng cho qua.**

Lỗi không nằm ở mồi. Lỗi nằm ở tiền đề: cho một công cụ **bỏ sót nhiều hơn** (DAST cần app chạy, tham số GET, mồi đúng, payload trúng) quyền phủ quyết một công cụ **bỏ sót ít hơn**. Kết hợp như vậy luôn phát hiện ít hơn hoặc bằng SAST đứng một mình. Và DAST chỉ đi theo chỉ tay của SAST thì không bao giờ tìm ra thứ SAST bỏ sót — nó mất giá trị riêng.

Thực tế ngành xác nhận: Facebook chuyển Infer từ quét theo lô sang quét tại diff, tỉ lệ sửa từ ≈0% lên >70% với cùng công cụ; Google chỉ cho phép check **không báo nhầm** làm hỏng build và tắt analyzer nào bị đánh "không hữu ích" quá 10%; đối chiếu SAST × DAST ngoài đời (Semgrep + StackHawk) dùng để **xếp ưu tiên**, không để bỏ qua.

Thiết kế hiện tại làm đúng bốn điều đó: quét diff tại PR, chỉ chặn bằng rule tin cậy cao, GitHub thực thi cổng, DAST cộng thêm và không phủ quyết. Chạy lại PR #1 với thiết kế mới: bị chặn bởi `Semgrep-du-an`, kèm nhãn *đã khai thác được* khi mồi đúng.

---

## Giới hạn đã biết

Những điều dưới đây được đo và công bố, không phải giấu đi.

**Bộ rule là C#.** Repo ngôn ngữ khác thì tầng 1 và 2 không dùng được.

**Bộ rule không đầy đủ, và sẽ bỏ sót.** Rule bắt theo dấu hiệu bề mặt, không truy vết luồng dữ liệu. Đưa chuỗi qua một hàm trung gian, gán vào một trường của lớp, hay ghép bằng `StringBuilder` là thoát. DAST độc lập bù một phần — không bù hết.

**Lỗi logic không có công cụ nào bắt.** Thiếu kiểm tra phân quyền, sai nghiệp vụ — SAST không có mẫu, DAST không có payload. Đây là giới hạn của mọi công cụ tự động; nó thuộc về review và thiết kế.

**Tầng 5 chỉ chạy với ứng dụng tự chứa.** App cần SQL Server, Redis hay dịch vụ ngoài thì phải thêm service container vào CI, hoặc đặt `run-dast: false` và chấp nhận bốn tầng tĩnh — trang kết quả nói rõ tầng động đã bị bỏ qua.

**Tầng 5 chỉ tới được endpoint có tham số GET kiểu đơn giản.** 43% với ứng dụng mẫu, 9% với eShopOnWeb của Microsoft. Không quét sau đăng nhập.

**DAST chỉ kết luận được khi giá trị mồi sinh ra dữ liệu.** Mồi trả về trang trống thì mọi payload đều trống như nhau. `devsecops-seeds.json` cho phép chỉ mồi thật; không có thì DAST mù ở những endpoint so bằng. Với thiết kế mới điều này chỉ làm mất nhãn *đã khai thác được*, không làm mất cổng — SAST vẫn chặn.

**Semgrep không phân tích cú pháp Razor.** Rule cho `.cshtml` chạy ở chế độ generic — khớp văn bản thuần.

**Hook pre-commit không đi theo git** và bỏ qua được. Nó là tư vấn. Hàng rào duy nhất là PR.
