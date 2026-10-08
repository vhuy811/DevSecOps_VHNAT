# Độ phủ OWASP Top 10 (2021) của pipeline

Tệp này trả lời một câu hỏi duy nhất: **với mỗi nhóm trong OWASP Top 10, pipeline
chặn được gì, chỉ báo được gì, và không phủ gì.**

## Cách lập bảng

Mỗi rule và mỗi tầng được gắn vào nhóm OWASP **theo danh sách CWE chính thức của
từng nhóm** trên owasp.org/Top10, bằng mã chứ không gán tay. Lý do: gán tay thì rất
dễ xếp một rule gần gần vào một nhóm để bảng trông kín, và đó chính là kiểu tự lừa
mà cả bộ công cụ này được dựng để tránh.

Ba mức, phân biệt rõ:

| Mức | Nghĩa |
|---|---|
| **CHẶN** | Cảnh báo mới trong PR làm merge không qua được. Thực thi bằng ruleset GitHub *Require code scanning results*, hoặc bằng job `Cong xac nhan` thoát mã 1. |
| **chỉ báo** | Hiện trong Code Scanning, người review đọc được, nhưng không chặn merge. Dành cho rule chưa đo được tỉ lệ báo nhầm, hoặc đã đo và báo nhầm cao. |
| **chưa phủ** | Không công cụ nào trong pipeline nhắm tới. Ghi thẳng là chưa phủ, không gán một rule gần giống vào cho đẹp bảng. |

Cột *đã đo* chỉ điền khi có số từ một phòng đo chạy được, kèm nguồn. Trống nghĩa là
**chưa có bộ đo** — không phải 0%, cũng không phải tốt.

## Bảng phủ

| Nhóm OWASP | Tầng nào phủ | Mức | Đã đo (bắt / báo nhầm) |
|---|---|---|---|
| **A01** Kiểm soát truy cập hỏng | 8 rule đường dẫn (CWE-22/23/36) + chuyển hướng mở (601) của đồ án; CodeQL; **DAST-idor** kiểm IDOR/BOLA có xác thực (CWE-639) | CHẶN | CWE-23 49%/0%, CWE-36 49%/0%, CWE-601 74%/2% (Juliet #28). IDOR: 2/2 trên bộ kiểm chức năng, chưa có corpus |
| **A02** Thất bại mật mã | `dso-weak-hash`, `dso-weak-random`, `dso-hardcoded-crypto-key`; CodeQL mật mã yếu; 2 rule CWE-319 | **hỗn hợp** | CWE-327 100%/0%; CWE-321 49%/0%; **CWE-328 và CWE-338 bắt 100%/0% nhưng chỉ ở mức WARNING nên KHÔNG chặn**; CWE-319 **0%/0% — không công cụ nào bắt** |
| **A03** Chèn mã | 26 rule chặn + 11 rule chỉ báo của đồ án (SQLi, cmdi, XSS, XPath, LDAP, XXE, chèn mã, CRLF); CodeQL; **OWASP-ZAP** xác nhận động | CHẶN | CWE-89 72%/1%, CWE-78 85%/2%, CWE-90 85%/2%, CWE-643 49%/0%, CWE-80 74%/2%, CWE-113 49%/0%, CWE-470 49%/0% (Juliet #28). ZAP: 6/6 lỗ hổng gài trước, 0 báo nhầm (phòng đo DAST) |
| **A04** Thiết kế không an toàn | — | **chưa phủ** | — |
| **A05** Cấu hình sai | 5 rule XXE/DTD của đồ án; **Trivy** quét cấu hình hạ tầng; **DAST-runtime** kiểm header và cờ cookie | CHẶN | CWE-614 100%/0% (Juliet #28). DAST-runtime: 5/5 rule trên bộ kiểm chức năng. Trivy: **chưa có bộ đo** |
| **A06** Thành phần lỗi thời | **SCA** — `sca.py` (dotnet), `retire.js` (JS nhúng), `dependency-review` (GitHub) | CHẶN | **chưa có bộ đo.** Tầng này không suy đoán — so phiên bản với advisory database nên không có báo nhầm theo nghĩa của SAST; nhưng *bỏ sót* thì chưa đo được |
| **A07** Xác thực hỏng | `dso-hardcoded-password`; **Gitleaks** quét secret; CodeQL | CHẶN | CWE-259 24%/0% (Juliet #28). Gitleaks: **chưa có bộ đo** |
| **A08** Toàn vẹn phần mềm/dữ liệu | Rule cộng đồng bắt deserialization (CWE-502) nhưng **không chặn**; `ky-image-reusable.yml` ký image | **chỉ báo** | **chưa đo.** Đồ án cố ý không viết rule CWE-502: ZAP không có active scan tương ứng nên không thể xác nhận động |
| **A09** Ghi log và giám sát | CodeQL log injection (CWE-117) | CHẶN | CWE-117 **76%/2%** (Juliet #28) — và toàn bộ đến từ CodeQL, đồ án không có rule nào |
| **A10** SSRF | 4 rule SSRF (C#, Python, Java) + CodeQL | CHẶN | **chưa đo riêng.** Juliet C# không có CWE-918; Juliet Java cũng không. BenchProctor Python có 600 case CWE-918 — sẽ có số sau phòng đo Python |

## Bốn chỗ yếu, nói thẳng

**A04 Thiết kế không an toàn — chưa phủ, và sẽ khó phủ.** Nhóm này là thiếu
kiểm soát ở mức thiết kế: không giới hạn tần suất, thiếu phân tách quyền, luồng
nghiệp vụ cho phép lạm dụng. Không có hình dạng mã nào để khớp. SAST và DAST đều
không với tới. Cách phủ thật là threat modeling và review thiết kế — việc của
người, không phải của pipeline. Ghi "chưa phủ" là trung thực hơn mọi lựa chọn khác.

**A02 có hai lỗ cụ thể.** `dso-weak-hash` và `dso-weak-random` bắt **100% với 0%
báo nhầm** trên Juliet nhưng đang ở mức WARNING nên không chặn. Chưa nâng vì Juliet
không có lần nào dùng MD5 hợp lệ (checksum, cache key, ETag), nên 0% báo nhầm ở đó
**không nói gì** về mã nguồn thật — nâng lên mà không có bằng chứng về mã thật thì
đúng vào vế "không lỗi vẫn block". Còn CWE-319 thì 0% cho mọi công cụ: đã đọc hàm
Bad của Juliet và biết dạng thật là *đọc bí mật qua `http://` không mã hoá rồi dùng
làm thông tin đăng nhập*, nhưng chưa viết rule vì cần đọc cả hàm goodB2G trước.

**A08 chỉ báo, không chặn.** Deserialization không an toàn do rule cộng đồng bắt
và không có quyền chặn. Đây là lựa chọn có chủ đích đã ghi trong `sast-detect.yaml`:
quyền chặn dành cho CWE mà ZAP có active scan tương ứng, để cảnh báo còn đi tiếp
được tới nhãn CONFIRMED. CWE-502 không có. Cái giá là A08 không được chặn.

**Ba tầng chưa có bộ đo: SCA, secret, hạ tầng.** Nên con số "bắt 61.6%" của đồ án
là con số của **hai tầng phân tích tĩnh trên Juliet C#**, không phải của cả pipeline.
Không thể cộng tỉ lệ của năm tầng lại vì chúng không cùng mẫu số: Juliet đếm lỗi
tiêm ở mức mã nguồn, SCA đếm phiên bản thư viện dính CVE, Gitleaks đếm credential bị
commit, Trivy đếm cấu hình sai. Muốn một con số cho cả năm tầng thì phải có một bộ
đo mà cả năm tầng đều có cái để tìm — bộ đó không tồn tại công khai.

## Việc cần làm để bịt, theo thứ tự giá trị

1. **Dựng đáp án cho SCA và Gitleaks** — repo mẫu gài sẵn CVE biết trước (npm, pip,
   nuget, maven) và credential biết trước (AWS key, token GitHub, chuỗi kết nối,
   khoá riêng), kèm cả dạng đã khử (placeholder, biến môi trường) để đo báo nhầm.
   Đây là việc bịt được ba ô "chưa có bộ đo" trong bảng.
2. **CWE-319** — đọc hàm goodB2G rồi viết rule. 148 case đang 0%.
3. **CWE-328/338** — đo báo nhầm trên mã nguồn thật (không phải Juliet) rồi quyết
   có nâng lên mức chặn hay không.
4. **A08** — xét có nên cho CWE-502 quyền chặn dù ZAP không xác nhận được, hay giữ
   nguyên nguyên tắc. Đây là quyết định về nguyên tắc, cần số liệu báo nhầm trước.
5. **A04** — không bịt bằng công cụ. Cách trung thực là ghi rõ trong tài liệu rằng
   pipeline không thay được review thiết kế.
