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
| **A03** Chèn mã | 26 rule chặn + 11 rule chỉ báo của đồ án (SQLi, cmdi, XSS, XPath, LDAP, XXE, chèn mã, CRLF) + **2 rule mới**: NoSQL `$where` (CWE-943) và SSTI (CWE-1336); CodeQL; **OWASP-ZAP** xác nhận động | CHẶN | CWE-89 72%/1%, CWE-78 85%/2%, CWE-90 85%/2%, CWE-643 49%/0%, CWE-80 74%/2%, CWE-113 49%/0%, CWE-470 49%/0% (Juliet #28). ZAP: 6/6 lỗ hổng gài trước, 0 báo nhầm (phòng đo DAST). **NoSQL và SSTI: chưa đo** — BenchProctor có 150 case NoSQL và 147 case SSTI, trước G6.2 không công cụ nào của đồ án thấy chúng |
| **A04** Thiết kế không an toàn | — | **chưa phủ** | — |
| **A05** Cấu hình sai | 5 rule XXE/DTD của đồ án; **Trivy** quét cấu hình hạ tầng; **DAST-runtime** kiểm header và cờ cookie | CHẶN | CWE-614 100%/0% (Juliet #28). DAST-runtime: 5/5 rule trên bộ kiểm chức năng. Trivy: **chưa có bộ đo** |
| **A06** Thành phần lỗi thời | **SCA** — `sca.py` (chỉ NuGet), `retire.js` (chỉ JS nhúng sẵn), `dependency-review` (chỉ thư viện **mới** trong PR), **Trivy fs** (mọi hệ sinh thái, thư viện **đã có**) | CHẶN | có bộ đo từ G5.2: fixture sinh lúc chạy, 9 gói dính lỗ hổng + 6 gói sạch trên npm/pip/maven/nuget |
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
đúng vào vế "không lỗi vẫn block". **Bộ đo cho đúng câu này đã dựng** (G6.4):
`semgrep-rules/kiem-thu-rule/logic-nghiep-vu/` — 38 hàm mã nghiệp vụ an toàn mà
trông như lỗi, trong đó có MD5 dùng làm ETag / khoá cache / dấu vết trùng lặp và
`Random` dùng cho jitter / lấy mẫu log / xáo trộn gợi ý. Đáp án là 0 cảnh báo mức
chặn. Có số rồi thì quyết được, còn bây giờ **vẫn chưa có số**. Còn CWE-319 thì 0% cho mọi công cụ: đã đọc hàm
Bad của Juliet và biết dạng thật là *đọc bí mật qua `http://` không mã hoá rồi dùng
làm thông tin đăng nhập*, nhưng chưa viết rule vì cần đọc cả hàm goodB2G trước.

**A08 chỉ báo, không chặn.** Deserialization không an toàn do rule cộng đồng bắt
và không có quyền chặn. Đây là lựa chọn có chủ đích đã ghi trong `sast-detect.yaml`:
quyền chặn dành cho CWE mà ZAP có active scan tương ứng, để cảnh báo còn đi tiếp
được tới nhãn CONFIRMED. CWE-502 không có. Cái giá là A08 không được chặn.

**Một lỗ đã tìm ra và đã bịt ở A06.** Trước G5.2, tầng thư viện chỉ gồm `sca.py`
(đọc NuGet), `retire.js` (đọc JS nhúng sẵn, không đọc `package.json`) và
`dependency-review` (chỉ xét thư viện **mới thêm trong PR**). Nghĩa là với một repo
Python hay Java, các thư viện **đã có** trong `requirements.txt` hay `pom.xml` không
tầng nào quét — một repo kéo về với `log4j-core 2.14.1` có sẵn thì không cảnh báo
nào. Đây là lỗ của chính câu "dùng được cho nhiều loại repo". Bản bịt không cần công
cụ mới: Trivy đã quét filesystem để sinh SBOM, chỉ là chưa được hỏi lỗ hổng.

**Một lỗ A03 đã tìm ra và đã bịt: NoSQL injection.** Trước G6.2, bộ rule chỉ có
đích SQL (`execute`, `text`, `raw`) — không có đích MongoDB. Đo trên BenchProctor:
150 case `$where` nối chuỗi mà **không công cụ nào của đồ án nhìn thấy**. Một repo
dùng Mongo thì tầng SAST mù hoàn toàn với A03, đúng vào câu "dùng được cho nhiều
loại repo". Cùng lần đo đó tìm ra 147 case SSTI mà Semgrep **có** báo nhưng điểm
không được tính, vì rule khai `cwe: CWE-79` trong khi SSTI thuộc họ CWE-1336 — lỗi
gán nhãn, không phải lỗi phát hiện.

**Hai tầng vẫn chưa có bộ đo: secret và hạ tầng.** Nên con số "bắt 61.6%" của đồ án
là con số của **hai tầng phân tích tĩnh trên Juliet C#**, không phải của cả pipeline.
Không thể cộng tỉ lệ của năm tầng lại vì chúng không cùng mẫu số: Juliet đếm lỗi
tiêm ở mức mã nguồn, SCA đếm phiên bản thư viện dính CVE, Gitleaks đếm credential bị
commit, Trivy đếm cấu hình sai. Muốn một con số cho cả năm tầng thì phải có một bộ
đo mà cả năm tầng đều có cái để tìm — bộ đó không tồn tại công khai.

## Việc cần làm để bịt, theo thứ tự giá trị

1. ~~Dựng đáp án cho SCA~~ — **xong (G5.2)**: `tools/kiem_thu_sca.py`, fixture sinh
   lúc chạy, 15 gói trên bốn hệ sinh thái. Việc này đồng thời tìm ra và bịt lỗ
   "thư viện đã có không tầng nào quét". Còn **Gitleaks** thì chưa có đáp án.
2. **CWE-319** — đọc hàm goodB2G rồi viết rule. 148 case đang 0%.
3. **CWE-328/338** — ~~đo báo nhầm trên mã nguồn thật~~ **bộ đo đã dựng (G6.4)**,
   chờ chạy: `phong-do-logic-nghiepvu.yml`. Có kết quả rồi mới quyết có nâng lên mức
   chặn hay không. Hạn chế đã ghi: đây là mã tự viết, số case nhỏ, nên đọc là "có
   chặn oan hay không" chứ không phải một tỉ lệ có mẫu số đáng tin.
4. **A08** — xét có nên cho CWE-502 quyền chặn dù ZAP không xác nhận được, hay giữ
   nguyên nguyên tắc. Đây là quyết định về nguyên tắc, cần số liệu báo nhầm trước.
5. **A04** — không bịt bằng công cụ. Cách trung thực là ghi rõ trong tài liệu rằng
   pipeline không thay được review thiết kế.
