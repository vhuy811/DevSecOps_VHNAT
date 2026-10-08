# Kết quả đo — mọi con số của đồ án, kèm bộ đo và hạn chế

Tệp này là chỗ duy nhất ghi các con số. Mỗi bảng phải nói rõ **đo trên bộ nào**,
**ngày nào**, và **hạn chế gì** — một tỉ lệ không có ba thứ đó thì không dùng được.

Nguyên tắc: trống nghĩa là **chưa có bộ đo**, không phải 0%, cũng không phải tốt.

---

## 1. Cổng chặn trên C# — Juliet C# 1.3 (NIST SARD #110)

6611 test case, 21 CWE. Mỗi case có một hàm `bad` và các hàm `good`, nên mẫu số
của cả hai tỉ lệ là toàn bộ case.

| Lần đo | Thay đổi | Bắt | Báo nhầm | Youden |
|---|---|---|---|---|
| #23 | nguồn chỉ HTTP | 47.3% | 5.2% | +0.42 |
| #26 | mở rộng nguồn ra ngoài HTTP | 63.6% | 5.2% | +0.58 |
| #28 | bỏ CWE-643 khỏi tầng CodeQL | **61.6%** | **1.0%** | **+0.61** |

Tách theo công cụ ở lần #28:

| Công cụ | Bắt | Báo nhầm |
|---|---|---|
| Rule đồ án, chỉ mức có quyền chặn | 33.8% | **0.0%** |
| CodeQL (threat model local) | 40.2% | 5.2% |
| **Hợp lại = cổng chặn** | **61.6%** | **1.0%** |

**Điều đã học ở lần #26.** Phòng đo chia theo loại nguồn dữ liệu cho thấy rule
taint chỉ khai nguồn HTTP, nên 4218/6611 case có nguồn mạng, CSDL hoặc cục bộ
chưa từng được chạm. Ba dòng 0% nhảy lên đúng bằng dòng HTTP (35%) sau khi mở
rộng nguồn, và cột báo nhầm giữ 0.0% ở cả bốn — mở rộng nguồn là mở rộng vùng
bắt mà không mở rộng vùng báo nhầm.

**Điều đã học ở lần #28.** Dò hết 143 tổ hợp ngưỡng: toàn bộ 5.2% báo nhầm của
cổng đến từ **đúng một loại** — CodeQL bắt CWE-643 76% nhưng báo nhầm cũng 76%.
Bỏ loại đó khỏi quyền chặn của CodeQL: đổi 2.0 điểm bắt lấy 4.2 điểm bớt chặn
oan. Không mất độ phủ vì `dso-taint-xpathi` của đồ án bắt CWE-643 ở 49% với 0%
báo nhầm.

**Trần của phương pháp.** Theo đường đi dữ liệu, rule Semgrep có quyền chặn đạt
68–71% trên các nhóm luồng trong cùng một hàm nhưng **0% trên 2975 case** mà
luồng đi qua hàm khác, tệp khác, collection hay kế thừa. Đó là giới hạn thật của
Semgrep CE (taint chỉ đi trong một hàm), không phải rule viết thiếu. 45% bộ đo
nằm ngoài tầm của Semgrep và chỉ CodeQL với tới (42%).

---

## 2. Cổng chặn trên Java — Juliet Java 1.3 (bản mirror ghim `8b5b9d6`)

5772 test case, 9 CWE. Đo lần đầu, không có mốc trước để so.

| Công cụ | Bắt | Báo nhầm | Youden |
|---|---|---|---|
| Rule đồ án (Semgrep) | 11.8% | **0.3%** | +0.12 |
| Semgrep cộng đồng | 21.3% | 11.0% | +0.10 |
| CodeQL | 73.1% | 21.3% | +0.52 |
| CodeQL (threat model local) | **94.2%** | 21.9% | +0.72 |
| **Cổng chặn** | **86.9%** | **22.0%** | +0.65 |

**Dự đoán trước khi đo là ~15%** (27% case có nguồn HTTP × 54% case luồng trong
một hàm), thực tế 11.8%. Nguyên nhân đúng như xác định: cả 8 rule taint Java chỉ
khai nguồn HTTP servlet, trong khi Juliet Java có 12 họ nguồn và chỉ 3 là HTTP.

**Ba điều phòng đo này nói, và một trong đó là quyết định sai trước đó:**

Thứ nhất, **loại CWE-643 là sai cho Java.** Bản bịt trước đó loại theo tag
`external/cwe/cwe-643`, mà tag đó có ở mọi ngôn ngữ. CodeQL Java bắt CWE-643
100% với chỉ 3% báo nhầm — loại nó mất 4 điểm bắt mà không được gì (bảng dò
ngưỡng: `codeql-local=medium` đạt 94.2%/21.9%, `med-643` chỉ 90.4%/21.8%). Trong
khi CodeQL C# bắt 76% và báo nhầm 76% nên ở C# loại là đúng. **Ngưỡng là chuyện
theo ngôn ngữ**, và một quyết định C# đã bị áp cho mọi ngôn ngữ. Đã sửa: loại
theo ID truy vấn `cs/xml/xpath-injection` thay vì theo họ CWE.

Thứ hai, **trên Java rule của đồ án không thêm gì cho cổng.** Tổ hợp tốt nhất
trong 143 tổ hợp là `codeql-local=medium` **một mình** (94.2%/21.9%/+0.723);
thêm rule Semgrep của đồ án vào thì 94.2%/22.2%/+0.720 — 0 điểm bắt, +0.3 điểm
nhầm. Rule tự viết bắt 11.8% với 0.3% nhầm khi dùng riêng, nhưng CodeQL đã trùm
hết phần đó. Giá trị của bộ rule tự viết trên Java nằm ở chỗ CodeQL không có sẵn
(runner self-hosted, repo private không có GitHub Advanced Security), không nằm ở
chỗ tăng thêm độ phủ.

Thứ ba, **22% báo nhầm là vấn đề "không lỗi vẫn block" lớn nhất tìm được tới
giờ**, và nguồn đã khoanh được: CWE-89 (2220 case, 38% bộ đo) CodeQL bắt 100% và
báo nhầm **44%**; CWE-78 (444 case) bắt 100% báo nhầm **49%**. Các CWE còn lại
1–5%. Hai truy vấn này báo oan hàm `good` khoảng một nửa số lần. **Chưa rõ vì
sao, nên chưa sửa gì** — cần đọc hàm `goodB2G` của Juliet Java trước khi kết
luận. CWE-81 (333 case) thì 0% cho mọi công cụ.

---

## 3. Tầng DAST — VulnShop-App tại ba commit có lỗi thật

Đáp án là 6 lỗ hổng gài trước, cộng 2 endpoint đã khử độc không được báo.

| Cấu hình | Bắt | Báo nhầm |
|---|---|---|
| Policy gốc của ZAP | 3/6 | 0 |
| **Có lớp error-based cho SQLite (đang dùng)** | **6/6** | **0** |
| Đẩy ZAP lên HIGH | 5/6 | 3 |

Đẩy độ nhạy lên vừa bỏ sót `/Product/Filter` vừa sinh 3 báo nhầm — lớp
error-based riêng cho `Microsoft.Data.Sqlite` làm tốt hơn cả hai.

**Hạn chế:** 6 case là phép kiểm chức năng, không phải một tỉ lệ. Đặt "100%"
cạnh "61.6% trên 6611 case" là so sánh hai thứ khác loại.

---

## 4. Chưa có bộ đo

| Tầng | Trạng thái |
|---|---|
| Python (SAST) | bộ đo đã dựng (BenchProctor 18.300 case), chưa chạy xong |
| SCA — thư viện đã có | đáp án đã dựng (15 gói, 4 hệ sinh thái), chưa chạy xong |
| Secret (Gitleaks) | **chưa có đáp án** |
| Hạ tầng (Trivy config) | **chưa có đáp án** |

---

## 5. Vì sao không có một con số cho cả năm tầng

Năm tầng không cùng mẫu số. Juliet đếm lỗi tiêm ở mức mã nguồn; SCA đếm phiên
bản thư viện dính CVE; DAST đếm endpoint chạy thật; Gitleaks đếm credential bị
commit; Trivy đếm cấu hình sai. Cộng phần trăm của chúng là làm số học trên những
thứ không cùng loại.

Muốn một con số cho cả năm tầng thì phải có một bộ đo mà cả năm tầng đều có cái
để tìm, kèm đáp án cho cả năm. Bộ đó không tồn tại công khai: Juliet và OWASP
Benchmark đều chỉ phủ SAST.

Nên con số **61.6% / 1.0%** là con số của **hai tầng phân tích tĩnh trên Juliet
C#** — không phải của cả pipeline, và không phải tỉ lệ trên mọi loại lỗi ngoài
thực tế.
