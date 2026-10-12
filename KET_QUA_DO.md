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

5772 test case, 9 CWE. Đã đo hai lần.

| Công cụ | Lần #1 — bắt / nhầm | Lần #10 — bắt / nhầm | Youden #10 |
|---|---|---|---|
| Rule đồ án (Semgrep) | 11.8% / **0.3%** | **39.0%** / 3.1% | +0.36 |
| Semgrep cộng đồng | 21.3% / 11.0% | 21.3% / 11.0% | +0.10 |
| CodeQL | 73.1% / 21.3% | 73.1% / 21.3% | +0.52 |
| CodeQL (threat model local) | **94.2%** / 21.9% | **94.2%** / 21.9% | +0.72 |
| **Cổng chặn** | 86.9% / 22.0% | **94.2%** / 25.0% | +0.69 |

Lần #10 là lần đo **sau khi mở rộng nguồn** (G6.3) và **trước khi** bỏ nguồn cấu
hình (G6.5). Nên con số 39.0% ở trên là con số **được thổi lên** — xem mục 6; nó
được giữ lại ở đây đúng để làm vế "trước" của cặp so sánh. Dự đoán khi mở rộng là
~46%, thực tế 39.0%, vẫn dưới trần cấu trúc 54.1%.

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

### Bảng tách theo rule của lần #10 trả lời thêm ba câu

**(a) Giới hạn trong-một-hàm của Semgrep CE đo được chính xác.** Bảng "theo
đường đi của dữ liệu" là bằng chứng sạch nhất mà đồ án có về việc vì sao cần
*hai* công cụ SAST chứ không phải một:

| Đường đi của dữ liệu | Case | Rule đồ án (Semgrep CE) | CodeQL-local |
|---|---|---|---|
| 01 · cơ bản | 156 | **80%** | 94% |
| 02–22 · qua rẽ nhánh / vòng lặp | 2808 | **71%** | 94% |
| 31 · qua biến trung gian | 156 | **80%** | 94% |
| 41–45 · qua hàm khác | 468 | **0%** | 94% |
| 51–54 · qua tệp khác | 624 | **0%** | 94% |
| 61–68 · qua giá trị trả về / mảng / trường | 624 | **0%** | 94% |
| 71–75 · qua collection | 780 | **0%** | 94% |
| 81 · qua lớp con (kế thừa) | 156 | **0%** | 94% |

Không phải "kém hơn một chút" mà là **đúng 0%** ở mọi biến thể vượt khỏi một hàm
— tức 2652/5772 case (46%) nằm ngoài tầm của Semgrep bản cộng đồng *về nguyên
tắc*, không phải vì rule viết thiếu. Đây là lý do định lượng cho việc xếp hai
engine SAST cạnh nhau, và cũng là trần thật của mọi cải tiến rule Semgrep.

**(b) Một rule của đồ án gây ra toàn bộ tỉ lệ báo nhầm.** `dso-java-taint-xpathi`
bắt 180 case (3%) và báo nhầm **đúng 180 case (3%)** — trên CWE-643 nó bắt 41% và
báo nhầm 41%, tức **không phân biệt được gì cả**. Bỏ nó: rule đồ án còn
**36% bắt / 0.0% báo nhầm**. Youden gần như không đổi (+0.36 cả hai bên), nhưng
một bên không chặn oan lần nào. Quyết định nên lấy là bỏ hoặc viết lại rule này.

**(c) Hai truy vấn CodeQL đóng góp 0 điểm bắt và 1116 cảnh báo sai cho cổng.**

| Truy vấn | Bắt | Báo nhầm | Bắt riêng | Bỏ thì cổng còn |
|---|---|---|---|---|
| `java/concatenated-sql-query` | **0** (0%) | 912 (16%) | 0 | 94% bắt / **9%** nhầm |
| `java/concatenated-command-line` | **0** (0%) | 204 (4%) | 0 | 94% bắt / 21% nhầm |

Cả hai là truy vấn *hình dạng* (bắt chuỗi SQL/lệnh được nối, không theo luồng),
nên mọi case chúng bắt đều đã bị `java/sql-injection` và
`java/command-line-injection` bắt theo luồng — cột "bắt riêng" = 0 nói đúng điều
đó. Loại hai truy vấn này khỏi cổng đưa báo nhầm từ **25.0% xuống ~9%** mà **không
mất một điểm bắt nào**. Đây là cải tiến lớn nhất còn lại chưa làm, và nó không
cần viết thêm một rule nào — chỉ cần `query-filters` trong cấu hình CodeQL.

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

## 4. Bộ rule Python — BenchProctor quicktest, 18.300 test case

Chạy `Phong do Python #2` ngày 9/10/2026 trên commit `0d3b8cc`, 10 phút 6 giây.
9.150 case có lỗi / 9.150 case sạch, 61 category, 3 khung (flask, fastapi, django).

Khác Juliet ở **mẫu số**: Juliet mỗi case có cả hàm `bad` lẫn hàm `good` nên mẫu số
của cả hai tỉ lệ là toàn bộ case; BenchProctor mỗi case là một tệp *hoặc* có lỗi
*hoặc* sạch, nên tỉ lệ bắt tính trên 9.150 case có lỗi và tỉ lệ báo nhầm trên 9.150
case sạch.

| Công cụ | Lần #2 — bắt / nhầm | Lần #9 — bắt / nhầm | Youden #9 |
|---|---|---|---|
| Rule đồ án (Semgrep) | 7,2% / 4,4% | **14,5%** / **10,5%** | **+0,04** |
| Semgrep cộng đồng | 21,2% / 10,3% | 21,2% / 10,3% | +0,11 |
| CodeQL | 13,3% / 3,3% | 13,3% / 3,3% | +0,10 |
| CodeQL (threat model local) | 14,1% / 4,0% | 14,1% / 4,0% | +0,10 |
| **Cổng chặn** | 18,2% / 7,4% | **24,2%** / **12,8%** | +0,11 |

Theo khung web, rule đồ án lần #2: flask 10%/7%, fastapi 7%/4%, django 4%/2%.

**Lần #9 là lần đo sau khi mở rộng nguồn + 3 đích (G6.2), và nó nói một điều khó
nghe: mở rộng đó gần như chỉ thêm tiếng ồn.** Bắt tăng gấp đôi (7,2% → 14,5%)
nhưng báo nhầm cũng tăng gấp hơn hai (4,4% → 10,5%), nên Youden chỉ nhích từ
+0,03 lên **+0,04** — tức bộ rule Python của đồ án vẫn **chỉ hơn đoán mò một
chút**, và kém bộ rule cộng đồng (+0,11) rõ rệt trên bộ đo này.

Quan trọng hơn: dự đoán là 33,6% → **78,2%** sau khi mở rộng. Thực tế **14,5%**.
Lệch quá xa để còn giải thích bằng "thiếu nguồn, thiếu đích" được nữa. Nguyên nhân
thật đã được đo sạch ở phòng đo Java (mục 2, bảng theo đường đi của dữ liệu):
**taint của Semgrep bản cộng đồng đi được 71–80% khi luồng nằm trong một hàm và
đúng 0% khi luồng vượt ra khỏi hàm.** Trần 78,2% được tính từ *nguồn và đích*, mà
yếu tố chặn thật là *độ dài của luồng* — tức trần đó tính sai cơ sở.

Hệ quả cho báo cáo: đường cải tiến "thêm nguồn, thêm đích" đã hết tác dụng đối
với Semgrep CE. Phần còn lại của 85,5% chưa bắt được **không** nằm trong tầm của
rule Semgrep, mà là việc của CodeQL.

**Cả 7,2% lẫn 14,5% phải đọc kèm trần của chúng.** Bộ rule Python chỉ nhắm tới 8 họ CWE trong 61
category của bộ đo — tức **2.250/9.150 case có lỗi (24,6%)**. 6.900 case còn lại
thuộc các loại đồ án **cố ý không phủ** (`authzfailure`, `hardcodedcreds`,
`loginjection`, `sessionfixation`…), vì quyền chặn chỉ dành cho CWE mà ZAP có
active scan tương ứng. Nên đặt con số này cạnh "61,6% trên Juliet C#" là so
sánh sai: Juliet C# chỉ chứa đúng những CWE mà rule nhắm tới.

**Ba điều lần #2 xác nhận, cả ba đã sửa và đã đo lại ở lần #9:**

| Phát hiện | Số liệu | Bản sửa |
|---|---|---|
| NoSQL injection không công cụ nào thấy | CWE-943: **0% / 0%** cho *cả 4* công cụ | rule `dso-py-taint-nosqli` (G6.2) |
| SSTI bị bỏ khi chấm do gán nhãn sai họ CWE | CWE-1336: rule đồ án **0%**, cộng đồng 35% | rule `dso-py-taint-ssti` với `cwe: CWE-1336` (G6.2) |
| Nguồn quá hẹp | bắt 7,2% so với trần cấu trúc 33,6% | mở 10 hình dạng nguồn (G6.2) |

**Báo nhầm 4,4% (lần #2) là con số gộp, và nó che mất vấn đề thật.** Trên toàn bộ 9.150 case
sạch thì thấp, nhưng báo nhầm **dồn hết vào đúng các CWE mà rule nhắm tới**:
CWE-22 36%, CWE-95 33%, CWE-78 32%, CWE-88 30%, CWE-918 26%. Hai nhóm thậm chí
**báo nhầm nhiều hơn bắt được**: CWE-918 (22% bắt / 26% nhầm) và CWE-601 (13% / 17%).
Đây đúng là sàn báo nhầm đã dự đoán trong `PHAT_HIEN_BENCHPROCTOR.md`: bản sạch của
BenchProctor khử độc bằng `if không hợp lệ thì return 400`, giá trị tới đích không
đổi, mà `pattern-sanitizers` của Semgrep chỉ khớp biểu thức *làm đổi giá trị*.

Điểm sáng duy nhất của rule đồ án: **CWE-611 (XXE) bắt 100% với 0% báo nhầm** —
vì rule đó không dùng taint mà khớp trực tiếp cấu hình `resolve_entities=True`.

> **Không dùng bảng dò ngưỡng của lần chạy này.** Bảng đó in tỉ lệ bằng **đúng một
> nửa** sự thật: `quet_nguong()` dùng mẫu số kiểu Juliet (toàn bộ 18.300 case) trong
> khi bảng chính tách 9.150/9.150. Cùng một cấu hình mà bảng chính ghi 18,2%/7,4%
> còn bảng dò ngưỡng ghi 9,1%/3,7%. Đã sửa và đã có phép kiểm khẳng định hai bảng
> phải khớp nhau. Thứ hạng trong bảng đó vẫn đúng (cả hai tỉ lệ cùng chia cho một
> hằng số), chỉ con số là sai.

---

## 5. Ba thay đổi đã làm sau lần đo, chưa có số mới

Ghi ở đây để lần đo sau đối chiếu được. **Chưa có số** nghĩa là chưa chạy, không
phải đã cải thiện.

| Thay đổi | Dự đoán, và căn cứ |
|---|---|
| **Python: mở nguồn + 3 đích mới** (G6.2) | Trần cấu trúc 33.6% → **78.2%** của 2.250 case thuộc phạm vi rule. Báo nhầm **sẽ không gần 0**: sàn ≈ 22.6% vì bản sạch của BenchProctor khử độc bằng `if … return 400`, thứ `pattern-sanitizers` không diễn tả được. Chi tiết: `PHAT_HIEN_BENCHPROCTOR.md` |
| **Java: mở nguồn ra ngoài HTTP** (G6.3), **đã đảo ngược một phần** (G6.5) | Dự đoán ban đầu 11.8% → ~46%. Dự đoán đó **không còn hiệu lực**: hai trong bốn họ nguồn được thêm đã bị bỏ lại, vì chúng là *cấu hình* chứ không phải *dữ liệu*. Xem mục 6 — đây là phát hiện phương pháp đáng kể nhất của phần đo |
| **Corpus logic nghiệp vụ** (G6.4) | Bộ đo mới cho câu "mã đúng có bị chặn không": 3 tệp, 38 hàm mã nghiệp vụ an toàn nhưng trông như lỗi. Đáp án **0 cảnh báo mức chặn**. Đây là bộ đo còn thiếu để quyết `dso-weak-hash` / `dso-weak-random` có nâng lên mức chặn được hay không |

Những dự đoán này là **phép kiểm cho chẩn đoán**, không phải lời hứa — và dòng
Java ở trên là ví dụ về việc một phép kiểm như vậy *trượt*: không phải vì chẩn
đoán "thiếu nguồn" sai, mà vì hai trong bốn họ nguồn được thêm **không mang
quyền điều khiển của kẻ tấn công trên mã thật**. Mục 6 ghi đầy đủ.

---

## 6. Khi điểm bắt là điểm tăng giả — họ nguồn "cấu hình"

Đây là phát hiện quan trọng nhất mà phần đo của đồ án tạo ra, và nó chỉ hiện ra
được vì có **ba** bộ đo chứ không phải một.

### Việc đã làm, và vì sao nó trông đúng

Lần đo Java #1 cho tỉ lệ bắt **11.8%**, nằm ngay dưới trần cấu trúc 14.0%. Chẩn
đoán: rule thiếu nguồn. Đo lại nhãn của corpus xác nhận — nguồn HTTP chỉ chiếm
777/2997 case (25.9%), còn **74.1%** case dùng nguồn khác. Bốn họ nguồn ngoài
HTTP được thêm vào, và trần tính lại nhảy lên 54.1%.

Lập luận khi đó: *"mở rộng nguồn là mở rộng vùng bắt mà không mở rộng vùng báo
nhầm, vì đích vẫn là đích cũ."* Nghe hợp lý, và trên bộ rule C# nó đã đúng thật
ở lần đo #26 (47.3% → 63.6% bắt, cột báo nhầm giữ nguyên 0.0%).

### Việc bộ đo thứ ba phát hiện

`Phòng đo logic nghiệp vụ #7` **chặn oan** một hàm mã đúng:

```java
public static File tepTamBaoCao() {
    return new File(System.getProperty("java.io.tmpdir"), "bao_cao_tam.csv");
}
```

`dso-java-taint-path-traversal` báo, vì `$P.getProperty(...)` vừa trở thành
nguồn. Không có gì để "khử độc" ở đây — hàm này **không có** dữ liệu người dùng.

### Bốn con số dẫn tới quyết định bỏ

| Bằng chứng | Số |
|---|---|
| Rule taint Java trong `semgrep/semgrep-rules` dùng `System.getenv` hoặc `getProperty` làm nguồn | **0 / 21** — không xuất hiện một lần nào |
| Tệp rule Python chính thức có dùng, và **chỉ** cho đích *thực thi lệnh* | 2 / 59 |
| Tệp Juliet Java lấy `getProperty` (761) hoặc `getenv` (222) làm nguồn | **983 / 4920** — họ nguồn ngoài-HTTP lớn nhất của corpus |
| Lần chặn oan trên corpus mã nghiệp vụ thật | **1** |

### Vì sao hai số đó không mâu thuẫn nhau

Juliet dùng `System.getProperty` vì nó cần **một giá trị mà trình biên dịch
không gấp lại được** — đó là thủ thuật kỹ thuật để sinh test case, **không** phải
một mô hình về kẻ tấn công. Mã thật dùng đúng hai hàm đó để đọc **cấu hình triển
khai**: giá trị do người vận hành đặt. Ai đặt được system property cho tiến trình
JVM thì đã chạy được mã trong tiến trình đó rồi — không còn gì để leo thang.

Nên nhận họ nguồn này là "nhiễm độc" làm tỉ lệ bắt trên Juliet tăng mạnh **mà
không** làm pipeline bắt thêm được một lỗ hổng thật nào. Câu *"mở rộng nguồn
không mở rộng vùng báo nhầm"* chỉ đúng với nguồn **đọc dữ liệu** (`readLine`,
`ResultSet.getString`). Với nguồn **cấu hình** nó sai, và cái giá **không hiện ra
trên Juliet** — chỉ hiện ra trên mã thật.

### Đã sửa gì

Bỏ nguồn cấu hình khỏi mọi rule taint của cả ba bộ rule, giữ lại duy nhất ở rule
`*-cmdi` (đích là thực thi lệnh — chỗ duy nhất bộ rule chính thức chấp nhận, và
cũng là chỗ biến môi trường đi vào shell thật sự nguy hiểm):

| Bộ rule | Nguồn bị bỏ | Số rule bị ảnh hưởng |
|---|---|---|
| `sast-detect.yaml` (C#) | `Environment.GetEnvironmentVariable` | 7 |
| `sast-detect-java.yaml` | `System.getenv`, `$P.getProperty` | 8 |
| `sast-detect-python.yaml` | `os.environ`, `os.getenv` | 9 |

Giữ nguyên ở `pattern-sanitizers` của rule CWE-259/798: ở đó "giá trị đến từ biến
môi trường" đúng là bằng chứng mật khẩu **không** bị viết cứng — ngược dấu hoàn
toàn với việc dùng nó làm nguồn.

### Phép kiểm, không phải chú thích

Một quyết định chỉ ghi trong chú thích thì lần sau có người đi tìm điểm bắt sẽ
thêm lại, và bảng đo Juliet sẽ tự khen. Nên có hai lớp chốt:

1. `nguon_cauhinh_sai_cho()` trong `semgrep-rules/kiem-thu-rule/chay_kiem_thu.py`
   — làm CI đổ **trước khi** chạy Semgrep nếu nguồn cấu hình xuất hiện ngoài rule
   `*-cmdi`. Đã thử bốn hướng: ba tệp hiện tại sạch; đột biến trên cả ba tệp đều
   bị bắt; nguồn nằm ở `pattern-sinks` / `pattern-sanitizers` được bỏ qua đúng.
2. Hai case fixture *nguồn-cấu-hình-vào-đích-đường-dẫn* chuyển từ `Co_Loi.*` sang
   `Da_Khu_Doc.*`, **bỏ luôn bước khử độc**, thành case **phải không bị bắt**
   (thêm một case tương tự cho Python). Thêm lại nguồn thì điều kiện 2 của bộ
   kiểm thử đổ ngay tại dòng đó.

### Hệ quả phải ghi thẳng

**Tỉ lệ bắt Juliet Java ở lần đo sau sẽ thấp hơn mức ~46% đã dự đoán.** Đó là con
số *đúng hơn*, không phải con số *tệ hơn*. Và nếu đồ án chỉ có Juliet với
BenchProctor, lần mở rộng nguồn đó đã được ghi vào báo cáo như một **cải tiến**.

---

## 7. Chưa có bộ đo

| Tầng | Trạng thái |
|---|---|
| ~~Python (SAST)~~ | **đã có số — xem mục 4** |
| SCA — thư viện đã có | đáp án đã dựng (15 gói, 4 hệ sinh thái), chưa chạy xong |
| Secret (Gitleaks) | đáp án đã dựng (14 tệp, 7 dạng secret + 4 mồi, fixture sinh lúc chạy), chưa chạy xong |
| Hạ tầng (Trivy config) | **chưa có đáp án** |

---

## 8. Vì sao không có một con số cho cả năm tầng

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
