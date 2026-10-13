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
| #28 | bỏ CWE-643 khỏi tầng CodeQL | 61.6% | 1.0% | +0.61 |
| #43 | bỏ họ nguồn cấu hình khỏi rule taint | 60.8% | 1.0% | +0.60 |
| #47 | thêm `dso-sqli-tham-so-ham-noi-chuoi` (rule chặn được SQLi tầng dữ liệu) | **62.3%** | **4.3%** | **+0.58** |

**Lần #47 là lần đo có thẩm quyền** — chạy trên `main` tại commit `daf589e`,
tức bộ rule đang dùng thật. Mọi con số C# trong báo cáo lấy từ lần này.

Tách theo công cụ ở lần #47:

| Công cụ | Bắt | Báo nhầm | Youden |
|---|---|---|---|
| Rule đồ án, tính cả mức chỉ báo | 50.4% | 31.9% | +0.18 |
| Rule cộng đồng của Semgrep | 11.0% | 10.2% | +0.01 |
| CodeQL (bộ truy vấn mặc định) | 27.5% | 3.3% | +0.24 |
| CodeQL (threat model local) | 40.2% | 5.2% | +0.35 |
| Rule đồ án, chỉ mức có quyền chặn | 35.9% | 3.3% | +0.33 |
| **Hợp lại = cổng chặn** | **62.3%** | **4.3%** | **+0.58** |

### Rule mới làm cổng TỐT HƠN hay TỆ HƠN? — phải nói thẳng

Lần #47 thêm `dso-sqli-tham-so-ham-noi-chuoi`. Bảng tách theo rule của chính
lần đó cho biết cái giá của nó:

| | Bắt | Báo nhầm | Youden |
|---|---|---|---|
| Cổng **không có** rule này | 61.0% | 1.0% | **+0.60** |
| Cổng **có** rule này (đang dùng) | 62.3% | 4.3% | **+0.58** |

Đổi **+1.3 điểm bắt** lấy **+3.3 điểm báo nhầm**. Theo Youden thì rule này làm
cổng **tệ đi 0.02**. Giữ nó lại là một quyết định có chủ đích, và đây là ba căn
cứ — đọc xong vẫn có thể không đồng ý, nhưng không phải là giấu số:

1. **216 báo nhầm trên Juliet bị ép ra bởi thiết kế của chính Juliet.** Mỗi case
   có `badSink` và `goodG2BSink` với **thân hàm giống hệt nhau**; chỗ khác nhau
   nằm ở hàm gọi. Một rule taint trong-một-hàm lấy nguồn là tham số của hàm thì
   **bắt buộc** phải gắn cờ cả hai. Đây là hạn chế của bộ đo gặp hạn chế của
   Semgrep CE, không phải rule viết ẩu.
2. **104 case chỉ rule này bắt được** (cột "bắt riêng" của bảng
   `pipeline-hien-tai`). Bỏ nó đi là mất hẳn 104 case, không công cụ nào khác
   trong cổng đỡ được.
3. **Trên mã nghiệp vụ thật thì khác hẳn.** Corpus logic nghiệp vụ — mã đúng
   nhưng trông như lỗi — đo được **0 cảnh báo mức chặn**. Xem mục 3b; đó mới là
   con số nói về chặn oan trên mã người ta viết thật.

Và căn cứ quyết định nhất: rule này là **thứ duy nhất chặn được SQLi thật của
VulnShop tại dòng PR sửa**. CodeQL bỏ sót hoàn toàn, rule cộng đồng bắt được
nhưng neo ở dòng không đổi nên GitHub không chặn. Xem mục 3c.

**Điều đã học ở lần #43.** Bỏ họ nguồn cấu hình - biến môi trường và thuộc
tính cấu hình - khỏi mọi rule taint trừ rule command injection: cổng C# mất
**0.8 điểm bắt** (61.6% -> 60.8%) và bộ rule C# mất
**1.1 điểm** (33.8% -> 32.7%). Cùng thay đổi đó làm Juliet Java mất 11.2 điểm.
Chênh lệch giữa hai ngôn ngữ chính là thước đo mức độ corpus phụ thuộc vào họ
nguồn đó, chứ không phải thước đo chất lượng rule - xem PHAT_HIEN_BENCHPROCTOR.md.

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

| Công cụ | Lần #1 | Lần #10 (có nguồn cấu hình) | **Lần #12 (cuối)** | Youden #12 |
|---|---|---|---|---|
| Rule đồ án (Semgrep) | 11.8% / 0.3% | 39.0% / 3.1% | **27.8% / 0.0%** | +0.28 |
| Semgrep cộng đồng | 21.3% / 11.0% | 21.3% / 11.0% | 21.3% / 11.0% | +0.10 |
| CodeQL | 73.1% / 21.3% | 73.1% / 21.3% | 73.1% / 21.3% | +0.52 |
| CodeQL (threat model local) | 94.2% / 21.9% | 94.2% / 21.9% | 94.2% / 21.9% | +0.72 |
| **Cổng chặn** | 86.9% / 22.0% | 94.2% / 25.0% | **94.2% / 2.5%** | **+0.92** |

**Lần #12 là lần đo sau cả ba thay đổi** (bỏ nguồn cấu hình, bỏ
`dso-java-taint-xpathi`, loại hai truy vấn `java/concatenated-*` khỏi quyền
chặn). Hai điều đáng đọc:

1. **Cổng giữ nguyên 94.2% bắt nhưng báo nhầm tụt từ 25.0% xuống 2.5%** —
   Youden +0.69 → **+0.92**. Dự đoán trước khi làm là ~9%; thực tế 2.5%, tốt hơn
   dự đoán vì `dso-java-taint-xpathi` đóng góp thêm 180 cảnh báo sai nữa.
2. **Bộ rule tự viết về 0.0% báo nhầm** trên 5772 ca, đổi bằng 11.2 điểm bắt.

Bảng dò ngưỡng 224 tổ hợp xếp cấu hình đang chạy ở **hạng 3**, cùng +0.917 với
năm tổ hợp đứng trên (chúng chỉ khác nhau ở chỗ có cho Semgrep quyền chặn hay
không — mà Semgrep ở Java không thêm độ phủ, xem dưới).

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
một bên không chặn oan lần nào.

**Đã bỏ rule này (G6.6).** Cột "bắt riêng" của nó trong bảng `pipeline-hien-tai`
bằng 0, nên cổng chặn không mất điểm nào: `java/xml/xpath-injection` của CodeQL
bắt 444 case (8%) với 12 báo nhầm (0%) và bắt riêng 264. Đáng ghi lại là **cùng
CWE-643 nhưng hai ngôn ngữ cho hai kết luận ngược nhau**: ở C# thì CodeQL bắt 76%
/ báo nhầm 76% nên truy vấn `cs/xml/xpath-injection` bị loại và rule tự viết
`dso-taint-xpathi` (49% / 0%) giữ quyền chặn; ở Java thì đúng ngược lại. Không
có quy tắc chung nào suy ra được điều đó — chỉ có phòng đo từng ngôn ngữ.

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
cạnh "62.3% trên 6611 case" là so sánh hai thứ khác loại.

### Độ phủ — tầng DAST với tới bao nhiêu phần ứng dụng

Bắt được 6/6 lỗ hổng đã gài **không** có nghĩa là quét hết ứng dụng. Trên
VulnShop (15 endpoint), bản đồ route cho biết DAST với tới đâu:

| | Trước lớp POST | Sau lớp POST |
|---|---|---|
| GET có tham số | 4 | 4 |
| POST có tham số | 0 | 4 |
| **Tổng dò được** | **4/15 = 27%** | **8/15 = 53%** |

7 endpoint còn lại là GET không tham số (6) và POST không tham số (1) — không
có chỗ nào để chèn payload, nên không phải là thiếu sót của công cụ.

Nguyên nhân của 27% ban đầu **không phải đăng nhập** (`needs_auth = 0`) mà là
**phương thức**: 5 endpoint POST mang 8 tham số, gồm `/Account/Login`
(username, password) và `/Order/PlaceOrder` (customerName, address) — đúng các
vị trí SQLi hay nằm nhất — chưa bao giờ được dò.

### Hạn chế lớn nhất của tầng DAST: phụ thuộc chế độ chạy

Cả lớp GET lẫn lớp POST đều là **error-based**: chúng kết luận có SQLi khi phản
hồi lộ thông báo lỗi của `Microsoft.Data.Sqlite`. `Program.cs` chỉ bật trang
lỗi chi tiết khi `ASPNETCORE_ENVIRONMENT=Development`, và pipeline khởi động app
bằng `dotnet run` nên lấy profile `http` có đặt biến đó.

**Ở chế độ Production, lỗi bị nuốt và cả hai lớp mù hoàn toàn.** Đây không phải
lỗi để sửa — đó là bản chất của kỹ thuật error-based — nhưng mọi con số bắt
được của tầng DAST chỉ đúng cho ứng dụng chạy ở chế độ hiện lỗi.

---

## 3b. Chặn oan trên mã nghiệp vụ thật — corpus logic nghiệp vụ

Juliet và BenchProctor đều là **mã sinh ra để đo**: mỗi case sạch là một case
lỗi được sửa vừa đủ. Tỉ lệ báo nhầm đo trên đó nói về corpus đó, không nói về
mã ứng dụng thật. Corpus này lấp đúng chỗ đó: 3 tệp, **40 hàm mã nghiệp vụ
đúng nhưng trông như lỗi** — MD5 dùng làm ETag và khoá cache, `Random` dùng
phát hiện tệp trùng, mệnh đề `IN` ghép từ danh sách Id, `ORDER BY` lấy tên cột
từ bảng trắng.

**Kết quả: 0 cảnh báo ở mức có quyền chặn.** 7 cảnh báo ở mức chỉ báo — không
tính là sai, vì đó là lựa chọn có chủ đích: báo cho người review đọc, không
chặn merge.

**Đã chạy lại trên bộ rule hiện tại.** Lần đo trước là commit `4f964df`,
*trước* khi thêm `dso-sqli-tham-so-ham-noi-chuoi` — rule ở mức chặn, lấy nguồn
là tham số chuỗi của bất kỳ hàm nào, nên nó *có khả năng* chạm vào
`DemDonHang(string cotSapXep)`, hàm dùng tham số làm khoá tra bảng trắng. Đọc
rule thì nó không khớp, nhưng đọc không thay được chạy. Nên phép đo được chạy
lại: **Phòng đo logic nghiệp vụ #14**, commit `1bf920b` trên `main`, 41 giây,
kết luận Success.

| Lần đo | Commit | Có rule tầng truy cập dữ liệu? | Chặn oan | Mức chỉ báo |
|---|---|---|---|---|
| #13 | `4f964df` | không | 0 | 7 |
| **#14** | `1bf920b` | **có** (`dso-sqli-tham-so-ham-noi-chuoi`, ERROR) | **0** | **7** |

Hai lần đo cho kết quả giống nhau từng con số, nên **con số 0-chặn-oan áp dụng
cho bộ rule đang dùng thật**, không còn kèm điều kiện. Bảy cảnh báo mức chỉ báo
vẫn là bảy cảnh báo cũ, do `dso-weak-hash` (3), `dso-weak-random` (1),
`dso-xpathi-select-concat` (1), `dso-sqli-sqlcommand-ctor-concat` (1) và
`dso-sqli-commandtext-concat` (1) — **rule mới không sinh thêm cảnh báo nào**,
kể cả ở mức chỉ báo. Cảnh báo ngoài thư mục corpus: 0.

---

## 3c. Ba công cụ cùng thấy một lỗ hổng — chỉ một chặn được

Đây là phát hiện trung tâm của đồ án, đo trên PR #18 của VulnShop-App
(nhánh `demo/vuln-feature`, SQLi ở `Data/Db.cs`).

| Công cụ | Thấy lỗ hổng? | Neo cảnh báo ở dòng | Chặn được merge? |
|---|---|---|---|
| **Semgrep rule đồ án** | có — 2 cảnh báo | **94** và 97 | **CÓ** |
| Semgrep rule cộng đồng (`p/csharp`) | có — 1 cảnh báo | 97 | không |
| OWASP-ZAP (khai thác động) | có — High | `ProductController.cs:10` | qua cổng xác nhận |
| **CodeQL csharp** | **không — 0 cảnh báo** | — | không |

**Vì sao dòng neo quyết định tất cả.** GitHub chỉ chặn cảnh báo nằm trên dòng
mà PR **đã sửa**. Trong `Db.cs`, dòng 94 là chỗ nối chuỗi (`sql += ...`, PR sửa
dòng này) còn dòng 97 là chỗ thực thi (`cmd.CommandText = sql;`, PR không đụng
tới). Mặc định Semgrep taint neo cảnh báo ở **sink**, tức dòng 97 — và cảnh báo
đó bị GitHub xếp là "không mới", nên PR **merge được dù có lỗ hổng High**.

Rule cộng đồng bắt đúng lỗ hổng đó và cũng neo ở dòng 97, nên nó **cũng không
chặn được**. Nghĩa là: dùng bộ rule cộng đồng mặc định thì lỗ hổng này lọt.

Cách sửa là thêm một sink thứ hai ngay tại điểm nối chuỗi, với
`focus-metavariable` trỏ vào biểu thức được nối, để cảnh báo rơi đúng dòng PR
sửa. Sau khi sửa, PR #18 chuyển từ *"All checks have passed"* sang
**"Merging is blocked"**.

**Đây là lý do đồ án không dừng ở việc cài công cụ.** Cả ba công cụ đều "chạy
thành công" và đều hiện cảnh báo trong tab Code scanning. Người đọc bảng điều
khiển sẽ kết luận pipeline đang bảo vệ. Thực tế là merge vẫn đi qua.

---

## 3d. Pull request thứ ba — cùng loại lỗ hổng, CodeQL cho kết quả ngược lại

PR #21 gieo SQL injection qua **biểu mẫu POST**: `Db.FindProducts(string term,
string? sortBy)` nối cả hai tham số vào câu lệnh, `sortBy` đi thẳng vào
`ORDER BY`.

| | PR #18 (tham số URL) | PR #21 (biểu mẫu POST) |
|---|---|---|
| Rule đồ án | 2 cảnh báo (94, 97) | 3 cảnh báo (114, 116, 117) |
| Rule cộng đồng | 1 (dòng 97) | 1 (dòng 117) |
| **CodeQL csharp** | **không thấy SQLi** (chỉ `cs/web/missing-token-validation`) | **thấy** — `cs/sql-injection`, 8.8 |
| Tầng động | ZAP: SQL Injection | ZAP: SQL Injection, **đã khai thác được** |
| Kết quả merge | bị chặn (sau khi vá) | **bị chặn** |

Hai lỗ hổng cùng hình dạng: tham số chuỗi của một hàm ở tầng truy cập dữ liệu,
nối vào câu lệnh, gọi từ một action nhận dữ liệu HTTP. **Nguyên nhân chênh lệch
chưa xác định được** và không được suy đoán ở đây.

Điều rút ra được: phân tích liên thủ tục của CodeQL **có** bắt loại này nhưng
**không ổn định**. Một cổng chỉ dựa vào CodeQL sẽ để lọt trường hợp thứ nhất.

### Tầng động chặn merge thật

Đây là lần đầu tầng động chặn merge trong pipeline thật, không phải trong phòng
đo. Cổng xác nhận thoát mã 1 vì một phát hiện **đã được chứng minh bằng tương
tác thật** — khác với suy đoán tĩnh, nên nó chặn bất kể dòng mã có nằm trong
thay đổi của PR hay không.

Bằng chứng: `H01_PR21-cong-xac-nhan-chan.jpg`,
`H02_PR21-DAST-bat-sqli-qua-form-POST.jpg`, `H03_PR21-codeql-bat-duoc-lan-nay.jpg`.

### Hai chỗ lần chạy này làm lộ ra

1. **Dòng độ phủ trong bảng tóm tắt chỉ đếm `testable`** nên ghi 4/16 trong khi
   tầng động đo được 8. Đã sửa để cộng cả `post_param`.
2. **Job canh giữ ruleset báo "chưa kiểm được"** trên VulnShop, vì
   `ruleset_mong_doi.json` nằm ở kho bộ công cụ chứ không ở kho ứng dụng — mà
   job chạy trong ngữ cảnh kho gọi. Nghĩa là ruleset của VulnShop **vẫn chưa
   được canh giữ**. Phải thêm tệp đặc tả vào kho ứng dụng.

---

## 3e. Lớp POST — chạy lại cùng một commit, trước và sau khi sửa

PR #21 được chạy **hai lần trên đúng commit `5b85e36`**, chỉ khác bộ công cụ.

| Chỉ số | Lần 1 (lớp POST còn lỗi) | Lần 2 (sau khi sửa) |
|---|---|---|
| Độ phủ tầng động | 4/16 | **9/16** (4 URL + 5 biểu mẫu) |
| DAST mức High | 2 | **3** |
| Cổng xác nhận chặn | 1 | **2** |
| Tổng vấn đề phải sửa | 4 | **5** |
| Lớp POST đóng góp | **0** | **1 — tham số `term`** |

Lỗi đã sửa: lớp POST đặt mọi trường của biểu mẫu bằng seed, nên ô chọn `sortBy`
thành `ORDER BY a` và sinh lỗi CSDL ngay với đầu vào lành → bước so sánh mốc kết
luận "endpoint luôn lỗi" → bỏ qua cả biểu mẫu.

Hai dòng DAST của lần 2 bắt **hai tham số khác nhau của cùng một endpoint, bằng
hai kỹ thuật khác nhau**: ZAP bắt `sortBy` (payload `;`), lớp POST bắt `term`
(payload `a'`).

**Dạng hỏng này đáng ghi nhớ:** lần 1 không báo sai điều gì, nó chỉ *im lặng* —
và im lặng không phân biệt được với "đã quét, không có gì".

Bằng chứng: `J01_PR21-lop-POST-bat-duoc-term.jpg`.

---

## 3f. Độ phủ ngoài SQL injection — PR #22

Ba PR trước đều gieo SQLi. PR #22 gieo **6 lỗ hổng thuộc 5 nhóm OWASP, không có
SQLi nào**. Sáu rule được dự đoán trước khi chạy:

| Lỗ hổng | OWASP | Rule | Dự đoán | Thực tế |
|---|---|---|---|---|
| XSS qua `Html.Raw` | A03 | `dso-xss-html-raw-razor` | chặn | **High ✔** |
| Path traversal | A01 | `dso-pathtraversal-physicalfile` | chặn | **High ✔** |
| SSRF | A10 | `dso-ssrf-http-client-concat` | chặn | **High ✔** |
| Mật khẩu cứng | A07 | `dso-hardcoded-password` | chặn | **High ✔** |
| Băm yếu MD5 | A02 | `dso-weak-hash` | chỉ báo | **Medium ✔** |
| Open redirect | A01 | `dso-openredirect-parameter` | chỉ báo | **Medium ✔** |
| — ngoài dự đoán | A01 | `dso-taint-path-traversal` | — | **High** |

**6/6 đúng**, cộng một rule ngoài dự đoán (lớp taint bắt path traversal độc lập
với rule hình dạng, cùng một dòng).

### Tầng động xếp nặng hơn tầng tĩnh ở đúng một chỗ

ZAP ra 4 cảnh báo High: XSS phản xạ, **External Redirect**, path traversal ×2.

Open redirect được phân tích tĩnh xếp **chỉ báo** (hình dạng trùng nhiều trường
hợp chuyển hướng hợp lệ), nhưng ZAP xếp **High** — vì ZAP không suy đoán từ hình
dạng mà gửi URL ngoài rồi quan sát ứng dụng chuyển hướng thật.

Đây là minh hoạ cụ thể cho lý do hai tầng không thay thế nhau: tĩnh thấy *mọi*
chỗ đáng ngờ nhưng không biết chỗ nào khai thác được; động chỉ thấy chỗ nó với
tới nhưng biết chắc. Open redirect rơi đúng khoảng cách đó.

Bằng chứng: `I01_PR22-SAST-7-rule-5-nhom-owasp.jpg`,
`I02_PR22-ZAP-xss-openredirect-pathtraversal.jpg`.

---

## 4. Bộ rule Python — BenchProctor quicktest, 18.300 test case

Chạy `Phong do Python #2` ngày 9/10/2026 trên commit `0d3b8cc`, 10 phút 6 giây.
9.150 case có lỗi / 9.150 case sạch, 61 category, 3 khung (flask, fastapi, django).

Khác Juliet ở **mẫu số**: Juliet mỗi case có cả hàm `bad` lẫn hàm `good` nên mẫu số
của cả hai tỉ lệ là toàn bộ case; BenchProctor mỗi case là một tệp *hoặc* có lỗi
*hoặc* sạch, nên tỉ lệ bắt tính trên 9.150 case có lỗi và tỉ lệ báo nhầm trên 9.150
case sạch.

| Công cụ | Lần #2 — bắt / nhầm | Lần #9 — bắt / nhầm | Youden #11 |
|---|---|---|---|
| Rule đồ án (Semgrep) | 7,2% / 4,4% | **13,7%** / **9,9%** | **+0,04** |
| Semgrep cộng đồng | 21,2% / 10,3% | 21,2% / 10,3% | +0,11 |
| CodeQL | 13,3% / 3,3% | 13,3% / 3,3% | +0,10 |
| CodeQL (threat model local) | 14,1% / 4,0% | 14,1% / 4,0% | +0,10 |
| **Cổng chặn** | 18,2% / 7,4% | **23,7%** / **12,4%** | +0,11 |

Theo khung web, rule đồ án lần #2: flask 10%/7%, fastapi 7%/4%, django 4%/2%.

**Lần #9 là lần đo sau khi mở rộng nguồn + 3 đích (G6.2), và nó nói một điều khó
nghe: mở rộng đó gần như chỉ thêm tiếng ồn.** Bắt gần gấp đôi (7,2% → 13,7%)
nhưng báo nhầm cũng tăng gấp hơn hai (4,4% → 9,9%), nên Youden chỉ nhích từ
+0,03 lên **+0,04** — tức bộ rule Python của đồ án vẫn **chỉ hơn đoán mò một
chút**, và kém bộ rule cộng đồng (+0,11) rõ rệt trên bộ đo này.

Quan trọng hơn: dự đoán là 33,6% → **78,2%** sau khi mở rộng. Thực tế **13,7%**.
Lệch quá xa để còn giải thích bằng "thiếu nguồn, thiếu đích" được nữa. Nguyên nhân
thật đã được đo sạch ở phòng đo Java (mục 2, bảng theo đường đi của dữ liệu):
**taint của Semgrep bản cộng đồng đi được 71–80% khi luồng nằm trong một hàm và
đúng 0% khi luồng vượt ra khỏi hàm.** Trần 78,2% được tính từ *nguồn và đích*, mà
yếu tố chặn thật là *độ dài của luồng* — tức trần đó tính sai cơ sở.

Hệ quả cho báo cáo: đường cải tiến "thêm nguồn, thêm đích" đã hết tác dụng đối
với Semgrep CE. Phần còn lại của 85,5% chưa bắt được **không** nằm trong tầm của
rule Semgrep, mà là việc của CodeQL.

**Cả 7,2% lẫn 13,7% phải đọc kèm trần của chúng.** Bộ rule Python chỉ nhắm tới 8 họ CWE trong 61
category của bộ đo — tức **2.250/9.150 case có lỗi (24,6%)**. 6.900 case còn lại
thuộc các loại đồ án **cố ý không phủ** (`authzfailure`, `hardcodedcreds`,
`loginjection`, `sessionfixation`…), vì quyền chặn chỉ dành cho CWE mà ZAP có
active scan tương ứng. Nên đặt con số này cạnh "60,8% trên Juliet C#" là so
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
| Tệp rule Python chính thức có dùng — và **mọi** tệp trong số đó đều đặt nguồn này cho đích *thực thi* (tiến trình, shell, hoặc chạy một chuỗi mã) | 11 / 59 |
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

## 7. Bảng đối soát — mỗi tầng chứng minh bằng gì

Câu hỏi "làm sao đảm bảo SAST hoạt động, DAST hoạt động" chỉ có một cách trả
lời không gian dối: với **từng tầng**, chỉ ra phép đo nào chạy, kết quả bao
nhiêu, bắt được lỗi thật nào, và ảnh nào chứng minh. Dòng nào không điền được
hết thì ghi là chưa có, không viết chữ "đạt".

### 7a. Tầng có phép đo chạy tự động

| Tầng | Công cụ | Phép đo | Kết quả | Đột biến |
|---|---|---|---|---|
| 0 · Secret | Gitleaks | `kiem_thu_secret.py` (fixture 14 tệp, 7 dạng secret + 4 mồi) | 7/7 bắt, 0 báo nhầm | **5/5** |
| 1 · Thư viện | Trivy fs | `kiem_thu_sca.py` (4 hệ sinh thái, phiên bản dính CVE biết trước) | 9/9 bắt, 0/6 mồi báo nhầm | **5/5** |
| 1b · JS nhúng | retire.js | job `retire` (jquery 1.8.1) | 7 CVE | — |
| 2 · SAST C# | Semgrep + CodeQL | Juliet C# 1.3, 6611 case, lần #47 | 62.3% bắt / 4.3% nhầm | — |
| 2 · SAST — chặn oan | Semgrep | Corpus logic nghiệp vụ, 40 hàm mã đúng | **0 chặn oan**, 7 mức chỉ báo | — |
| 3 · Bản đồ route | `gen_routes_map.py` | `kiem_thu_banto.py`, 6 endpoint đáp án gài sẵn | 6/6 phân loại đúng | **3/3** |
| 4 · Hạ tầng | Trivy config | `kiem_thu_hatang.py` (Dockerfile có lỗi + bản đã sửa) | bắt DS-0002, im trên bản sửa | **5/5** |
| 5 · DAST — lớp URL | error-based SQLite | `kiem_thu_dast_sqlite.py` | bắt `/Product/Filter`, `/Product/Search` | — |
| 5 · DAST — lớp POST | error-based qua form | `kiem_thu_dast_post.py` | 8/8 ca | **4/4** |
| 5 · DAST — runtime | rule header/cookie | `kiem_thu_runtime.py` | 5 phát hiện | **2/2** |
| 5 · DAST — IDOR | `idor.py` | `kiem_thu_idor.py` | 2 phát hiện + 4 ca rào cùng gốc | **3/3** |
| Cổng | `gate.py` | `kiem_thu_gate.py` | 10 phép kiểm | **3/3** |
| Chống lách cổng | — | `kiem_bypass.py` + `kiem_thu_bypass.py` | 16 chốt | **16/16** |
| Bước quyết định bỏ tầng | — | `kiem_thu_phamvi.py` | 10/10 ca | **3/3** |
| Canh giữ ruleset | `kiem_ruleset.py` | `kiem_thu_ruleset.py` | 19/19 ca | **4/4** |

"Đột biến" = phép đo tự phá chính thứ nó đo để chứng minh nó có đo thật. Ba
dòng còn để trống là ba phép đo phụ thuộc công cụ ngoài (retire.js, CodeQL,
Semgrep trên corpus lớn) nên chưa dựng được bước tự phá rẻ — đó là việc còn
thiếu, ghi ra chứ không lấp liếm.

### Một ca đo thiếu, lộ ra nhờ chính bước đột biến

Khi thêm đột biến cho lớp IDOR, phép thử "bỏ rào cùng gốc" **không bị bắt**.
Điều tra ra nguyên nhân: bộ kiểm chưa bao giờ kiểm hàm `_cung_goc()`. Rào đó
ngăn một cấu hình bị sửa trở thành bánh lái — công cụ mang cookie phiên **thật**
đi gọi đích của kẻ tấn công (SSRF). Đã thêm 4 ca kiểm thẳng, và đột biến đó
giờ bị bắt.

Đây đúng là lý do bước đột biến tồn tại: nó không chỉ chứng minh phép đo có
răng, nó còn chỉ ra chỗ phép đo **còn thiếu** răng.

### 7b. Vẫn chưa có bộ đo

| Chỗ | Vì sao chưa có |
|---|---|
| ZAP active scan (ngoài lớp error-based) | Chưa có corpus nào đo riêng phần ZAP gốc đóng góp; con số 3/6 ở mục 3 là của một lần chạy, không phải tỉ lệ |
| Tầng ký image / SBOM | Có workflow, chưa có phép đo nào kiểm chữ ký bị giả thì có bị phát hiện không |

---

## 7c. Một cổng báo hỏng mà không chặn — job canh giữ ruleset tự chứng minh

Lần đầu job `Canh giu ruleset` chạy đối chiếu thật trên kho ứng dụng (PR #23,
sau khi thêm `ruleset_mong_doi.json`), nó báo lệch ngay:

```
[LECH] ruleset that khong khop ruleset_mong_doi.json:
    kiem tra bat buoc bi go: security / Cong xac nhan (DAST da chung minh)
```

Đối chiếu Settings → Rules → main xác nhận: Required status checks chỉ có
`security / scan` và `security / dependency-review`. Cổng xác nhận chưa bao giờ
được thêm, dù chú thích trong `devsecops-reusable.yml` đã ghi rõ đó là điều kiện
để nó chặn được merge.

Hệ quả đo trên PR #21:

| Kiểm tra | Kết quả | Bắt buộc | Khoá merge |
|---|---|---|---|
| `security / Cong xac nhan (DAST da chung minh)` | hỏng | **không** | **không** |
| `security / scan` | đạt | có | — |
| `security / dependency-review` | đạt | có | — |
| Code scanning (CodeQL, ZAP, Semgrep ×2) | hỏng | — | **có** |

GitHub nói thẳng lý do chặn: *"CodeQL has detected 1 security relevant alert
blocking this code from being merged."*

**Đây là luận điểm trung tâm của đồ án lặp lại lần thứ hai.** Lần một: cảnh báo
đúng nhưng neo sai dòng nên không chặn (mục 3c). Lần hai: cổng chạy đúng, báo
hỏng đúng, nhưng chưa khai báo bắt buộc nên cũng không chặn. Cả hai đều là
**màu đỏ trông như đã chặn**.

### Kết quả sau khi vá

Kiểm tra đã được thêm vào Required status checks, cả hai pull request chạy lại:

| | PR #21 (gieo lỗ hổng) | **PR #23 (chỉ thêm tệp JSON)** |
|---|---|---|
| Kiểm tra hỏng | 5 | **1** |
| Kiểm tra đạt | 12 | 16 |
| Cổng quét mã nguồn | hỏng — 4 công cụ | **đạt sạch** |
| Cổng xác nhận | hỏng, nhãn `Required` | hỏng, nhãn `Required` |
| Canh giữ ruleset | **đạt** | **đạt** |
| Nút merge | vô hiệu | **vô hiệu** |

**PR #23 là phép thử cô lập.** Nó chỉ thêm một tệp cấu hình, không đụng mã
nguồn, nên cổng quét mã nguồn đạt sạch. Trong 17 kiểm tra chỉ 1 hỏng — cổng xác
nhận — và merge vẫn bị khoá. Đây là chứng minh **một mình nó chặn được**, điều
PR #21 không tách ra được vì ở đó hai cổng cùng hỏng.

### Hệ quả lộ ra ngay khi cổng có hiệu lực

Lỗ hổng mà cổng chặn trên PR #23 **không do PR đó tạo ra**: đó là SQL injection
đã nằm sẵn trên `main` tại endpoint tìm kiếm, bằng chứng khai thác `ZAP AND 1=1 --`,
vân tay `zap|89|/Product|q`.

Cổng cố ý xét mọi phát hiện động đã chứng minh, bất kể có nằm trong diff hay
không — phát hiện động không gán được vào dòng mã nào. Hệ quả: **khi `main` còn
một lỗ hổng động chưa sửa thì không PR nào merge được**, kể cả PR vô can. Đây là
fail-closed có chủ đích, không phải lỗi.

Cơ chế đi kèm: `.devsecops/baseline-confirmed.json` khai báo vân tay các phát
hiện ĐÃ BIẾT trên `main`; vân tay nào có trong đó thì bỏ qua, nên cổng chỉ còn
chặn phát hiện MỚI. Tệp được đọc từ bản checkout của chính PR, nên một PR thêm
tệp đó sẽ tự qua được cổng — không có thế kẹt.

---

## 8. Vì sao không có một con số cho cả năm tầng

Năm tầng không cùng mẫu số. Juliet đếm lỗi tiêm ở mức mã nguồn; SCA đếm phiên
bản thư viện dính CVE; DAST đếm endpoint chạy thật; Gitleaks đếm credential bị
commit; Trivy đếm cấu hình sai. Cộng phần trăm của chúng là làm số học trên những
thứ không cùng loại.

Muốn một con số cho cả năm tầng thì phải có một bộ đo mà cả năm tầng đều có cái
để tìm, kèm đáp án cho cả năm. Bộ đó không tồn tại công khai: Juliet và OWASP
Benchmark đều chỉ phủ SAST.

Nên con số **62.3% / 4.3%** là con số của **hai tầng phân tích tĩnh trên Juliet
C#** — không phải của cả pipeline, và không phải tỉ lệ trên mọi loại lỗi ngoài
thực tế.
