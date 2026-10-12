# Đo trước khi sửa — bộ rule Python trên BenchProctor 18.300 case

Tệp này ghi **sáu phép đo trên mã nguồn thật của bộ đo**, làm trước khi sửa một
dòng rule nào. Lý do làm theo thứ tự đó: lần mở rộng nguồn cho bộ rule C# đã cho
thấy đoán sai rất dễ — dự đoán 15% thực tế 11.8% — và một rule viết theo cảm
giác thì không biết nó bịt được gì.

Bộ đo: BenchProctor python quicktest, bản ghim SHA `9c5bc0f`, zip sha256
`8a80cd9e…`. 18.300 case, 9.150 có lỗi / 9.150 sạch, 61 category, 3 khung
(flask, fastapi, django). Đáp án nằm trong CSV **ngoài** mã nguồn.

Mọi con số dưới đây đếm **tệp**, không phải số lần xuất hiện.

---

## 1. Phạm vi: 8 rule của đồ án chỉ nhắm tới 1/4 bộ đo

| | case có lỗi |
|---|---|
| Thuộc 8 nhóm CWE mà rule Python nhắm tới | **2.250** (24.6%) |
| Nằm ngoài phạm vi 8 rule | 6.900 (75.4%) |

6.900 case ngoài phạm vi là 46 category khác: `authzfailure`, `hardcodedcreds`,
`debug_code_production`, `cleartextstorage`, `sessionfixation`,
`hardcoded_crypto_key`, `resourceexhaust`, `loginjection`,
`no_brute_force_limit`, `intoverflow`, `missingcritauthn`,
`cookie_no_samesite`… mỗi loại 150 case.

Đây **không phải lỗ hổng của bộ rule** mà là lựa chọn đã ghi trong
`sast-detect-python.yaml`: quyền chặn chỉ dành cho CWE mà ZAP có active scan
tương ứng, để cảnh báo tĩnh còn đi tiếp được tới nhãn CONFIRMED. Phần bề rộng để
cho rule cộng đồng `p/python` + `p/security-audit`.

**Hệ quả phải nói rõ khi dùng số này:** tỉ lệ bắt của *rule đồ án* trên
BenchProctor không thể vượt ~24.6%. Đặt con số đó cạnh "61.6% trên Juliet C#" là
so sánh sai, vì Juliet C# chỉ chứa đúng những CWE mà rule nhắm tới.

---

## 2. Nguồn: rule chỉ nhìn thấy 41.5% case

Liệt kê toàn bộ hình dạng nguồn corpus dùng, rồi đối chiếu với `pattern-sources`
đang khai:

| | case |
|---|---|
| Có ít nhất một nguồn rule đã khai | 7.587 (41.5%) |
| **Không có nguồn nào đã khai, nhưng có nguồn đang thiếu** | **6.179 (33.8%)** |
| Không khớp hình dạng nào đã liệt kê | 4.534 (24.8%) |

Các hình dạng thiếu, theo số case trong phần chưa chạm tới được:

| hình dạng | case | ghi chú |
|---|---|---|
| `request.body` | 2.032 | Django / Starlette, thân yêu cầu thô |
| `request.META.get` | 1.724 | Django đọc header qua WSGI |
| `os.environ` / `os.getenv` | 1.231 | nguồn **cục bộ**, không phải HTTP |
| `await request.body()` | 847 | Starlette / FastAPI |
| `request.get_data` | 581 | Flask, thân yêu cầu thô |
| `Query()` / `Path()` / `Header()` | 402 | tham số có kiểu của FastAPI |
| `request.COOKIES` | 377 | Django viết chữ HOA — rule chỉ có `cookies` |

Đã sửa: thêm 10 hình dạng vào cả 9 rule taint. `request.COOKIES` là ví dụ rõ
nhất cho kiểu lỗi này — rule có `$R.cookies.get(...)` nhưng Django dùng
`request.COOKIES`, chỉ khác chữ hoa chữ thường mà mất 377 case.

---

## 3. Đích: hai lỗ thật, và một lỗ do tôi đọc sai

Trong 2.250 case có lỗi thuộc phạm vi rule, tách theo nguyên nhân không bắt được:

| nhóm | case lỗi | nguồn+đích đã với tới | mở nguồn là với | **thiếu ĐÍCH** |
|---|---|---|---|---|
| CWE-94 (code/ssti) | 450 | 146 | 104 | **147** |
| CWE-78 (cmdi) | 450 | 224 | 170 | 0 |
| CWE-79 (xss) | 300 | 72 | 92 | **100** |
| CWE-89 (sqli/nosql) | 300 | 69 | 45 | **150** |
| CWE-918 (ssrf) | 300 | 93 | 72 | **72** |
| CWE-601 (redirect) | 150 | 45 | 52 | 0 |
| CWE-611 (xxe) | 150 | 52 | 59 | 0 |
| CWE-22 (pathtraver) | 150 | 55 | 41 | 42 |

Đọc từng nhóm "thiếu đích" bằng cách mở mã nguồn ra xem, không suy luận:

**CWE-89, 150 case — toàn bộ là NoSQL injection.** Đích là
`mongo_db.users.find({'$where': "this.username == '" + data + "'"})`. Bộ rule chỉ
có đích SQL (`execute`, `text`, `raw`) nên **không công cụ nào của đồ án nhìn
thấy nhóm này**. Một repo dùng MongoDB thì tầng SAST mù hoàn toàn với A03.
→ Đã thêm rule `dso-py-taint-nosqli` (CWE-943).

**CWE-94, 147 case — là SSTI, và đây là lỗi GÁN NHÃN của đồ án, không phải lỗi
phát hiện.** Đích `render_template_string(...)` đã nằm trong
`dso-py-taint-xss`, nhưng rule đó khai `metadata.cwe = CWE-79`. Bộ chấm và tầng
đối sánh đều gom theo **họ CWE**: họ của 79 là {79,80,81,…}, còn SSTI đánh số
CWE-1336 thuộc họ {94,95,96,1336}. Hai họ không giao nhau → Semgrep **có** báo
nhưng cảnh báo bị bỏ khi chấm. Đây đúng kiểu sai im lặng: tỉ lệ bắt thấp hơn
thực tế mà không có dấu hiệu gì.
→ Đã thêm rule `dso-py-taint-ssti` với `cwe: CWE-1336`.

**CWE-918, 72 case — đích là socket thô**, `socket.create_connection((data, 80))`,
không qua `requests`/`urllib`.
→ Đã thêm hai đích socket vào `dso-py-taint-ssrf`.

**CWE-22, 42 case — không phải lỗ đích.** Biểu thức tôi dùng để phân loại thiếu
`os.unlink`, trong khi rule **đã có** `os.unlink($X)`. Mở case ra xem thì nguồn
là `request.get_data(as_text=True)` — tức đây là case **thiếu nguồn**, đã tính ở
mục 2. Ghi lại vì nó là lý do phải đọc mã trước khi kết luận: xấp xỉ của người đo
cũng là một nguồn sai.

**CWE-79, 100 case — lỗ đích thật, chưa bịt.** Đích là *giá trị trả về của một
view Flask*: `return '<div>' + str(data) + '</div>'`. Không có
`HttpResponse`/`Markup`/`render_template_string` nào. Đây là dạng XSS phổ biến
nhất của Flask ngoài thực tế. Chưa thêm vì hình dạng đích này
(`return $X` bên trong một hàm có decorator route) là dạng pattern **chưa từng
dùng trong repo**, và máy phát triển không có Semgrep để thử. Để một commit
riêng, CI xác nhận.

---

## 4. Trần sau khi sửa

| | case bắt được về mặt cấu trúc | % của 2.250 |
|---|---|---|
| Trước | 756 | 33.6% |
| Sau khi mở nguồn | 1.391 | 61.8% |
| Sau khi thêm NoSQL + SSTI + socket | **1.760** | **78.2%** |

Đây là **trần cấu trúc** (nguồn khớp *và* đích khớp), không phải tỉ lệ bắt. Tỉ
lệ bắt thật sẽ thấp hơn vì taint của Semgrep CE chỉ đi trong một hàm — xem mục 6.

---

## 5. Vì sao tỉ lệ báo nhầm Python sẽ KHÔNG gần 0 như C#

Đây là phát hiện quan trọng nhất của lần đo này, và nó là giới hạn của phương
pháp chứ không phải của cách viết rule.

Bản **sạch** của BenchProctor khử độc bằng cách **kiểm rồi thoát sớm, giá trị đi
tới đích KHÔNG đổi**:

```python
data = request.headers.get('Origin', '')
if not re.fullmatch(r'[a-zA-Z0-9_.-]+', str(data)):
    return jsonify({'error': 'invalid input'}), 400
processed = data                      # <-- y nguyên
mongo_db.users.find({'$where': "this.username == '" + str(processed) + "'"})
```

`pattern-sanitizers` của Semgrep khớp một **biểu thức làm đổi giá trị**
(`int(...)`, `escape(...)`, `shlex.quote(...)`). Một câu `if` rồi `return`
không làm đổi gì cả, nên **không có cách nào khai nó là sanitizer**. Rule taint
sẽ báo cả bản sạch.

Đếm dấu hiệu "kiểm rồi thoát sớm" trên 4.500 case của 8 nhóm:

| | có dấu hiệu chặn bằng điều kiện |
|---|---|
| case **có lỗi** | 40 / 2.250 = **1.8%** |
| case **sạch** | 509 / 2.250 = **22.6%** |

Hai con số này nói hai điều:

1. **Sàn báo nhầm ≈ 22.6%** cho mọi rule taint trên bộ đo này. Juliet C# đạt
   0.0% báo nhầm được vì hàm `goodB2G` của Juliet khử độc bằng *tham số hoá
   thật* — một biến đổi giá trị mà sanitizer khớp được. BenchProctor khử độc
   bằng *validation*. Khác biệt đó, không phải chất lượng rule, là nguyên nhân.
2. **Dấu hiệu đó phân biệt được sạch/lỗi rất tốt trên bộ đo này** (22.6% so với
   1.8%). Về mặt kỹ thuật có thể thêm `pattern-not-inside` cho câu guard để bỏ
   509 case báo nhầm, mất 40 case bắt. **Chưa làm**, vì:
   - dấu hiệu tôi đếm (`return jsonify({'error'…})`, `abort(4xx)`) là **thành
     ngữ của bộ sinh BenchProctor**, không phải của mã thật;
   - bịt theo nó là khớp vào đặc điểm của bộ đo — đúng kiểu tự lừa mà cả bộ công
     cụ này được dựng để tránh. Một guard sai biến (kiểm `a` rồi dùng `b`) vẫn
     là lỗ hổng thật, và `pattern-not-inside` sẽ bỏ qua nó.

   Muốn làm đúng thì phải khai guard theo **ngữ nghĩa** (giá trị được kiểm bằng
   allowlist *rồi chính giá trị đó* tới đích), và điều đó cần taint có hỗ trợ
   guard — Semgrep CE không có.

**Vì sao vẫn để hai rule mới ở mức ERROR (có quyền chặn).** Tiêu chí của đồ án
là *hình dạng hiếm và gần như luôn là lỗi thật*, không phải tỉ lệ báo nhầm trên
corpus. `$where` cộng nối chuỗi, và `from_string` trên dữ liệu người dùng, đều
hiếm trong mã thật và gần như luôn sai. Con số 22.6% ở trên là đặc điểm của một
corpus mà **mọi case sạch đều là một case lỗi được sửa vừa đủ** — tỉ lệ đó không
suy ra được cho repo thật. Bảng tách theo rule sẽ cho biết từng rule đóng góp
bao nhiêu, và nếu một rule báo nhầm nhiều mà "bắt riêng" bằng 0 thì hạ mức.

---

## 6. Hai hạn chế của bộ đo, phải ghi khi dùng số này

**Case là single-file.** Mỗi tệp một cặp nguồn → đích, không có luồng liên tệp.
Nên bộ đo này **không đo được** phân tích liên thủ tục — đúng chỗ Semgrep CE yếu
nhất và CodeQL mạnh nhất. Nhưng corpus **có** dùng chỉ hướng trong cùng một hàm
để né: `SimpleNamespace(payload=v)` rồi `getattr(ns,'payload')`, bọc trong
`class RequestContext`, hoặc đặt đích trong một `async def` lồng bên trong. Taint
của Semgrep CE không theo được các dạng đó, nên một phần trong 78.2% ở mục 4 sẽ
không thành cảnh báo thật.

**Nhãn do máy sinh** (generator 0.13.3), không phải người review từng case.
Benchmark mới, một nhà phát triển, chưa qua peer review cộng đồng — khác Juliet
của NIST. Đã đối chiếu tay 4 cặp (CWE-89, 78, 22, 79): cả 4 đúng. 4/18.300 là
mẫu nhỏ.

---

## 7. Việc còn lại, theo thứ tự giá trị

1. **Đích XSS "giá trị trả về của view Flask"** — 100 case, lỗ đích thật duy
   nhất còn lại. Cần CI xác nhận cú pháp pattern.
2. **Nguồn `Query()` / `Path()` / `Header()` của FastAPI** — 402 case. Khai được
   bằng pattern tham số có giá trị mặc định.
3. **4.534 case không khớp hình dạng nguồn nào đã liệt kê** — chưa biết chúng
   dùng gì. Phải đọc mẫu trước khi kết luận.
4. **46 category ngoài phạm vi** — quyết định về nguyên tắc: có mở quyền chặn
   cho CWE mà ZAP không xác nhận được hay không. Cần số báo nhầm trước.
