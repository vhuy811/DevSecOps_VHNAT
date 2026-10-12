# Corpus "logic nghiệp vụ" — mã ĐÚNG mà trông như lỗi

## Bộ đo này trả lời câu gì

Hai bộ đo hiện có (Juliet, BenchProctor) đều là mã **sinh ra để đo**: mỗi case
sạch là một case lỗi được sửa vừa đủ. Tỉ lệ báo nhầm đo trên đó nói về corpus
đó, **không nói về mã ứng dụng thật**. Hai chỗ trong đồ án đang bị chặn lại vì
thiếu đúng con số này:

1. `dso-weak-hash` và `dso-weak-random` bắt **100% với 0% báo nhầm** trên Juliet
   nhưng vẫn để mức WARNING, nên **không chặn** được A02. Lý do đã ghi trong
   `PHU_OWASP.md`: Juliet không có lần nào dùng MD5 **hợp lệ** (checksum, cache
   key, ETag), nên 0% báo nhầm ở đó *không nói gì* về mã thật. Nâng lên mà không
   có bằng chứng thì đúng vào vế "không lỗi vẫn bị chặn".
2. Mọi rule vừa mở rộng nguồn (`os.environ`, `$RS.getString`, `$X.readLine`)
   đều có một dạng dùng hợp lệ phổ biến mà corpus sinh tự động không chứa.

Corpus này là **mã nghiệp vụ thật, an toàn, nhưng có hình dạng dễ bị báo nhầm**.

## Đáp án

**0 cảnh báo ở mức có quyền chặn.** Mỗi cảnh báo mức chặn trong thư mục này là
một lần **chặn oan** — tức một lần pipeline sẽ chặn merge của mã đúng.

Cảnh báo mức WARNING được in ra nhưng không tính là sai: đó là lựa chọn có chủ
đích (báo cho người review đọc, không chặn).

## Lần đo đầu tiên — bộ đo này đã bắt được một lỗi thật ngay lần chạy đầu

Lần chạy **Phòng đo logic nghiệp vụ #7**: `dso-java-taint-path-traversal`
**chặn oan** `tepTamBaoCao()` — một hàm chỉ làm

```java
new File(System.getProperty("java.io.tmpdir"), "bao_cao_tam.csv")
```

Nguyên nhân: `$P.getProperty(...)` vừa được thêm làm nguồn taint, vì trong
Juliet Java nó là nguồn của **761 tệp** (và `System.getenv` thêm 222 tệp) — họ
nguồn ngoài-HTTP lớn nhất của corpus. Mở rộng sang nó làm tỉ lệ bắt trên Juliet
tăng mạnh.

Nhưng Juliet dùng `getProperty` vì cần một giá trị mà trình biên dịch không gấp
lại được, **không** vì nó mô hình hoá kẻ tấn công. Mã thật dùng đúng hai hàm này
để đọc **cấu hình triển khai** — giá trị do người vận hành đặt. Bằng chứng độc
lập: trong `semgrep/semgrep-rules`, **0/21** rule taint Java dùng chúng làm
nguồn; bên Python chỉ **2/59** tệp có, và cả hai đều **chỉ** đặt nguồn này cho
đích *thực thi lệnh*.

Đã bỏ nguồn cấu hình khỏi mọi rule taint trừ `*-cmdi`, ở cả ba bộ rule (C#,
Java, Python). Hệ quả phải ghi thẳng vào báo cáo: **tỉ lệ bắt trên Juliet giảm**,
và đó là con số *đúng hơn*, không phải con số tệ hơn.

Đây chính là câu mà bộ đo này được dựng để trả lời, và nó trả lời ngay lần chạy
đầu. Nếu chỉ có Juliet và BenchProctor, lần mở rộng nguồn đó sẽ được ghi vào báo
cáo như một **cải tiến**.

## Vì sao không lấy mã của VulnShop-App làm bộ đo này

VulnShop-App là ứng dụng **cố ý có lỗ hổng**, nên nó không trả lời được câu hỏi
"mã đúng có bị chặn không". Cần mã mà ta biết chắc là đúng.

## Nguyên tắc viết case

Mỗi tệp trong thư mục này phải ghi, ngay trên từng hàm:
- **việc nghiệp vụ**: hàm này làm gì trong một ứng dụng thật;
- **vì sao an toàn**: lập luận cụ thể, không phải "vì tôi nói vậy";
- **rule nào có thể báo oan**: tên rule hoặc truy vấn.

Case nào không viết được ba dòng đó thì không thuộc bộ đo này — rất dễ tự lừa
bằng cách thêm một hàm "an toàn" mà chính mình cũng không chắc.

## Giới hạn

Đây là mã **tôi viết**, không phải mã lấy từ một dự án thật đang chạy. Nó phản
ánh hiểu biết của tôi về dạng dùng hợp lệ phổ biến, và số case nhỏ (vài chục).
Nên con số từ đây đọc là **"có chặn oan hay không"**, chứ không phải một tỉ lệ
báo nhầm có mẫu số đáng tin. Bước tiếp theo đúng đắn là chạy pipeline lên một
repo mã nguồn mở thật và đếm, nhưng việc đó cần một bộ đáp án riêng.
