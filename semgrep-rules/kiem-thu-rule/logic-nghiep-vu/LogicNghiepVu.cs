// =============================================================================
// CORPUS LOGIC NGHIEP VU - MA DUNG MA TRONG NHU LOI  (C#)
// =============================================================================
// Dap an: 0 canh bao o muc CO QUYEN CHAN. Moi canh bao muc chan o day la mot
// lan CHAN OAN. Xem DocQuyetDinh.md trong cung thu muc.
//
// Moi ham ghi ba dong: viec nghiep vu / vi sao an toan / rule nao co the bao oan.
// =============================================================================

using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace DoAn.LogicNghiepVu
{
    public class BangBamKhongPhaiBaoMat
    {
        // Viec nghiep vu: sinh ETag cho mot tep tinh de trinh duyet cache duoc.
        // Vi sao an toan: ETag chi de so sanh "tep co doi khong". Khong co bi mat
        //   nao duoc bao ve, va ke tan cong gia duoc ETag cung khong duoc gi -
        //   kich ban tan cong duy nhat la lam cache sai, ma noi dung van la noi
        //   dung that cua server. MD5 duoc chon vi nhanh va ngan.
        // Rule co the bao oan: dso-weak-hash (CWE-328), cs/weak-crypto-algorithm.
        public static string SinhETag(byte[] noiDungTep)
        {
            using var md5 = MD5.Create();
            return Convert.ToHexString(md5.ComputeHash(noiDungTep));
        }

        // Viec nghiep vu: khoa cache cho ket qua truy van, gom tu cac tham so.
        // Vi sao an toan: dau ra chi dung lam KHOA trong Redis. Khong xac thuc,
        //   khong chu ky, khong mat khau. Va cham khoa chi gay tra sai cache cho
        //   chinh nguoi do - khong vuot quyen ai.
        // Rule co the bao oan: dso-weak-hash (CWE-328).
        public static string KhoaCache(string maNguoiDung, string boLoc, int trang)
        {
            var thanh = $"{maNguoiDung}|{boLoc}|{trang}";
            using var sha1 = SHA1.Create();
            return "tim:" + Convert.ToHexString(sha1.ComputeHash(Encoding.UTF8.GetBytes(thanh)));
        }

        // Viec nghiep vu: phat hien tep tai len trung de khong luu hai ban.
        // Vi sao an toan: chi de so sanh hai tep cua CUNG mot nguoi dung. Neu ai
        //   co tinh tao va cham MD5 thi ho chi lam chinh tep cua ho bi coi la
        //   trung - khong doc duoc tep nguoi khac vi khoa co ca maNguoiDung.
        // Rule co the bao oan: dso-weak-hash (CWE-328).
        public static string DauVetTrungLap(string maNguoiDung, Stream tep)
        {
            using var md5 = MD5.Create();
            return maNguoiDung + ":" + Convert.ToHexString(md5.ComputeHash(tep));
        }
    }

    public class NgauNhienKhongPhaiBaoMat
    {
        private static readonly Random _nn = new Random();

        // Viec nghiep vu: cho ngau nhien truoc khi thu lai, de nhieu client khong
        //   cung luc dap vao server (exponential backoff + jitter).
        // Vi sao an toan: doan ra duoc do tre thu lai khong giup ke tan cong lam
        //   gi. Dung RandomNumberGenerator o day chi lam cham hon ma khong them
        //   bao mat nao.
        // Rule co the bao oan: dso-weak-random (CWE-338), cs/weak-prng... (chi khi
        //   truy van coi moi Random la yeu bat ke muc dich).
        public static TimeSpan DoTreThuLai(int lanThu)
        {
            var goc = Math.Min(1000 * Math.Pow(2, lanThu), 30000);
            return TimeSpan.FromMilliseconds(goc + _nn.Next(0, 250));
        }

        // Viec nghiep vu: lay mau 1% luu luong de ghi log chi tiet.
        // Vi sao an toan: quyet dinh lay mau khong bao ve gi ca. Ke tan cong doan
        //   duoc minh co bi ghi log hay khong cung khong vuot duoc quyen nao.
        // Rule co the bao oan: dso-weak-random (CWE-338).
        public static bool CoGhiLogChiTiet() => _nn.Next(0, 100) == 0;

        // Viec nghiep vu: xao tron danh sach san pham goi y cho trang chu.
        // Vi sao an toan: thu tu hien thi khong phai bi mat. Day la trang tri UI.
        // Rule co the bao oan: dso-weak-random (CWE-338).
        public static List<T> XaoTronGoiY<T>(List<T> ds)
            => ds.OrderBy(_ => _nn.Next()).ToList();
    }

    public class TruyVanDongNhungAnToan
    {
        // Thu tu sap xep hop le - DANH SACH CO DINH trong ma nguon, khong phai
        // dau vao. Day la cho quyet dinh tinh an toan cua ham duoi.
        private static readonly Dictionary<string, string> _cotChoPhep = new()
        {
            ["gia"] = "Gia",
            ["ten"] = "Ten",
            ["moi"] = "NgayTao",
        };

        // Viec nghiep vu: danh sach san pham cho phep nguoi dung chon cot sap xep.
        // Vi sao an toan: ORDER BY khong the tham so hoa trong SQL, nen phai ghep
        //   chuoi. Nhung gia tri ghep vao KHONG den tu nguoi dung: no den tu
        //   _cotChoPhep, mot tu dien hang so trong ma nguon. Dau vao chi duoc
        //   dung lam KHOA tra cuu; khoa khong co trong tu dien thi roi vao gia tri
        //   mac dinh. Dieu kien WHERE thi tham so hoa binh thuong.
        // Rule co the bao oan: dso-taint-sqli / cs/sql-injection - hinh dang la
        //   "chuoi do nguoi dung anh huong noi vao cau lenh SQL".
        public static SqlCommand DanhSachSanPham(SqlConnection conn, string sapXepTheo,
                                                 string tuKhoa)
        {
            var cot = _cotChoPhep.TryGetValue(sapXepTheo ?? "", out var c) ? c : "NgayTao";
            var sql = $"SELECT Id, Ten, Gia FROM SanPham WHERE Ten LIKE @tk ORDER BY {cot} DESC";
            var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@tk", "%" + tuKhoa + "%");
            return cmd;
        }

        // Viec nghiep vu: lay nhieu san pham theo danh sach Id (menh de IN).
        // Vi sao an toan: SQL khong co cach tham so hoa mot danh sach do dai thay
        //   doi, nen phai sinh dung so dau @p0,@p1,... Chuoi ghep vao cau lenh chi
        //   gom TEN THAM SO do ma nguon sinh ra; GIA TRI di qua Parameters. Them
        //   nua moi Id da qua int.Parse nen khong con la chuoi.
        // Rule co the bao oan: dso-taint-sqli / cs/sql-injection - co noi chuoi
        //   vao cau lenh, va $"...{bien}..." la hinh dang bi nham nhieu nhat.
        public static SqlCommand LaySanPhamTheoId(SqlConnection conn, IEnumerable<string> ids)
        {
            var so = ids.Select(int.Parse).ToArray();
            var ten = so.Select((_, i) => "@p" + i).ToArray();
            var cmd = new SqlCommand(
                $"SELECT Id, Ten FROM SanPham WHERE Id IN ({string.Join(",", ten)})", conn);
            for (var i = 0; i < so.Length; i++)
            {
                cmd.Parameters.AddWithValue(ten[i], so[i]);
            }
            return cmd;
        }
    }

    public class DuongDanAnToan
    {
        private const string GocTaiLen = @"C:\du_lieu\tai_len";

        // Viec nghiep vu: tra ve tep nguoi dung da tai len truoc do.
        // Vi sao an toan: hai lop. Mot, Path.GetFileName cat bo moi thanh phan
        //   thu muc nen "../../etc/passwd" thanh "passwd". Hai, sau khi ghep con
        //   kiem lai duong dan tuyet doi co thuc su nam duoi GocTaiLen - lop nay
        //   chan ca truong hop symlink hay ten tep la tra ve duong dan ngoai.
        // Rule co the bao oan: dso-taint-path-traversal / cs/path-injection.
        public static Stream MoTepDaTaiLen(string tenTepNguoiDungGui)
        {
            var ten = Path.GetFileName(tenTepNguoiDungGui);
            var dayDu = Path.GetFullPath(Path.Combine(GocTaiLen, ten));
            if (!dayDu.StartsWith(GocTaiLen + Path.DirectorySeparatorChar,
                                  StringComparison.Ordinal))
            {
                throw new UnauthorizedAccessException("duong dan ngoai thu muc tai len");
            }
            return File.OpenRead(dayDu);
        }
    }

    public class ChayLenhAnToan
    {
        // Viec nghiep vu: tao anh thu nho bang ImageMagick cho anh san pham.
        // Vi sao an toan: khong co shell. Doi so di qua ArgumentList nen moi phan
        //   tu la MOT doi so, dau cham phay hay dau ong dan trong ten tep chi la
        //   ky tu binh thuong. Ten tep con qua GetFileName truoc do.
        // Rule co the bao oan: dso-taint-cmdi / cs/command-line-injection.
        public static System.Diagnostics.ProcessStartInfo TaoAnhThuNho(string tenTep)
        {
            var ten = Path.GetFileName(tenTep);
            var psi = new System.Diagnostics.ProcessStartInfo("magick")
            {
                UseShellExecute = false,
            };
            psi.ArgumentList.Add(Path.Combine(@"C:\du_lieu\anh", ten));
            psi.ArgumentList.Add("-resize");
            psi.ArgumentList.Add("200x200");
            psi.ArgumentList.Add(Path.Combine(@"C:\du_lieu\thu_nho", ten));
            return psi;
        }
    }

    public class HttpVaHangSoTrongNhuBiMat
    {
        // Viec nghiep vu: goi endpoint kiem tra song cua chinh tien trinh nay.
        // Vi sao an toan: dia chi la vong lap noi bo (127.0.0.1). Luu luong khong
        //   ra khoi may nen khong co duong nao de nghe trom; bat TLS cho localhost
        //   chi them chung chi tu ky phai quan ly.
        // Rule co the bao oan: dso-cleartext-http (CWE-319).
        public static Task<HttpResponseMessage> KiemTraSong(HttpClient http)
            => http.GetAsync("http://127.0.0.1:8080/healthz");

        // Viec nghiep vu: ten tham so cau hinh de doc chuoi ket noi tu moi truong.
        // Vi sao an toan: day la TEN KHOA, khong phai gia tri. Gia tri that nam
        //   trong bien moi truong luc chay. Mot chuoi chua chu "Password" khong
        //   co nghia la mat khau bi viet cung.
        // Rule co the bao oan: dso-hardcoded-password (CWE-259/798).
        public const string KhoaCauHinhMatKhau = "ConnectionStrings:Password";

        // Viec nghiep vu: tien to cua ma don hang de nhan biet moi truong.
        // Vi sao an toan: hang so cong khai, in tren hoa don.
        // Rule co the bao oan: cac rule bi mat viet cung, do do dai va hinh dang
        //   giong mot token.
        public const string TienToMaDonHang = "VNSHOP-PROD-2026";
    }

    public class XmlVaChuyenHuongAnToan
    {
        // Viec nghiep vu: doc tep XML mo ta gia do doi tac tai len.
        // Vi sao an toan: DtdProcessing.Prohibit tat hoan toan DTD nen khong khai
        //   bao duoc thuc the ngoai; XmlResolver = null cat duong mang.
        // Rule co the bao oan: cac rule XXE - vi hinh dang "doc XML tu dau vao".
        public static XmlReader DocBangGiaDoiTac(Stream xml)
        {
            var ch = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            return XmlReader.Create(xml, ch);
        }

        private static readonly HashSet<string> _duongChoPhep = new()
        {
            "/gio-hang", "/don-hang", "/tai-khoan",
        };

        // Viec nghiep vu: sau khi dang nhap, tra nguoi dung ve trang truoc do.
        // Vi sao an toan: gia tri tra ve lay tu _duongChoPhep - danh sach hang so
        //   trong ma nguon. Dau vao chi dung de TRA CUU; khong khop thi ve "/".
        //   Nen khong co cach nao dieu huong ra mien ngoai.
        // Rule co the bao oan: dso-open-redirect (CWE-601), cs/web/unvalidated-url-redirection.
        public static string DuongVeSauDangNhap(string duongNguoiDungGui)
            => _duongChoPhep.Contains(duongNguoiDungGui ?? "") ? duongNguoiDungGui : "/";
    }

    public class PhanQuyenTrongNhuBypass
    {
        // Viec nghiep vu: cho phep nhan vien xem don hang cua nguoi khac.
        // Vi sao an toan: nhin qua giong "bo qua kiem tra chu so huu", nhung dieu
        //   kien dau tien la mot kiem tra VAI TRO that tu phien dang nhap da xac
        //   thuc, khong phai tu tham so nguoi dung gui. Nguoi khong co vai tro do
        //   van phai la chu so huu.
        // Rule co the bao oan: cac rule/truy van kiem soat truy cap, va DAST-idor
        //   neu lop kiem do chi so sanh ma don hang voi nguoi dang nhap.
        public static bool DuocXemDonHang(string vaiTroTuPhien, string maChuDon,
                                          string maNguoiDangNhap)
        {
            if (vaiTroTuPhien == "NhanVienHoTro" || vaiTroTuPhien == "QuanTri")
            {
                return true;
            }
            return maChuDon == maNguoiDangNhap;
        }
    }

    public class TangTruyCapDuLieu
    {
        // Viec nghiep vu: tim san pham theo danh muc va tu khoa, dung dan cau SQL
        //   theo nhung bo loc ma nguoi dung thuc su chon.
        // Vi sao an toan: moi thu duoc noi vao chuoi SQL deu la HANG CHUOI do lap
        //   trinh vien viet; hai gia tri cua nguoi dung di qua AddWithValue nen
        //   chung di vao CSDL duoi dang tham so, khong phai duoi dang cau lenh.
        //   Day la ban sao ham Db.GetProducts dang chay that tren nhanh main cua
        //   VulnShop-App, dua vao day lam moc: neu mot ban sua rule nao do lam
        //   ham nay bi bao o muc chan, nghia la rule do se chan merge cua chinh
        //   tang truy cap du lieu viet dung chuan.
        // Rule co the bao oan: dso-sqli-tham-so-ham-noi-chuoi,
        //   dso-sqli-commandtext-concat, dso-sqli-query-string-concat,
        //   csharp.lang.security.sqli.csharp-sqli.
        public static List<string> TimSanPham(string danhMuc, string tuKhoa)
        {
            var ketQua = new List<string>();
            using var conn = new SqlConnection("Server=.;Database=cuahang;");
            conn.Open();
            var cmd = conn.CreateCommand();
            var sql = "SELECT Id, Ten FROM SanPham WHERE 1=1";
            if (!string.IsNullOrWhiteSpace(danhMuc))
            {
                sql += " AND DanhMuc = @danhMuc";
                cmd.Parameters.AddWithValue("@danhMuc", danhMuc);
            }
            if (!string.IsNullOrWhiteSpace(tuKhoa))
            {
                sql += " AND Ten LIKE @tuKhoa";
                cmd.Parameters.AddWithValue("@tuKhoa", "%" + tuKhoa + "%");
            }
            sql += " ORDER BY Id";
            cmd.CommandText = sql;
            using var rd = cmd.ExecuteReader();
            while (rd.Read()) ketQua.Add(rd.GetString(1));
            return ketQua;
        }

        // Viec nghiep vu: dem don hang theo trang thai, ten cot sap xep do CHINH
        //   chuong trinh chon tu mot danh sach trang, khong phai do nguoi dung go.
        // Vi sao an toan: tham so cua ham khong bao gio di vao cau SQL - no chi
        //   duoc dung de TRA BANG, va thu di vao SQL la gia tri lay tu bang do.
        //   Day la cach duy nhat dung de "sap xep theo cot nguoi dung chon".
        // Rule co the bao oan: dso-sqli-tham-so-ham-noi-chuoi (tham so chuoi cua
        //   ham co mat trong cung ham voi mot sink SQL).
        public static int DemDonHang(string cotSapXep)
        {
            var cotHopLe = new Dictionary<string, string>
            {
                ["ngay"] = "NgayTao",
                ["tien"] = "TongTien",
                ["ma"]   = "Id",
            };
            if (!cotHopLe.TryGetValue(cotSapXep, out var cot)) cot = "Id";
            using var conn = new SqlConnection("Server=.;Database=cuahang;");
            conn.Open();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM DonHang ORDER BY " + cot;
            return (int)cmd.ExecuteScalar();
        }
    }

}
