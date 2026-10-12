// =============================================================================
// FIXTURE KIEM THU RULE - KHONG DUOC BI BAT
// =============================================================================
//
// Doi trong cua Co_Loi.cs. Moi phuong thuc o day lam DUNG mot viec ma
// Co_Loi.cs lam sai. Hai dieu kien phai dung cung luc:
//
//   1. KHONG rule phat hien nao duoc bat o tep nay.  <- kiem tra duong tinh gia
//   2. Rule sanitizer PHAI bat duoc bang chung khu doc. <- kiem tra nhan FILTERED
//
// Dieu kien 2 quan trong khong kem dieu kien 1. Khong co bang chung sanitizer
// thi khong canh bao nao duoc phep mang nhan FILTERED, va moi thu don het vao
// UNCONFIRMED - co che ba nhan sup con mot nhan.
// =============================================================================

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Security.Application;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace KiemThuRule
{
    public class DaKhuDocController : Controller
    {
        // ------------------------------------------------------------------
        // CWE-89 : tham so hoa
        // sanitizer: dso-sanitizer-sql-parameterized
        // ------------------------------------------------------------------
        public void Sql_ThamSoHoa(SqlCommand cmd, string ten)
        {
            cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = @ten";
            cmd.Parameters.AddWithValue("@ten", ten);
            cmd.ExecuteNonQuery();
        }

        // sanitizer: dso-sanitizer-sql-ef-interpolated
        public void Sql_EfInterpolated(AppDbContext ctx, string ten)
        {
            ctx.Database.ExecuteSqlInterpolated($"DELETE FROM SanPham WHERE Ten = {ten}");
        }

        // sanitizer: dso-sanitizer-sql-dapper-params
        public void Sql_DapperThamSo(SqlConnection conn, int id)
        {
            conn.Execute("UPDATE DonHang SET TrangThai = 1 WHERE Id = @id", new { id });
        }

        // ------------------------------------------------------------------
        // CWE-79 : ma hoa HTML
        // sanitizer: dso-sanitizer-html-encode
        // ------------------------------------------------------------------
        public string Xss_MaHoa(string tuKhoa)
        {
            var daMaHoa = WebUtility.HtmlEncode(tuKhoa);
            return daMaHoa;
        }

        // ------------------------------------------------------------------
        // CWE-78 : tach doi so
        // sanitizer: dso-sanitizer-cmd-argumentlist
        // ------------------------------------------------------------------
        public void Cmd_ArgumentList(string tenTep)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/usr/bin/convert";
            psi.ArgumentList.Add("-resize");
            psi.ArgumentList.Add("100x100");
            psi.ArgumentList.Add(tenTep);
            Process.Start(psi);
        }

        // ------------------------------------------------------------------
        // CWE-22 : cat bo thanh phan thu muc
        // sanitizer: dso-sanitizer-path-getfilename
        // ------------------------------------------------------------------
        public string Path_ChiTenTep(string tenTep)
        {
            var an = Path.GetFileName(tenTep);
            var day = Path.Combine("/var/data", an);
            return File.ReadAllText(day);
        }

        // CWE-22 (taint): File.Exists roi doc - nhung chi doc ten tep da cat bo thu muc
        public string Path_KiemTraRoiDoc(string tenTep)
        {
            var an = Path.GetFileName(tenTep);
            var duongDan = Path.Combine("/var/data", an);
            if (File.Exists(duongDan))
            {
                using var sr = new StreamReader(duongDan);
                return sr.ReadToEnd();
            }
            return "";
        }

        // ------------------------------------------------------------------
        // CWE-470 : chi khoi tao kieu nam trong danh sach biet truoc
        // ------------------------------------------------------------------
        public object Reflection_DanhSachTrang(string tenLop)
        {
            Type kieu = typeof(object);
            if (tenLop == "chuoi")
            {
                kieu = typeof(StringBuilder);
            }
            return Activator.CreateInstance(kieu);
        }

        // ------------------------------------------------------------------
        // CWE-259 / CWE-321 : bi mat lay tu cau hinh, khong viet cung
        // ------------------------------------------------------------------
        public NetworkCredential MatKhau_TuCauHinh(IConfiguration cfg)
        {
            var matKhau = cfg["Smtp:MatKhau"];
            return new NetworkCredential("user", matKhau, "domain");
        }

        public byte[] Khoa_TuBienMoiTruong(byte[] duLieu)
        {
            var khoa = Convert.FromBase64String(Environment.GetEnvironmentVariable("KHOA_MA_HOA"));
            using var aes = Aes.Create();
            var enc = aes.CreateEncryptor(khoa, aes.IV);
            return enc.TransformFinalBlock(duLieu, 0, duLieu.Length);
        }

        // ------------------------------------------------------------------
        // CWE-328 / CWE-338 : thuat toan manh
        // ------------------------------------------------------------------
        public byte[] Bam_Sha256(byte[] duLieu)
        {
            return SHA256.HashData(duLieu);
        }

        public int NgauNhien_AnToan()
        {
            return RandomNumberGenerator.GetInt32(1000000);
        }

        // ------------------------------------------------------------------
        // CWE-611 : dong DTD
        // sanitizer: dso-sanitizer-xxe-dtd-off
        // ------------------------------------------------------------------
        public void Xml_DongDtd()
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
        }

        // ------------------------------------------------------------------
        // CWE-601 : chi cho dia chi noi bo
        // sanitizer: dso-sanitizer-local-redirect
        // ------------------------------------------------------------------
        public IActionResult Redirect_NoiBo(string returnUrl)
        {
            return LocalRedirect(returnUrl);
        }

        // ------------------------------------------------------------------
        // CWE-91 : ma hoa noi dung XML
        // sanitizer: dso-sanitizer-xml-escape
        // ------------------------------------------------------------------
        public void Xml_MaHoa(XmlWriter writer, string ten)
        {
            var an = SecurityElement.Escape(ten);
            writer.WriteElementString("Ten", an);
        }

        // ------------------------------------------------------------------
        // G3.5 - NGUON NGOAI HTTP: doi trong an toan
        // ------------------------------------------------------------------
        // Cung nguon voi cac case G3.5 trong Co_Loi.cs (StreamReader, bien moi
        // truong, CSDL, tep, mang), nhung sink da duoc khu doc. Day la nua
        // "khong loi" cua tieu chi: mo rong nguon KHONG duoc keo theo bao nham.

        // nguon: StreamReader.ReadLine() -> SQL tham so hoa
        public void NguonDocDong_SqlThamSoHoa()
        {
            using var sr = new StreamReader("ten-nguoi-dung.txt");
            string ten = sr.ReadLine();
            using var cmd = new SqlCommand("select * from users where name = @ten");
            cmd.Parameters.AddWithValue("@ten", ten);
            cmd.ExecuteNonQuery();
        }

        // nguon: bien moi truong -> cat bo thanh phan thu muc
        // NGUON CAU HINH VAO DICH DUONG DAN - KHONG SANITIZER, VA PHAI KHONG BI BAT.
        //
        // Gia tri tu bien moi truong di THANG vao File.ReadAllText. Khong co
        // buoc lam sach nao, va dung nhu vay moi la y cua case: theo mo hinh de
        // doa cua du an, cau hinh trien khai khong phai du lieu ke tan cong dieu
        // khien.
        //
        // Truoc day day la case "chi lay ten tep" dung de kiem sanitizer
        // Path.GetFileName. Sanitizer do van duoc kiem boi Path_ChiTenTep() o
        // tren, voi nguon HTTP.
        //
        // Ham nay la PHEP KIEM CHAP HANH: them lai Environment.GetEnvironmentVariable
        // vao nguon cua rule duong dan thi dieu kien 2 do ngay o dong nay.
        //
        // KHONG duoc noi chuoi o day. Ban dau toi viet
        //     File.ReadAllText("/var/bao-cao/" + duong)
        // va vong CI #35 do: dso-pathtraversal-file-api-concat bat ngay. Rule do
        // khop HINH DANG (`<... $A + $B ...>` trong loi goi File API), khong lien
        // quan nguon taint, nen no bat du nguon la gi - dung nhu chu thich cua no
        // noi: tren Juliet no bat 100% case loi va bao nham 100% case an toan,
        // nen quyen chan da chuyen cho dso-taint-path-traversal tu G2.3.
        // Truyen bien tran de case nay do dung MOT thu: nguon cau hinh co con
        // chay vao dich duong dan cua rule TAINT hay khong.
        public string NguonBienMoiTruong_VaoDuongDan_KhongChan()
        {
            var duong = Environment.GetEnvironmentVariable("BAO_CAO");
            return File.ReadAllText(duong);
        }

        // nguon: CSDL -> tach doi so, khong ghep vao dong lenh
        public void NguonCsdl_TachDoiSo()
        {
            using var conn = new SqlConnection("Server=.;Database=kho;Encrypt=True");
            using var cmd = new SqlCommand("select ten_tep from tai_lieu", conn);
            using SqlDataReader rd = cmd.ExecuteReader();
            while (rd.Read())
            {
                var psi = new ProcessStartInfo();
                psi.FileName = "/usr/bin/convert";
                psi.ArgumentList.Add(rd.GetString(0));
                Process.Start(psi);
            }
        }

        // nguon: tep -> ma hoa URL truoc khi dat vao cookie
        public void NguonTep_CookieMaHoa()
        {
            string ngonNgu = File.ReadAllText("ngon-ngu-mac-dinh.txt");
            Response.Headers["Content-Language"] = WebUtility.UrlEncode(ngonNgu);
        }

        // nguon: mang -> ma hoa HTML truoc khi dat vao StatusDescription
        public void NguonMang_StatusDescriptionMaHoa()
        {
            var wc = new WebClient();
            string thongBao = wc.DownloadString("https://noi-bo/thong-bao");
            Response.StatusCode = 404;
            Response.StatusDescription = WebUtility.HtmlEncode(thongBao);
        }

        // nguon: StreamReader.ReadToEnd() -> chi khoi tao kieu trong danh sach trang
        public object NguonDocHet_DanhSachTrang()
        {
            using var sr = new StreamReader("bo-xu-ly.cfg");
            string tenLop = sr.ReadToEnd().Trim();
            Type kieu = typeof(object);
            if (tenLop == "chuoi")
            {
                kieu = typeof(StringBuilder);
            }
            return Activator.CreateInstance(kieu);
        }

        // nguon: Console.ReadLine() -> ma hoa bo loc LDAP
        public void NguonConsole_LdapMaHoa()
        {
            string ten = Console.ReadLine();
            var search = new DirectorySearcher();
            search.Filter = "(&(objectClass=user)(cn=" + Encoder.LdapFilterEncode(ten) + "))";
            search.FindOne();
        }

        // nguon: CSDL -> ma hoa noi dung XML truoc khi ghep vao XPath
        public XmlNode NguonCsdlGiaTri_XPathMaHoa()
        {
            using var conn = new SqlConnection("Server=.;Database=kho;Encrypt=True");
            using var cmd = new SqlCommand("select ma from bo_loc", conn);
            using SqlDataReader rd = cmd.ExecuteReader();
            rd.Read();
            string ma = (string)rd.GetValue(0);
            var doc = new XmlDocument();
            doc.Load("danh-muc.xml");
            // Ma hoa NGAY TAI CHO dung, khong phai o mot dong truoc do: rule hinh
            // dang dso-xpathi-select-concat chi doc duoc pham vi no khop, nen loi
            // goi ma hoa phai nam trong chinh bieu thuc XPath moi duoc tinh.
            return doc.SelectSingleNode("//muc[ma='" + SecurityElement.Escape(ma) + "']");
        }

        // ------------------------------------------------------------------
        // CWE-89 : cung hinh dang, nhung noi HANG CHUOI - khong duoc bat
        // ------------------------------------------------------------------
        // Doi trong cua TangDuLieu_NoiThamSoVaoSql. Day la ban sao gan nhu
        // nguyen van ham Db.GetProducts tren nhanh main cua VulnShop-App - tuc
        // la MA THAT DANG CHAY, khong phai vi du dung ra cho dep.
        //
        // No cung dung += bon lan de dung dan cau SQL, cung nhan hai tham so
        // chuoi tu ham goi. Khac biet duy nhat: moi thu duoc += vao deu la hang
        // chuoi, con hai gia tri nguoi dung di qua AddWithValue. Mot rule khop
        // theo HINH DANG ("co += vao bien SQL") se chan oan ngay ham nay; rule
        // theo luong du lieu thi im lang, vi chuoi khong bao gio nhiem.
        //
        // Case nay o day de neu ai do sau nay noi long rule cho "bat duoc nhieu
        // hon", dieu kien 2 cua bo kiem se do ngay.
        public void TangDuLieu_NoiHangChuoi_ThamSoHoa(string danhMuc, string tuKhoa)
        {
            using var conn = new SqlConnection("Server=.;Database=cuahang;");
            conn.Open();
            var cmd = conn.CreateCommand();
            var sql = "SELECT Id, Ten, DanhMuc, Gia FROM SanPham WHERE 1=1";
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
            cmd.ExecuteReader();
        }

        // ------------------------------------------------------------------
        // CWE-319 : bat ma hoa duong truyen
        // ------------------------------------------------------------------
        public void KetNoiCsdl_BatMaHoa()
        {
            using var conn = new SqlConnection(
                "Server=db.noi-bo;Database=donhang;Encrypt=True;TrustServerCertificate=False");
            conn.Open();
        }

        public void TruyenTai_GiaoThucHienDai()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }
    }
}
