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
using System.IO;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
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
            writer.WriteElementString("Ten", ten);
        }
    }
}
