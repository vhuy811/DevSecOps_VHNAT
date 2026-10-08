// =============================================================================
// FIXTURE KIEM THU RULE - PHAI BI BAT
// =============================================================================
//
// KHONG PHAI MA NGUON UNG DUNG. Day la du lieu kiem thu cho bo rule Semgrep.
// Moi phuong thuc trong tep nay chua dung MOT dang lo hong, va rule tuong ung
// PHAI bat duoc no. Neu mot rule khong bat duoc case cua no, rule do hong -
// chu khong phai ma nguon nay an toan.
//
// Tep nay bi loai tru khoi ca ba cho quet (hook pre-commit, CI, dashboard).
// Neu ban thay canh bao tu tep nay trong bao cao cua mot du an that, nghia la
// mot trong ba cau hinh loai tru bi sai.
//
// Chay kiem thu: python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
// =============================================================================

using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Xsl;
using Microsoft.AspNetCore.Mvc;

namespace KiemThuRule
{
    public class CoLoiController : Controller
    {
        private readonly HttpClient _http = new HttpClient();
        private readonly WebClient _wc = new WebClient();

        // ------------------------------------------------------------------
        // CWE-89 : SQL Injection
        // ------------------------------------------------------------------

        // rule: dso-sqli-commandtext-concat, dso-taint-sqli
        public void Sqli_CommandTextConcat(SqlCommand cmd, string ten)
        {
            cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = '" + ten + "'";
        }

        // rule: dso-sqli-commandtext-interpolated
        public void Sqli_CommandTextInterpolated(SqlCommand cmd, string ten)
        {
            cmd.CommandText = $"SELECT * FROM SanPham WHERE Ten = '{ten}'";
        }

        // rule: dso-sqli-query-string-concat
        public void Sqli_BienTrungGian(string ten)
        {
            var sqlLenh = "SELECT * FROM SanPham WHERE Ten = '" + ten + "'";
            Console.WriteLine(sqlLenh);
        }

        // rule: dso-sqli-sqlcommand-ctor-concat
        public void Sqli_HamDung(SqlConnection conn, string id)
        {
            var cmd = new SqlCommand("SELECT * FROM DonHang WHERE Id = " + id, conn);
            cmd.ExecuteNonQuery();
        }

        // rule: dso-sqli-efcore-raw
        public void Sqli_EfCoreRaw(AppDbContext ctx, string ten)
        {
            ctx.Database.ExecuteSqlRaw("DELETE FROM SanPham WHERE Ten = '" + ten + "'");
        }

        // rule: dso-sqli-dapper-concat
        public void Sqli_Dapper(SqlConnection conn, string id)
        {
            conn.Execute("UPDATE DonHang SET TrangThai = 1 WHERE Id = " + id);
        }

        // rule: dso-sqli-commandtext-concat (dang += cua Juliet "CommandText")
        public void Sqli_CommandTextCongDon(SqlCommand cmd, string[] ten)
        {
            foreach (var t in ten)
            {
                cmd.CommandText += "UPDATE SanPham SET Xem = Xem + 1 WHERE Ten = '" + t + "';";
            }
        }

        // ------------------------------------------------------------------
        // CWE-79 : Cross-Site Scripting
        // ------------------------------------------------------------------

        // rule: dso-xss-html-string-concat
        public void Xss_BienHtml(string tuKhoa)
        {
            var htmlKetQua = "<p>Ban vua tim: " + tuKhoa + "</p>";
            Console.WriteLine(htmlKetQua);
        }

        // rule: dso-xss-response-write
        public void Xss_ResponseWrite(string tuKhoa)
        {
            Response.Write("<div>" + tuKhoa + "</div>");
        }

        // rule: dso-xss-htmlstring-ctor
        public object Xss_HtmlString(string binhLuan)
        {
            return new HtmlString("<span>" + binhLuan + "</span>");
        }

        // rule: dso-xss-content-result-html
        public IActionResult Xss_ContentResult(string ten)
        {
            return Content("<h1>Xin chao " + ten + "</h1>", "text/html");
        }

        // ------------------------------------------------------------------
        // CWE-78 : OS Command Injection
        // ------------------------------------------------------------------

        // rule: dso-cmdi-process-start-concat, dso-taint-cmdi
        public void Cmdi_ProcessStart(string tenTep)
        {
            Process.Start("convert " + tenTep + " out.png");
        }

        // rule: dso-cmdi-processstartinfo-arguments
        public void Cmdi_Arguments(string tenTep)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/usr/bin/convert";
            psi.Arguments = "-resize 100x100 " + tenTep;
            Process.Start(psi);
        }

        // rule: dso-cmdi-shell-execute
        public void Cmdi_QuaShell(string thamSo)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/bin/sh";
            Process.Start(psi);
        }

        // ------------------------------------------------------------------
        // CWE-22 : Path Traversal
        // ------------------------------------------------------------------

        // rule: dso-pathtraversal-file-api-concat
        public string PathTraversal_ReadAllText(string tenTep)
        {
            return File.ReadAllText("/var/data/" + tenTep);
        }

        // rule: dso-pathtraversal-physicalfile
        public IActionResult PathTraversal_PhysicalFile(string tenTep)
        {
            return PhysicalFile("/var/data/" + tenTep, "application/octet-stream");
        }

        // rule: dso-pathtraversal-path-combine-request
        public string PathTraversal_PathCombine()
        {
            var duongDan = Path.Combine("/var/data", Request.Query["ten"]);
            return duongDan;
        }

        // ------------------------------------------------------------------
        // CWE-643 : XPath Injection
        // ------------------------------------------------------------------

        // rule: dso-xpathi-select-concat, dso-taint-xpathi
        public XmlNode XPathi_SelectSingleNode(XmlDocument doc, string ten)
        {
            return doc.SelectSingleNode("//NguoiDung[@ten='" + ten + "']");
        }

        // ------------------------------------------------------------------
        // CWE-611 : XXE
        // ------------------------------------------------------------------

        // rule: dso-xxe-dtd-processing-parse
        public void Xxe_ChoPhepDtd()
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
        }

        // rule: dso-xxe-xmlresolver-enabled
        public void Xxe_XmlResolver()
        {
            var settings = new XmlReaderSettings();
            settings.XmlResolver = new XmlUrlResolver();
        }

        // rule: dso-xxe-xmltextreader-default
        public void Xxe_XmlTextReader(string duongDan)
        {
            var reader = new XmlTextReader(duongDan);
            reader.Read();
        }

        // ------------------------------------------------------------------
        // CWE-918 : SSRF
        // ------------------------------------------------------------------

        // rule: dso-ssrf-http-client-concat
        public void Ssrf_HttpClient(string may)
        {
            _http.GetStringAsync("http://" + may + "/api/trangthai");
        }

        // rule: dso-ssrf-webrequest-concat
        public void Ssrf_WebClient(string may)
        {
            _wc.DownloadString("http://" + may + "/api/trangthai");
        }

        // ------------------------------------------------------------------
        // CWE-601 : Open Redirect
        // ------------------------------------------------------------------

        // rule: dso-openredirect-from-request
        public IActionResult OpenRedirect_TuRequest()
        {
            return Redirect(Request.Query["dich"]);
        }

        // rule: dso-openredirect-parameter
        public IActionResult OpenRedirect_ThamSo(string returnUrl)
        {
            return Redirect(returnUrl);
        }

        // ------------------------------------------------------------------
        // CWE-90 : LDAP Injection
        // ------------------------------------------------------------------

        // rule: dso-ldapi-filter-concat, dso-taint-ldapi
        public void Ldapi_Filter(DirectorySearcher s, string ten)
        {
            s.Filter = "(&(objectClass=user)(cn=" + ten + "))";
        }

        // ------------------------------------------------------------------
        // CWE-91 : XML / XSLT Injection
        // ------------------------------------------------------------------

        // rule: dso-xmli-innerxml-concat
        public void Xmli_LoadXml(XmlDocument doc, string ten)
        {
            doc.LoadXml("<NguoiDung><Ten>" + ten + "</Ten></NguoiDung>");
        }

        // rule: dso-xslti-enable-script
        public void Xslti_EnableScript()
        {
            var cauHinh = new XsltSettings();
            cauHinh.EnableScript = true;
        }

        // ------------------------------------------------------------------
        // CWE-113 : HTTP Response Splitting
        // ------------------------------------------------------------------

        // rule: dso-responsesplit-header-concat
        public void ResponseSplit_Header(string ngonNgu)
        {
            Response.Headers.Add("X-Ngon-Ngu", "vi-" + ngonNgu);
        }

        // ------------------------------------------------------------------
        // G2.3 - lan theo luong du lieu (taint)
        // ------------------------------------------------------------------

        // rule: dso-taint-path-traversal (khong noi chuoi: tham so di qua bien roi vao StreamReader)
        public string PathTraversal_Taint(string tenTep)
        {
            var duongDan = tenTep;
            if (File.Exists(duongDan))
            {
                using var sr = new StreamReader(duongDan);
                return sr.ReadToEnd();
            }
            return "";
        }

        // rule: dso-taint-header-injection
        public void Header_Cookie(string ngonNgu)
        {
            var cookie = new HttpCookie("lang", ngonNgu);
            Response.AppendCookie(cookie);
        }

        // rule: dso-taint-unsafe-reflection
        public object Reflection_TaoDoiTuong(string tenLop)
        {
            var kieu = Type.GetType(tenLop);
            return Activator.CreateInstance(kieu);
        }

        // rule: dso-taint-xss-status-description
        public void Xss_StatusDescription(string thongBao)
        {
            Response.StatusCode = 404;
            Response.StatusDescription = "Khong tim thay: " + thongBao;
        }

        // ------------------------------------------------------------------
        // G2.3 - mat ma va bi mat viet cung
        // ------------------------------------------------------------------

        // rule: dso-hardcoded-password
        public NetworkCredential MatKhau_VietCung()
        {
            var matKhau = "7e5tc4s3";
            return new NetworkCredential("user", matKhau, "domain");
        }

        // rule: dso-hardcoded-crypto-key
        public byte[] Khoa_VietCung(byte[] duLieu)
        {
            var khoa = "23 ~j;asn!@#/>as";
            using var aes = Aes.Create();
            var enc = aes.CreateEncryptor(Encoding.UTF8.GetBytes(khoa), aes.IV);
            return enc.TransformFinalBlock(duLieu, 0, duLieu.Length);
        }

        // rule: dso-weak-hash
        public byte[] Bam_Md5(byte[] duLieu)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(duLieu);
        }

        // rule: dso-weak-random
        public int NgauNhien_Yeu()
        {
            return new Random().Next();
        }

        // ------------------------------------------------------------------
        // CWE-94 : Server-Side Code Injection
        // ------------------------------------------------------------------

        // rule: dso-codei-dynamic-compile
        public void CodeI_ChayMa(string bieuThuc)
        {
            CSharpScript.EvaluateAsync(bieuThuc);
        }

        // ------------------------------------------------------------------
        // G3.5 - NGUON NGOAI HTTP (threat model "local")
        // ------------------------------------------------------------------
        // Phong do #23: nhom rule taint bat 35% case co nguon HTTP va 0% tren
        // 4218 case co nguon mang / CSDL / cuc bo. Cac case duoi day chung minh
        // tung nguon moi that su hoat dong - khong phai viet vao YAML roi tin.
        //
        // MOI HAM DUOI DAY CO Y KHONG NHAN THAM SO CHUOI. Neu nhan, nguon
        // "tham so cua action" se khop va case khong con chung minh duoc gi:
        // bat duoc o day nghia la bat NHO NGUON MOI.

        // nguon: StreamReader.ReadLine() - mot hinh dang nay phu 5 ho nguon cua
        // Juliet (ReadLine, File, Connect_tcp, Listen_tcp, NetClient)
        // rule: dso-taint-sqli
        public void NguonDocDong_VaoSql()
        {
            using var sr = new StreamReader("ten-nguoi-dung.txt");
            string ten = sr.ReadLine();
            using var cmd = new SqlCommand("select * from users where name='" + ten + "'");
            cmd.ExecuteNonQuery();
        }

        // nguon: Environment.GetEnvironmentVariable (ho Environment)
        // rule: dso-taint-path-traversal
        public string NguonBienMoiTruong_VaoDuongDan()
        {
            string duong = Environment.GetEnvironmentVariable("BAO_CAO");
            return File.ReadAllText("/var/bao-cao/" + duong);
        }

        // nguon: SqlDataReader.GetString(i) (ho Database) - injection BAC HAI:
        // du lieu da luu trong CSDL di vao lenh he dieu hanh
        // rule: dso-taint-cmdi
        public void NguonCsdl_VaoLenhHeDieuHanh()
        {
            using var conn = new SqlConnection("Server=.;Database=kho;Encrypt=True");
            using var cmd = new SqlCommand("select ten_tep from tai_lieu", conn);
            using SqlDataReader rd = cmd.ExecuteReader();
            while (rd.Read())
            {
                string tenTep = rd.GetString(0);
                Process.Start("/usr/bin/convert " + tenTep);
            }
        }

        // nguon: File.ReadAllText (ho File)
        // rule: dso-taint-header-injection
        public void NguonTep_VaoCookie()
        {
            string ngonNgu = File.ReadAllText("ngon-ngu-mac-dinh.txt");
            var cookie = new HttpCookie("lang", ngonNgu);
            Response.AppendCookie(cookie);
        }

        // nguon: WebClient.DownloadString (ho NetClient)
        // rule: dso-taint-xss-status-description
        public void NguonMang_VaoStatusDescription()
        {
            string thongBao = _wc.DownloadString("https://noi-bo/thong-bao");
            Response.StatusCode = 404;
            Response.StatusDescription = "Khong tim thay: " + thongBao;
        }

        // nguon: StreamReader.ReadToEnd()
        // rule: dso-taint-unsafe-reflection
        public object NguonDocHet_VaoPhanChieu()
        {
            using var sr = new StreamReader("bo-xu-ly.cfg");
            string tenLop = sr.ReadToEnd();
            return Activator.CreateInstance(Type.GetType(tenLop));
        }

        // nguon: Console.ReadLine() - cong cu dong lenh doc dau vao nguoi dung
        // rule: dso-taint-ldapi
        public void NguonConsole_VaoLdap()
        {
            string ten = Console.ReadLine();
            var search = new DirectorySearcher();
            search.Filter = "(&(objectClass=user)(cn=" + ten + "))";
            search.FindOne();
        }

        // nguon: SqlDataReader.GetValue(i) (ho Database)
        // rule: dso-taint-xpathi
        public XmlNode NguonCsdlGiaTri_VaoXPath()
        {
            using var conn = new SqlConnection("Server=.;Database=kho;Encrypt=True");
            using var cmd = new SqlCommand("select ma from bo_loc", conn);
            using SqlDataReader rd = cmd.ExecuteReader();
            rd.Read();
            string ma = (string)rd.GetValue(0);
            var doc = new XmlDocument();
            doc.Load("danh-muc.xml");
            return doc.SelectSingleNode("//muc[ma='" + ma + "']");
        }

        // ------------------------------------------------------------------
        // CWE-319 : truyen tin khong ma hoa (kiem tra cau hinh)
        // ------------------------------------------------------------------
        // Hai case nay la cua rule muc WARNING - xem ghi chu CWE-319 trong
        // sast-detect.yaml ve viec chung KHONG bat duoc dang that cua Juliet.

        // rule: dso-cleartext-sql-connection
        public void KetNoiCsdl_TatMaHoa()
        {
            using var conn = new SqlConnection(
                "Server=db.noi-bo;Database=donhang;User ID=sa;Password=x;Encrypt=false");
            conn.Open();
        }

        // rule: dso-cleartext-transport-disabled
        public void TruyenTai_HaGiaoThuc()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;
        }
    }
}
