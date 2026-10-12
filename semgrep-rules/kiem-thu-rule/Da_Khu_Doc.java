// =============================================================================
// FIXTURE KIEM THU RULE - KHONG DUOC BI BAT  (Java)
// =============================================================================
//
// Doi trong cua Co_Loi.java. Moi phuong thuc lam DUNG mot viec ma Co_Loi.java
// lam sai. Dieu kien: KHONG rule phat hien nao duoc bat o tep nay.
//
// Cach khu doc duoc chon de PHAN TICH LUONG DU LIEU KIEM CHUNG DUOC: tham so
// hoa, ham lam sach that, hoac hang so. KHONG dung kieu "kiem tra danh sach
// cho phep bang if" - taint khong lan theo logic do, viet vay la tao bao nham
// gia tao trong chinh bo kiem thu.
// =============================================================================

import java.io.FileInputStream;
import java.io.File;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import org.apache.commons.io.FilenameUtils;
import org.owasp.encoder.Encode;
import org.springframework.web.util.HtmlUtils;
import org.w3c.dom.Document;

public class Da_Khu_Doc {

    // CWE-89: PreparedStatement - gia tri di qua setString, khong vao cau lenh
    public PreparedStatement sqlThamSoHoa(HttpServletRequest request, Connection conn) throws Exception {
        String ten = request.getParameter("ten");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM san_pham WHERE ten = ?");
        ps.setString(1, ten);
        return ps;
    }

    // CWE-78: tung doi so tach rieng, khong qua shell
    public void cmdDanhSachDoiSo(HttpServletRequest request) throws Exception {
        String may = request.getParameter("may");
        new ProcessBuilder("ping", "-c", "1", may).start();
    }

    // CWE-22: cat bo thu muc truoc khi ghep
    public FileInputStream pathCatThuMuc(HttpServletRequest request) throws Exception {
        String tep = FilenameUtils.getName(request.getParameter("tep"));
        return new FileInputStream(new File("/du_lieu", tep));
    }

    // CWE-79: ma hoa HTML truoc khi ghi
    public void xssMaHoaHtml(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String loiNhan = request.getParameter("loi_nhan");
        response.getWriter().println("<p>" + HtmlUtils.htmlEscape(loiNhan) + "</p>");
    }

    // CWE-601: chi chuyen huong toi duong dan noi bo co dinh
    public void redirectNoiBo(HttpServletResponse response) throws Exception {
        response.sendRedirect("/trang-chu");
    }

    // CWE-918: dia chi la HANG SO, khong lay tu request
    public void ssrfDiaChiHangSo() throws Exception {
        new URL("https://noi-bo.example/trang-thai").openStream();
    }

    // CWE-643: bieu thuc XPath la hang so
    public Object xpathHangSo(XPath xpath, Document doc) throws Exception {
        return xpath.evaluate("//nguoi_dung[ten='co_dinh']", doc);
    }

    // CWE-90: ma hoa bo loc LDAP truoc khi noi
    public Object ldapMaHoaBoLoc(HttpServletRequest request, DirContext ctx, SearchControls sc) throws Exception {
        String uid = request.getParameter("uid");
        return ctx.search("dc=vi_du,dc=com", "(uid=" + Encode.forLdapFilter(uid) + ")", sc);
    }

    // CWE-611: tat DTD va bat che do xu ly an toan
    public DocumentBuilderFactory xxeTatDtd() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf;
    }

    // =======================================================================
    // Cac case duoi day dung NGUON VUA THEM (G6.3) nhung da khu doc dung cach,
    // chot lai rang nguon rong hon KHONG keo theo bao nham.
    // =======================================================================

    // Nguon readLine() nhung truy van THAM SO HOA
    public void readLineVaoSqlThamSoHoa(java.io.BufferedReader doc, Connection conn)
            throws Exception {
        String data = doc.readLine();
        PreparedStatement st = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        st.setString(1, data);
        st.executeQuery();
    }

    // Nguon bien moi truong nhung truyen DANH SACH doi so, khong qua shell
    public void moiTruongVaoDanhSachDoiSo() throws Exception {
        String data = System.getenv("BACKUP_HOST");
        new ProcessBuilder("rsync", "-a", "/var/data", data).start();
    }

    // Nguon System.getProperty nhung cat bo thu muc truoc khi ghep.
    // Dung DUNG ham sanitizer ma rule khai (FilenameUtils.getName): ban dau
    // toi viet `new File(...).getName()` - nhin thi tuong duong, nhung
    // `new File($X, ...)` CHINH LA mot sink cua rule nay nen nguon se chay
    // thang vao sink, va `getName()` khong phai `$P.getFileName()` da khai.
    // Tuc la case "sach" do lai la mot lo hong that theo dinh nghia cua rule.
    public void thuocTinhVaoDuongDanDaCat() throws Exception {
        String data = FilenameUtils.getName(System.getProperty("user.home"));
        new FileInputStream(new File("/du_lieu", data));
    }
}
