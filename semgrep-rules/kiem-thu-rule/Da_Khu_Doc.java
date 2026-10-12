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

    // NGUON CAU HINH VAO DICH DUONG DAN - KHONG CO SANITIZER, VA PHAI KHONG BI BAT.
    //
    // Day la ham DUY NHAT trong tep nay khong he "khu doc" gi ca: gia tri tu
    // System.getProperty di THANG vao sink. No van thuoc tep nay vi theo mo
    // hinh moi de doa cua du an, cau hinh trien khai KHONG phai du lieu ke tan
    // cong dieu khien - ai dat duoc system property cho tien trinh JVM thi da
    // chay duoc ma trong tien trinh do roi.
    //
    // Truoc day day la case "da cat thu muc" dung de kiem sanitizer
    // FilenameUtils.getName. Sanitizer do van duoc kiem - boi
    // thamSoVaoDuongDanDaCat() o tren, voi nguon HTTP.
    //
    // Ham nay la PHEP KIEM CHAP HANH cua quyet dinh bo nguon cau hinh: neu co
    // ai them lai $P.getProperty vao nguon cua rule duong dan, dieu kien 2 cua
    // bo kiem (khong duoc bao nham tren Da_Khu_Doc) se do ngay o dong nay -
    // khong phai doi den luc corpus logic nghiep vu chan oan mot PR that.
    public void thuocTinhVaoDuongDan_nguonCauHinh() throws Exception {
        String data = System.getProperty("user.home");
        new FileInputStream(new File("/du_lieu", data));
    }
}
