// =============================================================================
// FIXTURE KIEM THU RULE - PHAI BI BAT  (Java)
// =============================================================================
//
// KHONG PHAI MA NGUON UNG DUNG. Du lieu kiem thu cho sast-detect-java.yaml.
// Moi phuong thuc chua dung MOT dang lo hong, va rule tuong ung PHAI bat duoc
// no. Rule khong bat duoc case cua no la rule HONG - chu khong phai ma nguon
// nay an toan.
//
// Thu muc kiem-thu-rule bi loai tru khoi moi cho quet that. Thay canh bao tu
// tep nay trong bao cao mot du an that nghia la cau hinh loai tru bi sai.
//
// Chay kiem thu: python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
// =============================================================================

import java.io.FileInputStream;
import java.net.URL;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import org.w3c.dom.Document;

public class Co_Loi {

    // -----------------------------------------------------------------------
    // CWE-89 : SQL Injection
    // rule: dso-java-taint-sqli
    // -----------------------------------------------------------------------
    public ResultSet sqliNoiChuoi(HttpServletRequest request, Statement st) throws Exception {
        String ten = request.getParameter("ten");
        return st.executeQuery("SELECT * FROM san_pham WHERE ten = '" + ten + "'");
    }

    // -----------------------------------------------------------------------
    // CWE-78 : OS Command Injection
    // rule: dso-java-taint-cmdi
    // -----------------------------------------------------------------------
    public void cmdiRuntimeExec(HttpServletRequest request) throws Exception {
        String may = request.getParameter("may");
        Runtime.getRuntime().exec("ping -c 1 " + may);
    }

    // -----------------------------------------------------------------------
    // CWE-22 : Path Traversal
    // rule: dso-java-taint-path-traversal
    // -----------------------------------------------------------------------
    public FileInputStream pathTraversal(HttpServletRequest request) throws Exception {
        String tep = request.getParameter("tep");
        return new FileInputStream("/du_lieu/" + tep);
    }

    // -----------------------------------------------------------------------
    // CWE-79 : Cross-Site Scripting
    // rule: dso-java-taint-xss
    // -----------------------------------------------------------------------
    public void xssGhiThang(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String loiNhan = request.getParameter("loi_nhan");
        response.getWriter().println("<p>" + loiNhan + "</p>");
    }

    // -----------------------------------------------------------------------
    // CWE-601 : Open Redirect
    // rule: dso-java-taint-open-redirect
    // -----------------------------------------------------------------------
    public void openRedirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tiep = request.getParameter("tiep");
        response.sendRedirect(tiep);
    }

    // -----------------------------------------------------------------------
    // CWE-918 : Server-Side Request Forgery
    // rule: dso-java-taint-ssrf
    // -----------------------------------------------------------------------
    public void ssrfNewUrl(HttpServletRequest request) throws Exception {
        String diaChi = request.getParameter("dia_chi");
        new URL(diaChi).openStream();
    }

    // -----------------------------------------------------------------------
    // CWE-643 : XPath Injection
    // rule: dso-java-taint-xpathi
    // -----------------------------------------------------------------------
    public Object xpathInjection(HttpServletRequest request, XPath xpath, Document doc) throws Exception {
        String ten = request.getParameter("ten");
        return xpath.evaluate("//nguoi_dung[ten='" + ten + "']", doc);
    }

    // -----------------------------------------------------------------------
    // CWE-90 : LDAP Injection
    // rule: dso-java-taint-ldapi
    // -----------------------------------------------------------------------
    public Object ldapInjection(HttpServletRequest request, DirContext ctx, SearchControls sc) throws Exception {
        String uid = request.getParameter("uid");
        return ctx.search("dc=vi_du,dc=com", "(uid=" + uid + ")", sc);
    }

    // -----------------------------------------------------------------------
    // CWE-611 : XML External Entity
    // rule: dso-java-xxe-dtd-enabled
    // -----------------------------------------------------------------------
    public DocumentBuilderFactory xxeBatDtd() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        return dbf;
    }
}
