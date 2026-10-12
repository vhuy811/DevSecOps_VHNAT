// =============================================================================
// CORPUS LOGIC NGHIEP VU - MA DUNG MA TRONG NHU LOI  (Java)
// =============================================================================
// Dap an: 0 canh bao o muc CO QUYEN CHAN. Xem DocQuyetDinh.md.
//
// Phan lon case o day nham vao CAC NGUON VUA MO RONG o commit G6.3
// ($X.readLine(), System.getenv, $P.getProperty, $RS.getString). Dac biet co
// case "doc mot dong tu tep manifest roi mo tep do" - dung cho ma tep rule da
// ghi la CAN THEO DOI, vi Semgrep khong phan biet duoc readLine() doc tu socket
// hay doc tu tep cuc bo.
// =============================================================================

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.io.FilenameUtils;

public class LogicNghiepVu {

    private static final Random NN = new Random();
    private static final String GOC_TAI_LEN = "/var/du_lieu/tai_len";

    // --- NGUON MOI: $X.readLine() -----------------------------------------
    // Viec nghiep vu: doc tep manifest liet ke cac anh can tao thu nho, roi mo
    //   tung anh. Day la mot job xu ly theo lo rat pho bien.
    // Vi sao an toan: hai lop. FilenameUtils.getName cat bo moi thanh phan thu
    //   muc nen "../../etc/passwd" thanh "passwd"; sau khi ghep con kiem lai
    //   duong dan chuan hoa co nam duoi GOC_TAI_LEN hay khong.
    // Rule co the bao oan: dso-java-taint-path-traversal. DAY LA CASE QUAN
    //   TRONG NHAT cua tep nay - chinh cho ma ghi chu trong sast-detect-java.yaml
    //   noi phai theo doi. Neu case nay bi bao o muc chan thi ket luan la bo
    //   $X.readLine() khoi rule path-traversal.
    public static List<FileInputStream> moTheoManifest(BufferedReader manifest)
            throws IOException {
        List<FileInputStream> ra = new ArrayList<>();
        String dong;
        while ((dong = manifest.readLine()) != null) {
            String ten = FilenameUtils.getName(dong.trim());
            if (ten.isEmpty()) {
                continue;
            }
            File tep = new File(GOC_TAI_LEN, ten);
            if (!tep.getCanonicalPath().startsWith(GOC_TAI_LEN + File.separator)) {
                throw new SecurityException("duong dan ngoai thu muc tai len");
            }
            ra.add(new FileInputStream(tep));
        }
        return ra;
    }

    // Viec nghiep vu: doc so luong ban ghi can xu ly tu mot tep cau hinh.
    // Vi sao an toan: gia tri bi buoc ve so nguyen bang Integer.parseInt nen
    //   khong con la chuoi khi toi cau lenh; va cau lenh van tham so hoa.
    // Rule co the bao oan: dso-java-taint-sqli - readLine() la nguon moi.
    public static PreparedStatement layTheoLo(Connection conn, BufferedReader cauHinh)
            throws Exception {
        int soLuong = Integer.parseInt(cauHinh.readLine().trim());
        PreparedStatement st = conn.prepareStatement(
                "SELECT id, ten FROM san_pham ORDER BY id LIMIT ?");
        st.setInt(1, soLuong);
        return st;
    }

    // --- NGUON MOI: System.getenv / getProperty ---------------------------
    // Viec nghiep vu: dong bo du lieu sang may sao luu.
    // Vi sao an toan: ProcessBuilder nhan DANH SACH doi so, khong qua shell.
    //   Dau cham phay hay dau ong dan trong bien moi truong chi la ky tu.
    // Rule co the bao oan: dso-java-taint-cmdi - System.getenv la nguon moi.
    public static Process dongBoSaoLuu() throws IOException {
        String dich = System.getenv("BACKUP_HOST");
        return new ProcessBuilder("rsync", "-a", "/var/du_lieu", dich + ":/sao_luu").start();
    }

    // Viec nghiep vu: ghi tep tam vao thu muc tam cua he thong.
    // Vi sao an toan: java.io.tmpdir la thuoc tinh do JVM dat, va ten tep la
    //   hang so trong ma nguon - khong co phan nao do nguoi dung dieu khien.
    // Rule co the bao oan: dso-java-taint-path-traversal - $P.getProperty la
    //   nguon moi va new File(...) la sink.
    public static File tepTamBaoCao() {
        return new File(System.getProperty("java.io.tmpdir"), "bao_cao_tam.csv");
    }

    // --- NGUON MOI: $RS.getString() (tiem SQL bac hai) --------------------
    // Viec nghiep vu: doc ma danh muc tu bang san_pham roi dem so san pham cua
    //   danh muc do. Day la dang truy van hai buoc rat pho bien.
    // Vi sao an toan: gia tri doc tu CSDL di qua THAM SO cua PreparedStatement,
    //   khong noi vao cau lenh. Day moi la diem khac biet - khong phai "du lieu
    //   tu CSDL thi tin duoc", ma la "gia tri khong bao gio thanh cu phap SQL".
    // Rule co the bao oan: dso-java-taint-sqli - $RS.getString la nguon moi va
    //   day la hinh dang tiem SQL bac hai.
    public static PreparedStatement demTheoDanhMuc(Connection conn, ResultSet rs)
            throws Exception {
        String maDanhMuc = rs.getString("ma_danh_muc");
        PreparedStatement st = conn.prepareStatement(
                "SELECT COUNT(*) FROM san_pham WHERE ma_danh_muc = ?");
        st.setString(1, maDanhMuc);
        return st;
    }

    // --- TRUY VAN DONG NHUNG AN TOAN --------------------------------------
    private static final Map<String, String> COT_CHO_PHEP = Map.of(
            "gia", "gia", "ten", "ten", "moi", "ngay_tao");

    // Viec nghiep vu: danh sach san pham, nguoi dung chon cot sap xep.
    // Vi sao an toan: ORDER BY khong tham so hoa duoc nen phai ghep chuoi, nhung
    //   gia tri ghep vao den tu COT_CHO_PHEP - Map hang so trong ma nguon. Dau
    //   vao chi lam KHOA tra cuu; khong khop thi roi vao gia tri mac dinh.
    // Rule co the bao oan: dso-java-taint-sqli / java/sql-injection /
    //   java/concatenated-sql-query.
    public static PreparedStatement danhSachSanPham(Connection conn, String sapXepTheo,
                                                    String tuKhoa) throws Exception {
        String cot = COT_CHO_PHEP.getOrDefault(sapXepTheo == null ? "" : sapXepTheo,
                                               "ngay_tao");
        PreparedStatement st = conn.prepareStatement(
                "SELECT id, ten, gia FROM san_pham WHERE ten LIKE ? ORDER BY " + cot + " DESC");
        st.setString(1, "%" + tuKhoa + "%");
        return st;
    }

    // --- BANG BAM VA NGAU NHIEN KHONG PHAI BAO MAT ------------------------
    // Viec nghiep vu: sinh ETag cho tep tinh de trinh duyet cache duoc.
    // Vi sao an toan: ETag chi de so sanh "tep co doi khong". Khong bao ve bi mat
    //   nao; va cham chi lam cache sai, noi dung van la noi dung that cua server.
    // Rule co the bao oan: cac rule bang bam yeu (CWE-328),
    //   java/weak-cryptographic-algorithm.
    public static String sinhETag(byte[] noiDung) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest(noiDung)) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Viec nghiep vu: cho ngau nhien truoc khi thu lai de tranh dong loat.
    // Vi sao an toan: doan duoc do tre thu lai khong giup ke tan cong lam gi.
    // Rule co the bao oan: cac rule ngau nhien yeu (CWE-338), java/weak-prng.
    public static long doTreThuLai(int lanThu) {
        return Math.min(1000L << lanThu, 30000L) + NN.nextInt(250);
    }

    // --- PHAN QUYEN TRONG NHU BYPASS --------------------------------------
    // Viec nghiep vu: cho nhan vien ho tro xem don hang cua nguoi khac.
    // Vi sao an toan: dieu kien dau la kiem tra VAI TRO that tu phien da xac
    //   thuc, khong phai tu tham so nguoi dung gui.
    // Rule co the bao oan: cac truy van kiem soat truy cap; DAST-idor.
    public static boolean duocXemDonHang(String vaiTroTuPhien, String maChuDon,
                                         String maNguoiDangNhap) {
        if ("NhanVienHoTro".equals(vaiTroTuPhien) || "QuanTri".equals(vaiTroTuPhien)) {
            return true;
        }
        return maChuDon.equals(maNguoiDangNhap);
    }
}
