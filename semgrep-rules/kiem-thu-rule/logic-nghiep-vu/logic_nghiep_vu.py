# =============================================================================
# CORPUS LOGIC NGHIEP VU - MA DUNG MA TRONG NHU LOI  (Python)
# =============================================================================
# Dap an: 0 canh bao o muc CO QUYEN CHAN. Xem DocQuyetDinh.md.
#
# Phan lon case o day nham vao CAC NGUON VUA MO RONG o commit G6.2
# (os.environ, request.body, request.get_data, request.META). Moi nguon do deu
# co mot dang dung HOP LE rat pho bien ma corpus sinh tu dong khong chua -
# day la cho de xay ra "khong loi van bi chan" nhat.
# =============================================================================

import hashlib
import os
import random
import subprocess
import time

from flask import Flask, render_template, request

app = Flask(__name__)


# --- NGUON MOI: os.environ -----------------------------------------------
# Viec nghiep vu: dong bo du lieu sang may sao luu, dia chi lay tu cau hinh.
# Vi sao an toan: KHONG qua shell. subprocess.run voi DANH SACH doi so nen
#   dau cham phay hay dau ong dan trong bien moi truong chi la ky tu binh
#   thuong. Day la dang dung dung cua mot script trien khai.
# Rule co the bao oan: dso-py-taint-cmdi - vi os.environ vua duoc them lam
#   nguon, va "bien moi truong di vao lenh he dieu hanh" la hinh dang cua no.
def dong_bo_sao_luu():
    dich = os.environ.get("BACKUP_HOST", "backup.noi-bo")
    subprocess.run(["rsync", "-a", "/var/du_lieu", f"{dich}:/sao_luu"], check=True)


# Viec nghiep vu: mo ket noi CSDL, tham so lay tu bien moi truong.
# Vi sao an toan: gia tri chi di vao THAM SO ket noi cua driver, khong vao mot
#   cau lenh SQL va khong vao shell. Day la cach cau hinh dung chuan 12-factor.
# Rule co the bao oan: dso-py-taint-sqli neu sink bi viet rong hon muc can.
def chuoi_ket_noi():
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", "5432")),
        "dbname": os.environ.get("DB_NAME", "vnshop"),
    }


# --- NGUON MOI: request.body / request.get_data ---------------------------
# Viec nghiep vu: nhan webhook thanh toan, luu ma giao dich vao CSDL.
# Vi sao an toan: than yeu cau duoc phan tich thanh JSON, ma giao dich bi buoc
#   ve so nguyen, va truy van THAM SO HOA. Gia tri toi dich khong con la chuoi
#   nguoi dung gui.
# Rule co the bao oan: dso-py-taint-sqli - request.get_data vua duoc them lam
#   nguon va day la hinh dang "than yeu cau di vao SQL".
@app.route("/webhook/thanh-toan", methods=["POST"])
def webhook_thanh_toan(cur=None):
    import json
    goi = json.loads(request.get_data(as_text=True) or "{}")
    ma_gd = int(goi.get("ma_giao_dich", 0))
    cur.execute("UPDATE don_hang SET da_thanh_toan = 1 WHERE ma_gd = %s", (ma_gd,))
    return {"ok": True}


# Viec nghiep vu: ghi nhat ky dia chi IP cua nguoi goi API.
# Vi sao an toan: truy van tham so hoa; gia tri di o doi so thu hai.
# Rule co the bao oan: dso-py-taint-sqli - request.META vua duoc them lam nguon.
def ghi_nhat_ky_ip(cur):
    ip = request.META.get("REMOTE_ADDR", "")
    cur.execute("INSERT INTO nhat_ky (ip) VALUES (%s)", (ip,))


# --- BANG BAM VA NGAU NHIEN KHONG PHAI BAO MAT ---------------------------
# Viec nghiep vu: sinh ETag cho tep tinh de trinh duyet cache duoc.
# Vi sao an toan: ETag chi de so sanh "tep co doi khong". usedforsecurity=False
#   noi ro y dinh cho ca nguoi doc va cho FIPS mode cua Python.
# Rule co the bao oan: cac rule bang bam yeu (CWE-328).
def sinh_etag(noi_dung: bytes) -> str:
    return hashlib.md5(noi_dung, usedforsecurity=False).hexdigest()


# Viec nghiep vu: cho ngau nhien truoc khi thu lai de tranh dong loat.
# Vi sao an toan: doan duoc do tre thu lai khong giup ke tan cong lam gi.
# Rule co the bao oan: cac rule ngau nhien yeu (CWE-338).
def do_tre_thu_lai(lan_thu: int) -> float:
    return min(2 ** lan_thu, 30) + random.random() * 0.25


# --- TRUY VAN DONG NHUNG AN TOAN ----------------------------------------
_COT_CHO_PHEP = {"gia": "gia", "ten": "ten", "moi": "ngay_tao"}


# Viec nghiep vu: danh sach san pham, nguoi dung chon cot sap xep.
# Vi sao an toan: ORDER BY khong tham so hoa duoc nen phai ghep chuoi, nhung
#   gia tri ghep vao den tu _COT_CHO_PHEP - tu dien hang so trong ma nguon.
#   Dau vao chi lam KHOA tra cuu.
# Rule co the bao oan: dso-py-taint-sqli.
def danh_sach_san_pham(cur, sap_xep_theo, tu_khoa):
    cot = _COT_CHO_PHEP.get(sap_xep_theo or "", "ngay_tao")
    cur.execute(
        f"SELECT id, ten, gia FROM san_pham WHERE ten ILIKE %s ORDER BY {cot} DESC",
        (f"%{tu_khoa}%",),
    )
    return cur.fetchall()


# Viec nghiep vu: lay nhieu san pham theo danh sach id (menh de IN).
# Vi sao an toan: SQL khong tham so hoa duoc mot danh sach do dai thay doi nen
#   phai sinh dung so dau %s. Chuoi ghep vao cau lenh chi gom cac dau %s do ma
#   nguon sinh; gia tri di qua tham so va da qua int().
# Rule co the bao oan: dso-py-taint-sqli - co f-string vao cau lenh SQL.
def lay_san_pham_theo_id(cur, ids):
    so = [int(x) for x in ids]
    cho = ",".join(["%s"] * len(so))
    cur.execute(f"SELECT id, ten FROM san_pham WHERE id IN ({cho})", so)
    return cur.fetchall()


# --- MAU VA MONGO: dang AN TOAN cua hai rule moi -------------------------
# Viec nghiep vu: trang chao mung co ten nguoi dung.
# Vi sao an toan: dung render_template (mau co san tren dia), du lieu truyen
#   lam BIEN cua mau. Khong phai render_template_string nen nguoi dung khong
#   dieu khien duoc chuoi mau.
# Rule co the bao oan: dso-py-taint-ssti - neu sink bi viet rong thanh moi ham
#   render.
@app.route("/chao")
def trang_chao():
    return render_template("chao.html", ten=request.args.get("ten", ""))


# Viec nghiep vu: tim nguoi dung theo ten dang nhap trong MongoDB.
# Vi sao an toan: truy van theo TRUONG. Gia tri la du lieu, khong phai ma - khac
#   han $where (chay JavaScript tren server).
# Rule co the bao oan: dso-py-taint-nosqli.
def tim_nguoi_dung(mongo_db):
    return mongo_db.users.find({"username": request.args.get("u", "")})


# --- DUONG DAN AN TOAN ---------------------------------------------------
_GOC_TAI_LEN = "/var/du_lieu/tai_len"


# Viec nghiep vu: tra ve tep nguoi dung da tai len truoc do.
# Vi sao an toan: hai lop. basename cat bo moi thanh phan thu muc; sau khi ghep
#   con kiem lai duong dan thuc (realpath) co nam duoi goc hay khong - lop nay
#   chan ca symlink.
# Rule co the bao oan: dso-py-taint-path-traversal.
def mo_tep_da_tai_len(ten_nguoi_dung_gui):
    ten = os.path.basename(ten_nguoi_dung_gui)
    day_du = os.path.realpath(os.path.join(_GOC_TAI_LEN, ten))
    if not day_du.startswith(_GOC_TAI_LEN + os.sep):
        raise PermissionError("duong dan ngoai thu muc tai len")
    return open(day_du, "rb")


# --- PHAN QUYEN TRONG NHU BYPASS ----------------------------------------
# Viec nghiep vu: cho nhan vien ho tro xem don hang cua nguoi khac.
# Vi sao an toan: nhin qua giong "bo qua kiem tra chu so huu", nhung dieu kien
#   dau la kiem tra VAI TRO that tu phien da xac thuc, khong phai tu tham so
#   nguoi dung gui.
# Rule co the bao oan: cac truy van kiem soat truy cap; DAST-idor.
def duoc_xem_don_hang(vai_tro_tu_phien, ma_chu_don, ma_nguoi_dang_nhap):
    if vai_tro_tu_phien in ("nhan_vien_ho_tro", "quan_tri"):
        return True
    return ma_chu_don == ma_nguoi_dang_nhap


# Viec nghiep vu: do thoi gian xu ly de xuat metric.
# Vi sao an toan: khong lien quan bao mat, de o day vi time.time() hay bi gom
#   vao cac rule "dung thoi gian lam nguon ngau nhien".
def do_thoi_gian(ham):
    bd = time.time()
    ham()
    return time.time() - bd
