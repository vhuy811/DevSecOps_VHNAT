# =============================================================================
# FIXTURE KIEM THU RULE - KHONG DUOC BI BAT  (Python)
# =============================================================================
#
# Doi trong cua Co_Loi.py. Moi ham o day lam DUNG mot viec ma Co_Loi.py lam
# sai. Dieu kien: KHONG rule phat hien nao duoc bat o tep nay (kiem tra duong
# tinh gia).
#
# Cach khu doc o day duoc chon de PHAN TICH LUONG DU LIEU KIEM CHUNG DUOC:
# tham so hoa, ham lam sach that, hoac hang so. KHONG dung kieu "kiem tra
# danh sach cho phep bang if" - taint khong lan theo duoc logic do, nen viet
# vay la tao bao nham gia tao trong chinh bo kiem thu.
# =============================================================================

import os
import subprocess

import requests
from flask import (redirect, render_template, render_template_string,
                   request, url_for)
from lxml import etree
from markupsafe import Markup, escape
from werkzeug.utils import secure_filename


# CWE-89: tham so hoa - gia tri di o DOI SO THU HAI, khong vao cau lenh
def sql_tham_so_hoa(cur):
    ten = request.args.get("ten")
    cur.execute("SELECT * FROM san_pham WHERE ten = ?", (ten,))
    return cur.fetchall()


# CWE-78: danh sach doi so, KHONG qua shell
def cmd_danh_sach_doi_so():
    may = request.args.get("may")
    subprocess.run(["ping", "-c", "1", may])


# CWE-22: cat bo thu muc truoc khi ghep
def path_cat_thu_muc():
    ten_tep = secure_filename(request.args.get("tep"))
    with open(os.path.join("/du_lieu", ten_tep)) as fh:
        return fh.read()


# CWE-79: ma hoa HTML truoc khi ghep.
# KHONG dung render_template_string o day. Ban truoc viet:
#     render_template_string("<p>" + escape(loi_nhan) + "</p>")
# va rule SSTI moi (dso-py-taint-ssti) da bao - BAO DUNG, khong phai bao nham:
# escape() doi < > & thanh thuc the HTML nhung KHONG dung toi `{{` va `{%`.
# Nguoi dung gui "{{7*7}}" thi Jinja2 van tinh ra 49; gui
# "{{''.__class__.__mro__...}}" thi thanh thuc thi ma. Tuc doan do an toan voi
# XSS nhung CO LO SSTI, trong khi tep nay ghi nhan la "da khu doc".
# Mot rule moi them vao da tim ra lo hong that trong chinh ma ma du an tu
# chung nhan la sach.
def xss_ma_hoa_html():
    loi_nhan = request.args.get("loi_nhan")
    return Markup("<p>" + escape(loi_nhan) + "</p>")


# CWE-94: doc du lieu co cau truc, khong chay ma
def khong_chay_ma():
    import ast
    bieu_thuc = request.args.get("bieu_thuc")
    return ast.literal_eval(bieu_thuc)


# CWE-918: dia chi la HANG SO, khong lay tu request
def ssrf_dia_chi_hang_so():
    return requests.get("https://noi-bo.example/trang-thai").text


# CWE-601: chi chuyen huong toi route noi bo
def redirect_noi_bo():
    return redirect(url_for("trang_chu"))


# CWE-611: tat xu ly thuc the ngoai
def xxe_tat_thuc_the(du_lieu_xml):
    bo_doc = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(du_lieu_xml, bo_doc)


# CWE-943: truy van theo TRUONG, khong dung $where - gia tri khong phai ma
def nosql_truy_van_theo_truong(mongo_db):
    ten = request.args.get("ten")
    return mongo_db.users.find({"username": ten})


# CWE-1336: mau co san tren dia, du lieu truyen lam BIEN cua mau
def ssti_mau_co_san():
    ten = request.args.get("ten")
    return render_template("chao.html", ten=ten)


# CWE-1336: string.Template cua stdlib chi thay the $bien, KHONG chay ma.
# Case nay ton tai de chot lai quyet dinh khong dat `Template($X, ...)` tran
# trong sink SSTI - neu ai them lai, dieu kien 2 se do.
def template_stdlib_khong_chay_ma():
    import string
    ten = request.args.get("ten")
    return string.Template("Chao $ten").substitute(ten=ten)


# ===========================================================================
# Cac case duoi day dung NGUON VUA THEM (G6.2) nhung da khu doc dung cach.
# Chung chot lai rang mo rong nguon KHONG keo theo bao nham: nguon rong hon
# ma dich van an toan thi phai im lang.
# ===========================================================================

# Nguon request.META.get nhung truy van THAM SO HOA
def meta_vao_sql_tham_so_hoa(cur):
    tac_nhan = request.META.get("HTTP_USER_AGENT")
    cur.execute("SELECT * FROM log WHERE ua = ?", (tac_nhan,))


# Nguon bien moi truong nhung danh sach doi so, KHONG qua shell
def moi_truong_vao_danh_sach_doi_so():
    dich = os.environ.get("BACKUP_HOST")
    subprocess.run(["rsync", "-a", "/var/data", dich])


# Nguon request.get_data nhung ma hoa HTML truoc khi ghep.
# Cung ly do nhu tren: khong dua du lieu vao CHUOI MAU, chi dua vao noi dung
# da ma hoa. Markup() danh dau chuoi la HTML an toan, va escape() da lam no
# an toan that truoc do.
def get_data_vao_xss_da_ma_hoa():
    du_lieu = request.get_data(as_text=True)
    return Markup("<p>" + escape(du_lieu) + "</p>")


# Nguon request.COOKIES.get nhung cat bo thu muc truoc khi ghep
def cookies_vao_duong_dan_da_cat():
    phien = secure_filename(request.COOKIES.get("session"))
    with open(os.path.join("/du_lieu", phien)) as fh:
        return fh.read()


# NGUON CAU HINH VAO DICH DUONG DAN - KHONG SANITIZER, VA PHAI KHONG BI BAT.
#
# Ham duy nhat trong tep nay khong khu doc gi: os.environ di thang vao open().
# Theo mo hinh de doa cua du an, cau hinh trien khai khong phai du lieu ke tan
# cong dieu khien. os.environ CHI con la nguon cua dso-py-taint-cmdi, va sink
# o day khong phai thuc thi lenh.
#
# La PHEP KIEM CHAP HANH cua quyet dinh ghi o khoi "NGUON CAU HINH" dau tep
# sast-detect-python.yaml: them lai os.environ vao nguon cua rule duong dan thi
# dieu kien 2 do ngay o dong nay.
def moi_truong_vao_duong_dan_khong_chan():
    thu_muc = os.environ.get("THU_MUC_BAO_CAO", "/var/bao-cao")
    with open(os.path.join(thu_muc, "bao_cao.csv")) as fh:
        return fh.read()
