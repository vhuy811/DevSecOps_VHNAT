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
from flask import redirect, render_template_string, request, url_for
from lxml import etree
from markupsafe import escape
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


# CWE-79: ma hoa HTML truoc khi ghep
def xss_ma_hoa_html():
    loi_nhan = request.args.get("loi_nhan")
    return render_template_string("<p>" + escape(loi_nhan) + "</p>")


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
