# =============================================================================
# FIXTURE KIEM THU RULE - PHAI BI BAT  (Python)
# =============================================================================
#
# KHONG PHAI MA NGUON UNG DUNG. Day la du lieu kiem thu cho bo rule Semgrep
# sast-detect-python.yaml. Moi ham chua dung MOT dang lo hong, va rule tuong
# ung PHAI bat duoc no. Rule khong bat duoc case cua no la rule HONG - chu
# khong phai ma nguon nay an toan.
#
# Thu muc kiem-thu-rule bi loai tru khoi moi cho quet that (nhan_ngon_ngu.py,
# CI, pre-commit). Thay canh bao tu tep nay trong bao cao mot du an that nghia
# la cau hinh loai tru bi sai.
#
# Chay kiem thu: python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
# =============================================================================

import os
import subprocess

import requests
from flask import redirect, render_template_string, request
from lxml import etree


# ---------------------------------------------------------------------------
# CWE-89 : SQL Injection
# rule: dso-py-taint-sqli
# ---------------------------------------------------------------------------
def sqli_noi_chuoi(cur):
    ten = request.args.get("ten")
    cur.execute("SELECT * FROM san_pham WHERE ten = '" + ten + "'")
    return cur.fetchall()


# ---------------------------------------------------------------------------
# CWE-78 : OS Command Injection (qua shell)
# rule: dso-py-taint-cmdi
# ---------------------------------------------------------------------------
def cmdi_os_system():
    may = request.args.get("may")
    os.system("ping -c 1 " + may)


# ---------------------------------------------------------------------------
# CWE-78 : bien the subprocess shell=True
# rule: dso-py-taint-cmdi
# ---------------------------------------------------------------------------
def cmdi_subprocess_shell():
    may = request.args.get("may")
    subprocess.run("ping -c 1 " + may, shell=True)


# ---------------------------------------------------------------------------
# CWE-22 : Path Traversal
# rule: dso-py-taint-path-traversal
# ---------------------------------------------------------------------------
def path_traversal_open():
    ten_tep = request.args.get("tep")
    with open("/du_lieu/" + ten_tep) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# CWE-79 : Cross-Site Scripting
# rule: dso-py-taint-xss
# ---------------------------------------------------------------------------
def xss_render_template_string():
    loi_nhan = request.args.get("loi_nhan")
    return render_template_string("<p>" + loi_nhan + "</p>")


# ---------------------------------------------------------------------------
# CWE-94 : Server-Side Code Injection
# rule: dso-py-taint-code-injection
# ---------------------------------------------------------------------------
def code_injection_eval():
    bieu_thuc = request.args.get("bieu_thuc")
    return eval(bieu_thuc)


# ---------------------------------------------------------------------------
# CWE-918 : Server-Side Request Forgery
# rule: dso-py-taint-ssrf
# ---------------------------------------------------------------------------
def ssrf_requests_get():
    dia_chi = request.args.get("dia_chi")
    return requests.get(dia_chi).text


# ---------------------------------------------------------------------------
# CWE-601 : Open Redirect
# rule: dso-py-taint-open-redirect
# ---------------------------------------------------------------------------
def open_redirect():
    tiep = request.args.get("tiep")
    return redirect(tiep)


# ---------------------------------------------------------------------------
# CWE-611 : XML External Entity
# rule: dso-py-xxe-resolve-entities
# ---------------------------------------------------------------------------
def xxe_resolve_entities(du_lieu_xml):
    bo_doc = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(du_lieu_xml, bo_doc)
