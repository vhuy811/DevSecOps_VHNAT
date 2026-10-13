#!/usr/bin/env python3
"""
Kiem thu rule runtime (G3.3) cua dast_scan.py: soi header bao mat + co cookie.

Dung app GIA hai trang: "/" thieu het header + cookie khong co co bao ve;
"/safe" du header + cookie an toan. Chay qua HTTP that (localhost) va kiem tra
quet_runtime() bat dung, khong bao thua, dung muc do - va in bang phong do
(header yeu cau -> thieu? so voi dap an biet truoc).

Chay: python tools/kiem_thu_runtime.py
"""
from __future__ import annotations

import http.server
import socketserver
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dast_scan as d  # noqa: E402


class _App(http.server.BaseHTTPRequestHandler):
    """"/" = cau hinh so ho; "/safe" = cau hinh dung chuan."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/safe"):
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "sid=abc; Path=/; HttpOnly; SameSite=Lax")
        else:
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=abc; Path=/")   # khong co co bao ve
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")


def _do(mod=d, im_lang: bool = False) -> list:
    # Cong 0 = he dieu hanh tu cap mot cong con ranh.
    # Truoc day ba bo kiem nay ghim cong co dinh va HAI trong so do (idor,
    # dast_sqlite) dung CUNG cong 5097, nen chay noi tiep tren cung mot may la
    # "Address already in use". Trong CI chung nam o hai job khac may nen khong
    # ai thay - do la mot bo kiem HONG theo cach im lang. Ngoai ra dong
    # allow_reuse_address gan SAU khi TCPServer() da bind xong thi khong co tac
    # dung gi ca, nen da bo.
    srv = socketserver.TCPServer(("127.0.0.1", 0), _App)
    cong = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)
    base = f"http://127.0.0.1:{cong}"

    rt = mod.doc_chinh_sach().get("runtime", {})
    got = mod.quet_runtime(base, [base + "/", base + "/safe"], rt)
    srv.shutdown()
    srv.server_close()

    header_bat = {f["alert"].split(": ", 1)[1] for f in got if f["alert"].startswith("Thieu header")}
    cookie_bat = {f["alert"].split(" co ", 1)[1].split(":")[0] for f in got if f["alert"].startswith("Cookie thieu")}
    muc = {f["alert"]: f["risk"] for f in got}

    loi = []
    # Dap an tren HTTP thuan: HSTS va Secure co chi_https -> KHONG duoc bao.
    mong_header = {"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"}
    if header_bat != mong_header:
        loi.append(f"header bat sai: {sorted(header_bat)} (mong {sorted(mong_header)})")
    mong_cookie = {"HttpOnly", "SameSite"}
    if cookie_bat != mong_cookie:
        loi.append(f"cookie bat sai: {sorted(cookie_bat)} (mong {sorted(mong_cookie)} - Secure bo qua vi HTTP)")
    if muc.get("Thieu header bao mat: Content-Security-Policy") != "Medium":
        loi.append("CSP phai muc Medium")
    if muc.get("Thieu header bao mat: X-Content-Type-Options") != "Low":
        loi.append("X-Content-Type-Options phai muc Low")
    if not all(f.get("cweid") for f in got):
        loi.append("moi phat hien phai co cweid")

    # G3.3 lam_khoa: chi CSP + X-Frame-Options duoc chon lam khoa (Medium), con lai report-only.
    khoa = {f["alert"].split(": ", 1)[1] for f in got
            if f["alert"].startswith("Thieu header") and f.get("lam_khoa")}
    if khoa != {"Content-Security-Policy", "X-Frame-Options"}:
        loi.append(f"lam_khoa sai: {sorted(khoa)} (mong CSP + X-Frame-Options)")

    # Rule lam_khoa -> sarif_tools runtime sinh cong cu RIENG 'DAST-runtime' (nguong Medium).
    import json as _json, subprocess as _sp, tempfile as _tf, os as _os
    tmp = _tf.mkdtemp()
    vao, ra = _os.path.join(tmp, "zap-alerts.json"), _os.path.join(tmp, "runtime.sarif")
    _json.dump({"rule_runtime": got}, open(vao, "w"))
    _sp.check_call([sys.executable, str(Path(__file__).resolve().parent / "sarif_tools.py"),
                    "runtime", "--in", vao, "--fallback-file", "Program.cs", "--out", ra],
                   stdout=_sp.DEVNULL)
    run0 = _json.load(open(ra))["runs"][0]
    if run0["tool"]["driver"]["name"] != "DAST-runtime":
        loi.append("SARIF runtime phai co driver name 'DAST-runtime'")
    ids = {r["ruleId"] for r in run0["results"]}
    if ids != {"rt-csp", "rt-xfo"}:
        loi.append(f"SARIF runtime chi gom rt-csp, rt-xfo; got {sorted(ids)}")
    sevs = {ru["id"]: ru["properties"]["security-severity"] for ru in run0["tool"]["driver"]["rules"]}
    if any(sevs.get(i) != "5.0" for i in ("rt-csp", "rt-xfo")):
        loi.append(f"security-severity rule khoa phai 5.0 (Medium); got {sevs}")

    # Bang phong do
    if im_lang:
        return loi
    print("### Phong do rule runtime (G3.3)\n")
    print("| Rule | Muc | Bat tren `/` |")
    print("|---|---|---|")
    dap_an = {"Content-Security-Policy": "Medium", "X-Frame-Options": "Medium",
              "X-Content-Type-Options": "Low"}
    for h, m in dap_an.items():
        print(f"| Thieu {h} | {m} | {'✅' if h in header_bat else '❌'} |")
    for c in ("HttpOnly", "SameSite"):
        print(f"| Cookie thieu {c} | Low | {'✅' if c in cookie_bat else '❌'} |")
    print(f"| HSTS/Secure (chi HTTPS) tren HTTP | - | {'✅ bo qua' if 'Strict-Transport-Security' not in header_bat else '❌ bao nham'} |")
    print()

    if loi:
        print("KIEM THU THAT BAI:")
        for x in loi:
            print("  -", x)
        return loi
    print(f"KIEM THU DAT ({len(got)} phat hien)")
    return loi


# Moi dot bien la mot cach lop runtime co the hong ma bao cao VAN dep: no chi
# doc header va cookie, nen hong kieu "khong bao gi" trong khong khac gi mot
# ung dung da cau hinh dung.
DOT_BIEN = [
    ("quet_runtime() luon tra ve rong - lop mu hoan toan",
     lambda s: s.replace("def quet_runtime(base: str, urls: list[str], rt: dict,"
                         " moi_timeout: float = 8.0) -> list[dict]:",
                         "def quet_runtime(base: str, urls: list[str], rt: dict,"
                         " moi_timeout: float = 8.0) -> list[dict]:\n    return []")),
    ("bo co chi_https - bao nham HSTS tren ket noi HTTP thuan",
     lambda s: s.replace("chi_https", "chi_https_khong_ton_tai")),
]


def _dot_bien() -> int:
    import importlib.util
    import tempfile

    goc = Path(__file__).resolve().parent / "dast_scan.py"
    nguon = goc.read_text(encoding="utf-8")
    sot: list[str] = []
    print("\n### Dot bien - phep do nay co thuc su do khong?\n")
    print("| Dot bien | Phep do bao |")
    print("|---|---|")
    with tempfile.TemporaryDirectory() as td:
        for ten, sua in DOT_BIEN:
            hong_nguon = sua(nguon)
            if hong_nguon == nguon:
                sot.append(f"{ten}: khong ap duoc vao ma nguon")
                print(f"| {ten} | KHONG AP DUOC |")
                continue
            tam = Path(td) / "dast_scan_hong.py"
            tam.write_text(hong_nguon, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("ds_hong", tam)
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                loi = _do(mod=mod, im_lang=True)
            except Exception as e:
                loi = [f"pha lam module chet: {e}"]
            if loi:
                print(f"| {ten} | HONG ({len(loi)} ca) - dung |")
            else:
                sot.append(f"{ten}: pha roi ma phep do van bao DAT")
                print(f"| {ten} | **DAT - SAI** |")
    print()
    if sot:
        print(f"**PHEP DO KHONG DANG TIN** - {len(sot)}/{len(DOT_BIEN)} dot bien "
              f"khong bi bat:")
        for x in sot:
            print(f"- {x}")
        return 1
    print(f"**DAT** - {len(DOT_BIEN)}/{len(DOT_BIEN)} dot bien deu bi bat.")
    return 0


def main() -> int:
    if _do():
        return 1
    return _dot_bien()


if __name__ == "__main__":
    sys.exit(main())
