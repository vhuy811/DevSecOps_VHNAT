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


def main() -> int:
    srv = socketserver.TCPServer(("127.0.0.1", 5096), _App)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)
    base = "http://127.0.0.1:5096"

    rt = d.doc_chinh_sach().get("runtime", {})
    got = d.quet_runtime(base, [base + "/", base + "/safe"], rt)
    srv.shutdown()

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
        return 1
    print(f"KIEM THU DAT ({len(got)} phat hien)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
