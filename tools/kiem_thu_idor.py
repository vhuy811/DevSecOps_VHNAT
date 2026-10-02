#!/usr/bin/env python3
"""
Kiem thu bo kiem IDOR/BOLA (G3.4) cua idor.py.

App GIA co dang nhap (cookie sid=<ten>) va hai nhom endpoint tren cung du lieu:
  /vuln/order?id=N : tra ve don hang N cho BAT KY ai dang nhap  (LO IDOR)
  /safe/order?id=N : chi tra ve neu N thuoc ve nguoi dang nhap   (AN TOAN)
alice so huu don 1, bob so huu don 2. Kiem: bo kiem IDOR phai BAT duoc /vuln
(nguoi nay xem duoc don cua nguoi kia) va KHONG bao nham /safe.

Chay: python tools/kiem_thu_idor.py
"""
from __future__ import annotations

import http.server
import socketserver
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import idor as d  # noqa: E402

CHU = {"1": "alice", "2": "bob"}          # don hang -> chu so huu
MAT_KHAU = {"alice": "alice123", "bob": "bob123"}


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _ai(self):
        c = self.headers.get("Cookie", "")
        for phan in c.split(";"):
            phan = phan.strip()
            if phan.startswith("sid="):
                return phan[4:]
        return None

    def do_POST(self):
        if urlsplit(self.path).path == "/Account/Login":
            n = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            u = (form.get("username") or [""])[0]
            p = (form.get("password") or [""])[0]
            if MAT_KHAU.get(u) == p:
                self.send_response(302)
                self.send_header("Set-Cookie", f"sid={u}; Path=/; HttpOnly")
                self.send_header("Location", "/")
                self.end_headers()
                return
        self.send_response(401)
        self.end_headers()

    def _don(self, idc):
        return f"<h2>Don hang #{idc}</h2><p>Chu: {CHU.get(idc)} | Tong: {int(idc)*100}$</p>".encode()

    def do_GET(self):
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        idc = (q.get("id") or [""])[0]
        ai = self._ai()
        if u.path == "/vuln/order":           # LO: khong kiem chu so huu
            if ai and idc in CHU:
                self.send_response(200); self.end_headers(); self.wfile.write(self._don(idc)); return
        elif u.path == "/safe/order":         # AN TOAN: chi chu moi xem duoc
            if ai and idc in CHU and CHU[idc] == ai:
                self.send_response(200); self.end_headers(); self.wfile.write(self._don(idc)); return
            self.send_response(403); self.end_headers(); return
        self.send_response(404); self.end_headers()


def main() -> int:
    srv = socketserver.TCPServer(("127.0.0.1", 5097), _App)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)
    base = "http://127.0.0.1:5097"

    login = {"duong_dan": "/Account/Login", "truong_user": "username", "truong_pass": "password"}
    nguoi_dung = [{"ten": "alice", "mat_khau": "alice123"}, {"ten": "bob", "mat_khau": "bob123"}]

    loi = []
    # Dang nhap phai lay duoc cookie
    ck = d.dang_nhap(base, login, nguoi_dung[0])
    if not ck or "sid=alice" not in ck:
        loi.append(f"dang_nhap khong lay duoc cookie dung: {ck!r}")

    cfg_vuln = {"login": login, "nguoi_dung": nguoi_dung,
                "tai_nguyen": [{"mau": "/vuln/order?id={id}", "id_cua": {"alice": "1", "bob": "2"}}]}
    cfg_safe = {"login": login, "nguoi_dung": nguoi_dung,
                "tai_nguyen": [{"mau": "/safe/order?id={id}", "id_cua": {"alice": "1", "bob": "2"}}]}

    vuln = d.quet_idor(base, cfg_vuln)
    safe = d.quet_idor(base, cfg_safe)
    srv.shutdown()

    if not vuln:
        loi.append("KHONG bat duoc IDOR tren /vuln/order (bo kiem mu)")
    if not all(f["cweid"] == "639" and f["risk"] == "High" for f in vuln):
        loi.append("phat hien IDOR phai la CWE-639 muc High")
    if safe:
        loi.append(f"bao nham tren /safe/order: {[f['alert'] for f in safe]}")

    # Phat hien IDOR -> sarif_tools idor sinh cong cu RIENG 'DAST-idor' (muc High).
    import json as _json, subprocess as _sp, tempfile as _tf, os as _os
    tmp = _tf.mkdtemp()
    vao, ra = _os.path.join(tmp, "zap-alerts.json"), _os.path.join(tmp, "idor.sarif")
    _json.dump({"idor": vuln}, open(vao, "w"))
    _sp.check_call([sys.executable, str(Path(__file__).resolve().parent / "sarif_tools.py"),
                    "idor", "--in", vao, "--fallback-file", "Program.cs", "--out", ra],
                   stdout=_sp.DEVNULL)
    run0 = _json.load(open(ra))["runs"][0]
    if run0["tool"]["driver"]["name"] != "DAST-idor":
        loi.append("SARIF idor phai co driver name 'DAST-idor'")
    if len(run0["results"]) != len(vuln):
        loi.append(f"SARIF idor phai co {len(vuln)} result; got {len(run0['results'])}")
    sev = run0["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    if sev != "8.0":
        loi.append(f"security-severity IDOR phai 8.0 (High); got {sev}")

    print("### Phong do kiem IDOR/BOLA (G3.4)\n")
    print("| Endpoint | Ky vong | Ket qua |")
    print("|---|---|---|")
    print(f"| /vuln/order (lo) | bat IDOR | {'✅ ' + str(len(vuln)) + ' phat hien' if vuln else '❌ khong bat'} |")
    print(f"| /safe/order (an toan) | khong bao | {'✅ sach' if not safe else '❌ bao nham'} |")
    print()
    for f in vuln:
        print(f"- {f['alert']} ({f['attack']})")
    print()

    if loi:
        print("KIEM THU THAT BAI:")
        for x in loi:
            print("  -", x)
        return 1
    print(f"KIEM THU DAT ({len(vuln)} phat hien IDOR, 0 bao nham)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
