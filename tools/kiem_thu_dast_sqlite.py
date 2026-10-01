#!/usr/bin/env python3
"""
Kiem thu lop error-based Microsoft.Data.Sqlite cua dast_scan.py (G3.2).

Vi sao can: lop nay la ly do G3.2 ton tai - no bat ngu canh SQLi ma ZAP bo sot.
Mot bug lam no khong bat (hoac bat nham endpoint an toan) se lam hong ca tang
DAST ma khong ai hay. Tep nay dung mot app GIA mo phong VulnShop (noi chuoi SQL,
tra thong bao loi SQLite ra phan hoi) va kiem tra:
  - BAT dung endpoint co loi (Filter ngu canh =, Search ngu canh LIKE)
  - KHONG bat endpoint da tham so hoa (SafeSearch) hay endpoint khong cham CSDL (Echo)
  - chu ky loi khop thong bao that, khong khop noi dung binh thuong

Chay: python tools/kiem_thu_dast_sqlite.py
"""
from __future__ import annotations

import http.server
import socketserver
import sys
import threading
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dast_scan as d  # noqa: E402


class _App(http.server.BaseHTTPRequestHandler):
    """VulnShop gia: noi chuoi SQL. So dau nháy le lam vo hieu chuoi -> loi
    Microsoft.Data.Sqlite, duoc app bat va in ra phan hoi (giong controller that)."""

    def log_message(self, *a):  # im lang
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        le = lambda v: v.count("'") % 2 == 1  # noqa: E731
        body = "<html>VulnShop</html>"
        if p == "/Product/Filter":          # WHERE Category = '...'  (noi chuoi)
            v = (q.get("category") or [""])[0]
            body = "SQL error: SQLite Error 1: 'unrecognized token'" if le(v) else "<html>rows</html>"
        elif p == "/Product/Search":        # WHERE Name LIKE '%...%' (noi chuoi)
            v = (q.get("q") or [""])[0]
            body = "SQL error: SQLite Error 1: 'near: syntax error'" if le(v) else "<html>rows</html>"
        elif p == "/Product/SafeSearch":    # da tham so hoa -> KHONG bao gio loi
            body = "<html>safe rows</html>"
        elif p == "/Product/Echo":          # XSS, khong cham CSDL
            v = (q.get("msg") or [""])[0]
            body = "<html>" + v + "</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def main() -> int:
    srv = socketserver.TCPServer(("127.0.0.1", 5097), _App)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.4)

    routes = [
        {"url_path": "/Product/Filter", "status": "testable", "params": ["category"], "test_seed": "Phu kien"},
        {"url_path": "/Product/Search", "status": "testable", "params": ["q"], "test_seed": "a"},
        {"url_path": "/Product/SafeSearch", "status": "testable", "params": ["q"], "test_seed": "a"},
        {"url_path": "/Product/Echo", "status": "testable", "params": ["msg"], "test_seed": "a"},
    ]

    got = d.quet_loi_sqlite(routes, "http://127.0.0.1:5097")
    srv.shutdown()

    paths = sorted(urllib.parse.urlparse(a["url"]).path for a in got)
    loi = []
    if paths != ["/Product/Filter", "/Product/Search"]:
        loi.append(f"bat sai endpoint: {paths} - phai la Filter + Search, "
                   f"KHONG duoc co SafeSearch (tham so hoa) hay Echo (khong cham CSDL)")
    if not all(a["cweid"] == "89" and a["risk"] == "High" for a in got):
        loi.append("alert phai la CWE-89 muc High")
    if not d.co_loi_sqlite("x SQLite Error 1: 'unrecognized token' y"):
        loi.append("bo sot chu ky 'SQLite Error'")
    if not d.co_loi_sqlite("Microsoft.Data.Sqlite.SqliteException: ..."):
        loi.append("bo sot chu ky 'Microsoft.Data.Sqlite'")
    if d.co_loi_sqlite("Your SQL search returned 3 rows"):
        loi.append("bao nham tren noi dung binh thuong co chu 'SQL'")

    print(f"Lop error-based bat: {paths}")
    if loi:
        print("KIEM THU THAT BAI:")
        for x in loi:
            print("  -", x)
        return 1
    print("KIEM THU DAT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
