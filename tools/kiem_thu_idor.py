#!/usr/bin/env python3
"""
Kiem thu bo kiem IDOR/BOLA (G3.4) cua idor.py.

App GIA co dang nhap (cookie sid=<ten>) va hai nhom endpoint tren cung du lieu:
  /vuln/order?id=N : tra ve don hang N cho BAT KY ai dang nhap  (LO IDOR)
  /safe/order?id=N : chi tra ve neu N thuoc ve nguoi dang nhap   (AN TOAN)
alice so huu don 1, bob so huu don 2. Kiem: bo kiem IDOR phai BAT duoc /vuln
(nguoi nay xem duoc don cua nguoi kia) va KHONG bao nham /safe.

G3.5 - DANG NHAP QUA FORM CO CHONG CSRF:
App gia co THEM /Account/LoginCsrf thuc hien double-submit that: GET tra token
an + cookie antiforgery, POST chi chap nhan khi token form TRUNG cookie. Kiem
hai chieu:
  - dang_nhap() phai vuot qua duoc (lay duoc cookie phien)
  - POST TRAN (khong token) phai BI TU CHOI
Chieu thu hai bat buoc phai co: thieu no thi endpoint co the dang khong kiem
token gi ca, va phep kiem thu chieu thu nhat tu dat ma khong chung minh gi.

Chay: python tools/kiem_thu_idor.py
"""
from __future__ import annotations

import http.server
import secrets
import socketserver
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import idor as d  # noqa: E402

CHU = {"1": "alice", "2": "bob"}          # don hang -> chu so huu
MAT_KHAU = {"alice": "alice123", "bob": "bob123"}
TEN_TRUONG_TOKEN = "__RequestVerificationToken"       # giong ASP.NET Core
TEN_COOKIE_TOKEN = ".AspNetCore.Antiforgery.KiemThu"


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

    def _cookie(self, ten):
        for phan in self.headers.get("Cookie", "").split(";"):
            phan = phan.strip()
            if phan.startswith(ten + "="):
                return phan[len(ten) + 1:]
        return ""

    def _cap_phien(self, u, p):
        """Dat cookie phien neu mat khau dung."""
        if MAT_KHAU.get(u) == p:
            self.send_response(302)
            self.send_header("Set-Cookie", f"sid={quote(u, safe='')}; Path=/; HttpOnly")
            self.send_header("Location", "/")
            self.end_headers()
            return True
        return False

    def do_POST(self):
        duong = urlsplit(self.path).path
        if duong in ("/Account/Login", "/Account/LoginCsrf"):
            n = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            if duong == "/Account/LoginCsrf":
                # Double-submit that: token trong form phai trung cookie.
                tok_form = (form.get(TEN_TRUONG_TOKEN) or [""])[0]
                tok_cookie = self._cookie(TEN_COOKIE_TOKEN)
                if not tok_form or tok_form != tok_cookie:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"antiforgery token khong hop le")
                    return
            u = (form.get("username") or [""])[0]
            p = (form.get("password") or [""])[0]
            if self._cap_phien(u, p):
                return
        self.send_response(401)
        self.end_headers()

    def _don(self, idc):
        return f"<h2>Don hang #{idc}</h2><p>Chu: {CHU.get(idc)} | Tong: {int(idc)*100}$</p>".encode()

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/Account/LoginCsrf":
            tok = secrets.token_hex(8)
            body = (
                '<html><body><form method="post" action="/Account/LoginCsrf">'
                f'<input type="hidden" name="{TEN_TRUONG_TOKEN}" value="{tok}">'
                '<input type="hidden" name="ReturnUrl" value="/">'
                '<input type="text" name="username">'
                '<input type="password" name="password">'
                '<button type="submit">Dang nhap</button>'
                '</form></body></html>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", f"{TEN_COOKIE_TOKEN}={tok}; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(body)
            return
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

    login = {"duong_dan": "/Account/Login", "truong_user": "username", "truong_pass": "password"}
    nguoi_dung = [{"ten": "alice", "mat_khau": "alice123"}, {"ten": "bob", "mat_khau": "bob123"}]

    loi = []

    # RAO CUNG GOC. Ban do route va cau hinh deu la DAU VAO, nen neu lop IDOR
    # chiu di goi host khac thi mot cau hinh bi sua tro thanh banh lai (SSRF):
    # cong cu mang theo cookie phien that di goi dich cua ke tan cong.
    # Truoc day bo kiem KHONG he kiem rao nay - phat hien ra nho buoc dot bien
    # ben duoi: pha han rao ma phep do van bao DAT.
    for u_thu, mong, vi_sao in [
        (base + "/Account/Login", True, "cung host cung cong - phai cho"),
        ("http://evil.example.com/x", False, "host khac - phai chan"),
        ("http://127.0.0.1:1/x", False, "cung host khac cong - phai chan"),
        ("file:///etc/passwd", False, "khong phai http(s) - phai chan"),
    ]:
        if mod._cung_goc(u_thu, base) != mong:
            loi.append(f"rao cung goc sai tren {u_thu}: {vi_sao}")

    # Dang nhap phai lay duoc cookie
    ck = mod.dang_nhap(base, login, nguoi_dung[0])
    if not ck or "sid=alice" not in ck:
        loi.append(f"dang_nhap khong lay duoc cookie dung: {ck!r}")

    cfg_vuln = {"login": login, "nguoi_dung": nguoi_dung,
                "tai_nguyen": [{"mau": "/vuln/order?id={id}", "id_cua": {"alice": "1", "bob": "2"}}]}
    cfg_safe = {"login": login, "nguoi_dung": nguoi_dung,
                "tai_nguyen": [{"mau": "/safe/order?id={id}", "id_cua": {"alice": "1", "bob": "2"}}]}

    vuln = mod.quet_idor(base, cfg_vuln)
    safe = mod.quet_idor(base, cfg_safe)

    # ---- G3.5: dang nhap qua form CO chong CSRF -------------------------
    login_csrf = {"duong_dan": "/Account/LoginCsrf",
                  "truong_user": "username", "truong_pass": "password"}
    ck_csrf = mod.dang_nhap(base, login_csrf, nguoi_dung[0])
    if not ck_csrf or "sid=alice" not in ck_csrf:
        loi.append(f"dang_nhap KHONG vuot duoc form co chong CSRF: {ck_csrf!r}")

    # Chieu nguoc: POST tran (khong token) PHAI bi tu choi - neu khong thi
    # endpoint khong he kiem token, va phep kiem tren tu dat vo nghia.
    import urllib.error as _ue, urllib.request as _ur
    from urllib.parse import urlencode as _ue2
    tran_bi_tu_choi = False
    try:
        _r = _ur.urlopen(_ur.Request(
            base + "/Account/LoginCsrf",
            data=_ue2({"username": "alice", "password": "alice123"}).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=5)
        tran_bi_tu_choi = "sid=" not in " ".join(_r.headers.get_all("Set-Cookie") or [])
    except _ue.HTTPError as e:
        tran_bi_tu_choi = e.code in (400, 401, 403, 419)
    except Exception:
        tran_bi_tu_choi = False
    if not tran_bi_tu_choi:
        loi.append("POST tran khong bi tu choi -> endpoint khong kiem CSRF, "
                   "phep kiem G3.5 khong chung minh duoc gi")

    # Va quet IDOR phai chay duoc KHI dang nhap qua form co token
    cfg_csrf = {"login": login_csrf, "nguoi_dung": nguoi_dung,
                "tai_nguyen": [{"mau": "/vuln/order?id={id}", "id_cua": {"alice": "1", "bob": "2"}}]}
    vuln_csrf = mod.quet_idor(base, cfg_csrf)
    if not vuln_csrf:
        loi.append("qua form co chong CSRF: KHONG bat duoc IDOR (truoc day phai "
                   "co y bo token khoi app moi kiem duoc)")
    srv.shutdown()
    srv.server_close()

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

    if im_lang:
        return loi
    print("### Phong do kiem IDOR/BOLA (G3.4)\n")
    print("| Endpoint | Ky vong | Ket qua |")
    print("|---|---|---|")
    print(f"| /vuln/order (lo) | bat IDOR | {'✅ ' + str(len(vuln)) + ' phat hien' if vuln else '❌ khong bat'} |")
    print(f"| /safe/order (an toan) | khong bao | {'✅ sach' if not safe else '❌ bao nham'} |")
    print(f"| /Account/LoginCsrf (co token) | dang nhap duoc | "
          f"{'✅ ' + str(len(vuln_csrf)) + ' phat hien qua form co CSRF' if vuln_csrf else '❌ khong vuot duoc'} |")
    print(f"| Rao cung goc (4 ca, chong SSRF) | chan host khac | "
          f"{'✅' if not any('rao cung goc' in x for x in loi) else '❌'} |")
    print(f"| POST tran vao form co token | bi tu choi | "
          f"{'✅ bi tu choi' if tran_bi_tu_choi else '❌ duoc chap nhan'} |")
    print()
    for f in vuln:
        print(f"- {f['alert']} ({f['attack']})")
    print()

    if loi:
        print("KIEM THU THAT BAI:")
        for x in loi:
            print("  -", x)
        return loi
    print(f"KIEM THU DAT ({len(vuln)} phat hien IDOR, 0 bao nham)")
    return loi


# Lop IDOR hong theo kieu nguy hiem nhat la hong IM LANG: no bao "khong thay
# gi", ma ket qua do khong phan biet duoc voi "ung dung phan quyen dung".
# Dot bien thu hai tai hien dung loi lop nay da tung mac: khong mang token
# chong CSRF nen moi yeu cau bi tu choi, va lop bao khong thay gi.
DOT_BIEN = [
    ("quet_idor() luon tra ve rong - lop mu hoan toan",
     lambda s: s.replace(
         "def quet_idor(base: str, cfg: dict, moi_timeout: float = 8.0) -> list[dict]:",
         "def quet_idor(base: str, cfg: dict, moi_timeout: float = 8.0) -> list[dict]:\n"
         "    return []")),
    ("khong gui token an trong form - dang nhap bi tu choi, lop im lang",
     lambda s: s.replace("def _mo_trang_dang_nhap(url: str, base: str, timeout: float)"
                         " -> tuple[dict[str, str], str]:",
                         "def _mo_trang_dang_nhap(url: str, base: str, timeout: float)"
                         " -> tuple[dict[str, str], str]:\n"
                         "    return {}, _mo_trang_dang_nhap_goc(url, base, timeout)[1]\n\n\n"
                         "def _mo_trang_dang_nhap_goc(url: str, base: str, timeout: float)"
                         " -> tuple[dict[str, str], str]:")),
    ("bo rao cung goc - lop co the bi lai di goi host khac (SSRF)",
     lambda s: s.replace("    return u.scheme in (\"http\", \"https\") and u.scheme"
                         " == b.scheme and u.netloc == b.netloc",
                         "    return True")),
]


def _dot_bien() -> int:
    import importlib.util
    import tempfile

    goc = Path(__file__).resolve().parent / "idor.py"
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
            tam = Path(td) / "idor_hong.py"
            tam.write_text(hong_nguon, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("idor_hong", tam)
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
