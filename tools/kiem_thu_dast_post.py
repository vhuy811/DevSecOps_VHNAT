#!/usr/bin/env python3
"""Phong do lop POST cua dast_scan.py (G6.8).

VI SAO CAN TEP NAY
Do do phu DAST tren VulnShop ra 4/15 endpoint (27%). Nguyen nhan KHONG phai
dang nhap (needs_auth = 0) ma la phuong thuc: 5 endpoint POST mang 8 tham so
chua bao gio duoc do, trong do co /Account/Login (username, password) va
/Order/PlaceOrder (customerName, address).

Lop POST moi phai vuot duoc BA cua, va moi cua deu la mot cach no co the im
lang hong ma khong ai hay:
  1. Doc duoc form that trong HTML (action, ten truong).
  2. Mang theo token chong CSRF + cookie. Thieu -> app tra 400 -> lop bao
     "khong thay gi" trong khi chua he kiem duoc gi. Dung loi tang IDOR da
     tung mac phai.
  3. So sanh voi dau vao lanh truoc khi ket luan. Thieu -> endpoint nao luon
     bao loi CSDL cung bi ke la SQLi.

App gia duoi day dung de do ca ba cua, va phan DOT BIEN pha tung cua mot de
chung minh phep do that su do - khong phai trang tri.

Chay: python tools/kiem_thu_dast_post.py
"""
from __future__ import annotations

import http.server
import socketserver
import sys
import threading
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dast_scan as d  # noqa: E402

TOKEN = "tok-abc123"
COOKIE = "csrf=tok-abc123"


def _trang(action: str, truong: list[str], extra: str = "") -> str:
    o = [f'<form method="post" action="{action}">',
         f'<input type="hidden" name="__RequestVerificationToken" value="{TOKEN}">']
    o += [f'<input type="text" name="{t}">' for t in truong]
    o.append('<input type="submit" value="Gui">')
    o.append("</form>")
    return "<html><body>" + "".join(o) + extra + "</body></html>"


class _App(http.server.BaseHTTPRequestHandler):
    """App gia: form co chong CSRF, mot so truong noi chuoi SQL, mot so khong."""

    def log_message(self, *a):
        pass

    def _tra(self, body: str, ma: int = 200, cookie: bool = False):
        self.send_response(ma)
        self.send_header("Content-Type", "text/html")
        if cookie:
            self.send_header("Set-Cookie", COOKIE + "; Path=/")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/Order/Checkout":
            return self._tra(_trang("/Order/PlaceOrder", ["customerName", "address"]),
                             cookie=True)
        if p == "/Account/Login":
            return self._tra(_trang("/Account/Login", ["username", "password"]),
                             cookie=True)
        if p == "/Safe/Form":
            return self._tra(_trang("/Safe/Submit", ["note"]), cookie=True)
        if p == "/Sort/Form":
            # Tai hien dung form tim kiem nang cao cua VulnShop: mot o chu +
            # mot o chon thu tu sap xep. Neu lop POST dat MOI truong bang seed
            # thi sortBy="a" lam cau lenh thanh "ORDER BY a" -> loi CSDL ngay
            # voi dau vao lanh -> ca form bi bo qua.
            return self._tra(
                '<html><body><form method="post" action="/Sort/Find">'
                f'<input type="hidden" name="__RequestVerificationToken" value="{TOKEN}">'
                '<input type="text" name="term">'
                '<select name="sortBy">'
                '<option value="Id">Lien quan</option>'
                '<option value="Price">Gia</option>'
                '</select>'
                '<input type="submit" value="Tim"></form></body></html>', cookie=True)
        if p == "/Broken/Form":
            # Bay BAO NHAM: endpoint nay LUON bao loi CSDL, ke ca dau vao lanh.
            return self._tra(_trang("/Broken/Submit", ["bat_ky"]), cookie=True)
        if p == "/Account/Profile":
            # Form GET - lop POST phai bo qua.
            return self._tra(
                '<html><form method="get" action="/Account/Search">'
                '<input type="text" name="q"></form></html>', cookie=True)
        if p == "/Home/Index":
            # Form dang xuat - phai bo qua, neu gui se huy phien.
            return self._tra(_trang("/Account/Logout", ["xac_nhan"]), cookie=True)
        return self._tra("<html>VulnShop</html>", cookie=True)

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        f = urllib.parse.parse_qs(self.rfile.read(n).decode())
        lay = lambda k: (f.get(k) or [""])[0]  # noqa: E731
        le = lambda v: v.count("'") % 2 == 1   # noqa: E731

        # CUA 2: khong co token an + cookie dung thi tu choi, y nhu app that.
        if lay("__RequestVerificationToken") != TOKEN or \
                TOKEN not in (self.headers.get("Cookie") or ""):
            return self._tra("<html>400 - thieu token chong CSRF</html>", 400)

        if p == "/Order/PlaceOrder":
            # customerName NOI CHUOI -> co loi. address DA THAM SO -> an toan.
            if le(lay("customerName")):
                return self._tra("SQLite Error 1: 'unrecognized token'")
            return self._tra("<html>da dat hang</html>")
        if p == "/Account/Login":
            # username NOI CHUOI -> co loi. password DA THAM SO -> an toan.
            if le(lay("username")):
                return self._tra("SqliteException: SQL logic error")
            return self._tra("<html>sai tai khoan</html>")
        if p == "/Sort/Find":
            # sortBy di thang vao ORDER BY: gia tri ngoai bang trang -> loi CSDL.
            if lay("sortBy") not in ("Id", "Price"):
                return self._tra("SQLite Error 1: 'no such column: "
                                 + lay("sortBy") + "'")
            if le(lay("term")):
                return self._tra("SQLite Error 1: 'unrecognized token'")
            return self._tra("<html>ket qua</html>")
        if p == "/Broken/Submit":
            # Luon loi, ke ca dau vao lanh -> KHONG duoc ke la SQLi.
            return self._tra("SQLite Error 1: 'always broken'")
        if p == "/Account/Logout":
            return self._tra("<html>da dang xuat</html>")
        return self._tra("<html>ok</html>")


TRANG = ["/Order/Checkout", "/Account/Login", "/Safe/Form", "/Broken/Form",
         "/Sort/Form", "/Account/Profile", "/Home/Index"]

# (url ket thuc bang, ten tham so) PHAI bat duoc
PHAI_BAT = {("/Order/PlaceOrder", "customerName"), ("/Account/Login", "username"),
            # Truong noi chuoi NAM CHUNG form voi mot o chon ma seed lam hong
            # cau lenh. Day la ca da suyt lam lop POST im lang tren chinh form
            # co lo hong cua VulnShop.
            ("/Sort/Find", "term")}
# PHAI im lang - moi cai la mot kieu bao nham khac nhau
PHAI_IM = {
    ("/Order/PlaceOrder", "address"): "truong da tham so hoa trong form co loi",
    ("/Account/Login", "password"): "truong da tham so hoa trong form co loi",
    ("/Safe/Submit", "note"): "form hoan toan an toan",
    ("/Broken/Submit", "bat_ky"): "endpoint LUON loi - moc so sanh hong, khong ket luan duoc",
    ("/Account/Logout", "xac_nhan"): "form dang xuat - khong duoc gui",
    ("/Account/Search", "q"): "form method=GET - khong thuoc lop POST",
    ("/Sort/Find", "sortBy"): "o chon chi nhan gia tri trong bang trang - khong "
                              "phai lo hong chen chuoi",
}


def do(base: str) -> tuple[set, list[str]]:
    thay = d.quet_loi_sqlite_post(base, [base + t for t in TRANG])
    duoc = {(urllib.parse.urlparse(a["url"]).path, a["param"]) for a in thay}
    loi: list[str] = []
    for k in PHAI_BAT - duoc:
        loi.append(f"BO SOT {k[0]} tham so '{k[1]}'")
    for k, vi_sao in PHAI_IM.items():
        if k in duoc:
            loi.append(f"BAO NHAM {k[0]} tham so '{k[1]}' ({vi_sao})")
    return duoc, loi


def main() -> int:
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", 0), _App) as sv:
        cong = sv.server_address[1]
        base = f"http://127.0.0.1:{cong}"
        threading.Thread(target=sv.serve_forever, daemon=True).start()

        print("=== PHONG DO LOP POST ===")
        print(f"App gia tren {base}, {len(TRANG)} trang co form\n")
        duoc, loi = do(base)
        for k in sorted(PHAI_BAT):
            print(f"[{'DAT ' if k in duoc else 'HONG'}] bat duoc {k[0]} '{k[1]}'")
        for k, vi_sao in sorted(PHAI_IM.items()):
            print(f"[{'HONG' if k in duoc else 'DAT '}] im lang {k[0]} '{k[1]}' - {vi_sao}")

        print("\n=== DOT BIEN: phep do nay co thuc su do khong? ===")
        sot: list[str] = []

        goc_header = d._header_token

        def _pha_token(*a, **k):
            return {}
        # Dot bien 1: bo header token VA bo input an -> app tra 400 het.
        goc_gui = d._gui_post

        def _gui_khong_an(url, base_, truong, cookie, header_them, timeout):
            sach = {k: v for k, v in truong.items()
                    if k.lower() != "__requestverificationtoken"}
            return goc_gui(url, base_, sach, cookie, header_them, timeout)

        d._gui_post = _gui_khong_an
        _, l1 = do(base)
        d._gui_post = goc_gui
        if any("BO SOT" in x for x in l1):
            print("[DAT ] bo token chong CSRF -> phep do bao bo sot")
        else:
            sot.append("bo token chong CSRF ma phep do van bao dat")
            print("[SOT ] bo token chong CSRF ma phep do VAN bao dat")

        # Dot bien 2: bo buoc so sanh dau vao lanh -> /Broken phai bi ke nham.
        # co_loi_sqlite CHI duoc dung cho buoc kiem dau vao lanh (buoc tan cong
        # dung thang CHU_KY_SQLITE), nen vo hieu hoa no la bo dung buoc do.
        goc_co_loi = d.co_loi_sqlite

        d.co_loi_sqlite = lambda text: False
        _, l2 = do(base)
        d.co_loi_sqlite = goc_co_loi
        if any("BAO NHAM" in x and "Broken" in x for x in l2):
            print("[DAT ] bo so sanh dau vao lanh -> phep do bat duoc bao nham /Broken")
        else:
            sot.append("bo so sanh dau vao lanh ma phep do khong bat duoc bao nham")
            print("[SOT ] bo so sanh dau vao lanh ma phep do KHONG bat duoc bao nham")

        # Dot bien 3: dat MOI truong bang seed thay vi gia tri mac dinh cua
        # form. Day la ban ma TRUOC KHI SUA, va no lam lop POST im lang tren
        # dung form co lo hong cua VulnShop: o chon sap xep nhan seed "a" ->
        # "ORDER BY a" -> loi CSDL ngay voi dau vao lanh -> bo qua ca form.
        goc_quet = d.quet_loi_sqlite_post

        def _khong_dung_mac_dinh(base_, urls, seed="a", moi_timeout=8.0):
            that = d.thu_thap_form
            def _bo_mac_dinh(b, u, t=8.0):
                fs = that(b, u, t)
                for f in fs:
                    f["mac_dinh"] = {}
                return fs
            d.thu_thap_form = _bo_mac_dinh
            try:
                return goc_quet(base_, urls, seed, moi_timeout)
            finally:
                d.thu_thap_form = that

        d.quet_loi_sqlite_post = _khong_dung_mac_dinh
        _, l3 = do(base)
        d.quet_loi_sqlite_post = goc_quet
        if any("BO SOT" in x and "Sort/Find" in x for x in l3):
            print("[DAT ] bo gia tri mac dinh cua form -> phep do bao bo sot /Sort/Find")
        else:
            sot.append("bo gia tri mac dinh ma phep do khong bat duoc")
            print("[SOT ] bo gia tri mac dinh ma phep do KHONG bat duoc")

        # Dot bien 4: form method=GET va form dang xuat phai bi loai NGAY O
        # KHAU THU THAP. Do thang tren thu_thap_form chu khong do qua phat
        # hien: POST vao mot form GET se bi app tra 400 (thieu token) nen
        # khong sinh phat hien nao - tuc la do qua phat hien se luon "dat" ke
        # ca khi bo loc hong. Day dung la kieu phep do trang tri can tranh.
        form = d.thu_thap_form(base, [base + t for t in TRANG])
        duong = {urllib.parse.urlparse(f["action"]).path for f in form}
        for p_, nhan in (("/Account/Search", "form method=GET"),
                         ("/Account/Logout", "form dang xuat")):
            if p_ in duong:
                sot.append(f"{nhan} lot vao danh sach thu thap")
                print(f"[SOT ] {nhan} ({p_}) LOT vao danh sach thu thap")
            else:
                print(f"[DAT ] {nhan} ({p_}) bi loai o khau thu thap")
        # ... va cac form POST that PHAI co mat, neu khong phep do tren vo nghia.
        for p_ in ("/Order/PlaceOrder", "/Account/Login", "/Safe/Submit",
                   "/Sort/Find"):
            if p_ not in duong:
                sot.append(f"{p_} khong duoc thu thap")
                print(f"[SOT ] {p_} KHONG duoc thu thap")
        print(f"[DAT ] thu thap duoc {len(form)} form POST: {', '.join(sorted(duong))}")

        d._header_token = goc_header
        sv.shutdown()

    print()
    if loi:
        print(f"HONG {len(loi)} ca:")
        for x in loi:
            print(f"  - {x}")
        return 1
    if sot:
        print(f"PHEP DO KHONG DANG TIN - {len(sot)} dot bien khong bi bat:")
        for x in sot:
            print(f"  - {x}")
        return 1
    tong = len(PHAI_BAT) + len(PHAI_IM)
    print(f"DAT het {tong}/{tong} ca do, 4/4 dot bien deu bi bat.")
    print(f"Lop POST bat {len(PHAI_BAT)} truong noi chuoi, im lang tren "
          f"{len(PHAI_IM)} truong an toan / khong thuoc pham vi.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
