#!/usr/bin/env python3
"""
Kiem tra IDOR / BOLA (CWE-639) - G3.4.

ZAP active scan khong tu biet "tai nguyen nay cua ai": no khong co khai niem
quyen so huu. Loi kiem soat truy cap theo doi tuong (IDOR/BOLA) vi the lot qua
DAST thong thuong. Module nay quet CO XAC THUC: dang nhap bang NHIEU nguoi dung
that, roi thu lay tai nguyen cua nguoi NAY bang phien cua nguoi KHAC. Neu lay
duoc (HTTP 200, noi dung trung) thi ung dung khong kiem tra quyen so huu -> IDOR.

Cau hinh (JSON, do repo dich cung cap, vd .devsecops/idor.json):
  {
    "login":   {"duong_dan": "/Account/Login",
                "truong_user": "username", "truong_pass": "password",
                "truong_token": "__RequestVerificationToken"},   # tuy chon: de trong = tu nhan
    "nguoi_dung": [{"ten": "alice", "mat_khau": "..."},
                   {"ten": "bob",   "mat_khau": "..."}],
    "tai_nguyen": [
      {"mau": "/Account/Order?id={id}", "id_cua": {"alice": "1", "bob": "2"}}
    ]
  }

Chi hoat dong trong CUNG MOT GOC (same-origin) voi base-url de khong thanh SSRF.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode, urlsplit


def _cung_goc(url: str, base: str) -> bool:
    u, b = urlsplit(url), urlsplit(base)
    return u.scheme in ("http", "https") and u.scheme == b.scheme and u.netloc == b.netloc


class _KhongRedirect(urllib.request.HTTPRedirectHandler):
    """Khong tu dong theo 3xx - de bat Set-Cookie ngay o phan hoi dang nhap."""

    def redirect_request(self, *a, **k):
        return None


# Ten truong token chong CSRF cua cac khung pho bien (so sanh chu thuong).
TEN_TOKEN = {
    "__requestverificationtoken",   # ASP.NET Core / MVC
    "csrfmiddlewaretoken",          # Django
    "authenticity_token",           # Rails
    "_token",                       # Laravel
    "_csrf",                        # Spring Security
    "csrf_token", "csrf", "xsrf_token",
}
# Cookie mang token theo kieu double-submit (gui lai qua header).
COOKIE_TOKEN = {"xsrf-token", "csrftoken", "csrf-token", "x-csrf-token", "_csrf"}


class _DocInputAn(HTMLParser):
    """Rut moi <input type=hidden name=... value=...> cua trang dang nhap."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.an: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if a.get("type", "").lower() != "hidden":
            return
        ten = a.get("name")
        if ten:
            self.an[ten] = a.get("value", "")


def _gom_cookie(raw: list[str], truoc: str = "") -> str:
    """Gop Set-Cookie (va chuoi cookie co san) thanh mot chuoi 'a=1; b=2'."""
    jar = SimpleCookie()
    for nguon in ([truoc] if truoc else []) + list(raw):
        try:
            jar.load(nguon)
        except Exception:
            pass
    return "; ".join(f"{k}={m.value}" for k, m in jar.items())


def _mo_trang_dang_nhap(url: str, base: str, timeout: float) -> tuple[dict[str, str], str]:
    """GET trang dang nhap -> (cac input an, chuoi cookie).

    VI SAO CAN BUOC NAY: form co chong CSRF chi nhan POST khi co DU token an
    VA cookie doi ung (double-submit). Probe gui POST tran se bi 400/419, tuc
    la khong dang nhap duoc, va tang IDOR im lang - bao cao "khong thay gi"
    trong khi that ra chua he kiem duoc gi. Truoc day cach duy nhat de kiem
    IDOR la CO Y bo token khoi ung dung, nghia la bat ung dung tu lam yeu minh
    di cho vua cong cu. Day la sua dung cho: cong cu lam giong trinh duyet.
    """
    if not _cung_goc(url, base):
        return {}, ""
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout)
        html = r.read(262144).decode("utf-8", "replace")
        raw = r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        try:
            html = e.read(262144).decode("utf-8", "replace")
        except Exception:
            html = ""
        raw = e.headers.get_all("Set-Cookie") or []
    except (urllib.error.URLError, OSError):
        return {}, ""
    bo_doc = _DocInputAn()
    try:
        bo_doc.feed(html)
    except Exception:
        pass
    return bo_doc.an, _gom_cookie(raw)


def _header_token(an: dict[str, str], cookie: str, ten_token: str | None) -> dict[str, str]:
    """Header token cho khung doi double-submit qua header (Django, Angular, Rails).

    Gui thua header khong gay hai: khung nao khong dung thi bo qua.
    """
    gt = ""
    for k, v in an.items():
        if k == ten_token or k.lower() in TEN_TOKEN:
            gt = v
            break
    if not gt and cookie:
        jar = SimpleCookie()
        try:
            jar.load(cookie)
        except Exception:
            pass
        for k, m in jar.items():
            if k.lower() in COOKIE_TOKEN:
                gt = m.value
                break
    if not gt:
        return {}
    return {"X-CSRFToken": gt, "X-XSRF-TOKEN": gt, "X-CSRF-Token": gt}


def dang_nhap(base: str, login: dict, user: dict, timeout: float = 8.0) -> str | None:
    """Dang nhap that su (ke ca form co chong CSRF) -> chuoi Cookie hoac None.

    Ba buoc, giong trinh duyet:
      1. GET trang dang nhap: lay token an + cookie di kem.
      2. POST lai TAT CA input an (token, ReturnUrl...) kem user/mat khau,
         gui theo cookie cua buoc 1 va header token.
      3. Gop cookie cua ca hai buoc (cookie antiforgery + cookie phien).
    Trang dang nhap khong co token thi buoc 1 ra rong va ham chay y nhu ban cu
    (POST tran) - tuong thich nguoc hoan toan.
    """
    url = base + login["duong_dan"]
    if not _cung_goc(url, base):
        return None

    ten_token = login.get("truong_token") or None
    an, cookie_get = _mo_trang_dang_nhap(url, base, timeout)

    # Input an gui lai truoc, roi user/mat khau ghi de neu trung ten.
    du_lieu = dict(an)
    du_lieu[login["truong_user"]] = user["ten"]
    du_lieu[login["truong_pass"]] = user["mat_khau"]

    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Referer": url}          # Django doi Referer khi chay HTTPS
    if cookie_get:
        headers["Cookie"] = cookie_get
    headers.update(_header_token(an, cookie_get, ten_token))

    req = urllib.request.Request(url, data=urlencode(du_lieu).encode(),
                                 method="POST", headers=headers)
    op = urllib.request.build_opener(_KhongRedirect)
    try:
        r = op.open(req, timeout=timeout)
        raw = r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:            # 302 sau dang nhap van co Set-Cookie
        raw = e.headers.get_all("Set-Cookie") or []
    except (urllib.error.URLError, OSError):
        return None

    # Gop ca cookie buoc 1: ASP.NET giu cookie antiforgery rieng voi cookie phien.
    ket_qua = _gom_cookie(raw, truoc=cookie_get)
    return ket_qua or None


def _tai(url: str, cookie: str | None, base: str, timeout: float):
    if not _cung_goc(url, base):
        return None, ""
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.getcode(), r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError):
        return None, ""


def quet_idor(base: str, cfg: dict, moi_timeout: float = 8.0) -> list[dict]:
    """Dang nhap tung nguoi dung, thu truy cap cheo tai nguyen.

    Voi moi tai nguyen va moi (chu, nguoi_khac): neu nguoi_khac lay duoc tai
    nguyen cua chu (HTTP 200, body trung voi khi chinh chu lay) -> IDOR High.
    """
    ra: list[dict] = []
    login = cfg.get("login") or {}
    phien: dict[str, str | None] = {}
    for u in cfg.get("nguoi_dung", []):
        phien[u["ten"]] = dang_nhap(base, login, u, moi_timeout)

    for tn in cfg.get("tai_nguyen", []):
        mau = tn.get("mau", "")
        for chu, idc in (tn.get("id_cua") or {}).items():
            url = base + mau.replace("{id}", str(idc))
            ma_chu, body_chu = _tai(url, phien.get(chu), base, moi_timeout)
            if ma_chu != 200 or not body_chu:
                continue                      # chu khong lay duoc -> khong co moc so sanh
            for nguoi_khac in phien:
                if nguoi_khac == chu:
                    continue
                ma, body = _tai(url, phien.get(nguoi_khac), base, moi_timeout)
                if ma == 200 and body and body == body_chu:
                    ra.append({
                        "alert": f"IDOR/BOLA: {nguoi_khac} xem duoc tai nguyen cua {chu}",
                        "risk": "High", "confidence": "High", "cweid": "639",
                        "plugin": "kiem-idor", "nguon": "kiem-idor",
                        "url": url, "param": "id", "attack": f"id={idc} (cua {chu})",
                        "evidence": f"{nguoi_khac} nhan HTTP 200, body trung voi cua {chu}",
                        "cach_sua": ("Kiem tra quyen so huu tai nguyen theo nguoi dung dang "
                                     "nhap TRUOC khi tra ve (object-level authorization)."),
                    })
    return ra


def doc_cau_hinh(duong: str) -> dict:
    """Doc tep cau hinh IDOR. Thieu/hong -> {} (pipeline bo qua buoc IDOR)."""
    try:
        goc_an_toan = Path.cwd().resolve()
        p = Path(duong).resolve()
        p.relative_to(goc_an_toan)  # chan path traversal: chi doc trong thu muc lam viec
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
