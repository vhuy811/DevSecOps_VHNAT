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
                "truong_user": "username", "truong_pass": "password"},
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


def dang_nhap(base: str, login: dict, user: dict, timeout: float = 8.0) -> str | None:
    """POST form dang nhap, tra ve chuoi Cookie ('sid=...; ...') hoac None."""
    url = base + login["duong_dan"]
    if not _cung_goc(url, base):
        return None
    data = urlencode({login["truong_user"]: user["ten"],
                      login["truong_pass"]: user["mat_khau"]}).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    op = urllib.request.build_opener(_KhongRedirect)
    try:
        r = op.open(req, timeout=timeout)
        raw = r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:            # 302 sau dang nhap van co Set-Cookie
        raw = e.headers.get_all("Set-Cookie") or []
    except (urllib.error.URLError, OSError):
        return None
    jar = SimpleCookie()
    for c in raw:
        try:
            jar.load(c)
        except Exception:
            pass
    if not jar:
        return None
    return "; ".join(f"{k}={m.value}" for k, m in jar.items())


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
