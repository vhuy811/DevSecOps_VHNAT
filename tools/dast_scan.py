#!/usr/bin/env python3
"""
DAST - quet TOAN BO ung dung dang chay, doc lap voi SAST.

VI SAO DOI THIET KE
Truoc day ZAP chi ban vao dung endpoint ma SAST chi ra, va ket qua cua ZAP
duoc dung de GAT canh bao SAST ("ZAP khong khai thac duoc -> cho qua"). Hai
loi logic nam san trong do:
  1. DAST chi di theo SAST thi khong bao gio tim ra thu SAST bo sot - no mat
     han gia tri rieng cua minh.
  2. DAST bo sot nhieu hon SAST (can mui dung, payload trung, tham so GET...).
     Cho no quyen phu quyet nghia la moi lan no mu, mot lo hong that duoc tha.
     PR #1 da chung minh: SQL injection o /Product/Filter lot qua cong.

Thiet ke moi: SAST va DAST la HAI NGUON PHAT HIEN DOC LAP, ket qua CONG DON.
  - Danh sach endpoint lay tu ban do route (tang 3) + spider cua ZAP, khong
    lay tu SAST.
  - Moi alert muc High cua ZAP tu no du de chan.
  - Doi chieu voi SAST chi con dung de gan nhan "da khai thac duoc" -> uu tien
    sua truoc. Khong bao gio dung de bo qua mot canh bao.

TANG DAST THU HAI (G3.2): --kich-ban-loi-sqlite
  Phong do G3.1 cho thay rule SQLi 40018 cua ZAP mu voi stack ASP.NET Core +
  Microsoft.Data.Sqlite: o nguong MEDIUM no tat nhan dang loi CSDL chung chung,
  va dù co bat thi mau loi cua no khong khop thong bao cua Microsoft.Data.Sqlite
  ("SQLite Error 1: '...'"). Ngu canh WHERE Category = '...' (PR #1) vi the lot
  qua o MOI cuong do. Co --kich-ban-loi-sqlite them mot lop error-based rieng:
  voi tung endpoint trong ban do route, chen mot dau nháy va doi chieu phan hoi
  voi chu ky loi Microsoft.Data.Sqlite. Lop nay doc lap voi policy ZAP nen bat
  duoc ca ngu canh = ma khong phai day ZAP len HIGH (vi HIGH bao nham tren cac
  endpoint LIKE da tham so hoa - xem G3.1).

Chay:
    python tools/dast_scan.py --routes routes_map.json \
        --base-url http://localhost:5000 --zap http://localhost:8090 \
        --kich-ban-loi-sqlite --out reports/zap-alerts.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from correlate import CWE_ZAP_SCANNER, Zap  # noqa: E402

RISK_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}

# duong dan dac ta API ma cac framework pho bien tu phuc vu
DUONG_OPENAPI = ("/swagger/v1/swagger.json", "/openapi/v1.json", "/openapi.json",
                 "/v3/api-docs", "/api-docs", "/swagger.json", "/docs/openapi.json")

# ---------------------------------------------------------------------------
# TANG DAST THU HAI: nhan dang loi CSDL Microsoft.Data.Sqlite (G3.2)
# ---------------------------------------------------------------------------
# Chu ky rieng cho SQLite / Microsoft.Data.Sqlite, du hep de khong bao nham
# tren repo khac. Thong bao loi cua Microsoft.Data.Sqlite luon co dang
# "SQLite Error <ma>: '<chi tiet>'." nen "SQLite Error \d" la neo dang tin
# nhat; them vai mau dac trung khac cua SQLite phong truong hop wrapper doi
# dinh dang. KHONG dung cac cum chung chung ("syntax error", "SQL") de tranh
# bat nham noi dung binh thuong cua trang.
CHU_KY_SQLITE = re.compile(
    r"SQLite Error \d"
    r"|SqliteException"
    r"|Microsoft\.Data\.Sqlite"
    r"|unrecognized token"
    r"|SQL logic error",
    re.IGNORECASE,
)


def co_loi_sqlite(text: str) -> bool:
    """True neu phan hoi chua chu ky loi Microsoft.Data.Sqlite."""
    return bool(text) and CHU_KY_SQLITE.search(text) is not None


def _cung_goc(url: str, base: str) -> bool:
    """Chi cho phep goi dung muc tieu da cau hinh (cung scheme + host + cong).

    Vua la rao an toan that (ban do route la dau vao - khong de mot ban do bi
    sua tro thanh banh lai dua DAST di goi host khac), vua chan luong SSRF:
    phan tu bien doi (duong dan tu ban do route) khong the doi duoc host.
    """
    try:
        u, b = urlsplit(url), urlsplit(base)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and u.scheme == b.scheme and u.netloc == b.netloc


def _tai_trang(url: str, base: str, timeout: float) -> tuple[int | None, str]:
    """GET url (chi khi cung goc voi base), tra ve (ma_http, body). Doc ca body
    khi loi HTTP 4xx/5xx."""
    if not _cung_goc(url, base):
        return None, ""
    req = urllib.request.Request(url, headers={"User-Agent": "dast-kich-ban-sqlite"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except (URLError, OSError):
        return None, ""


def quet_loi_sqlite(routes: list[dict], base: str, moi_timeout: float = 8.0) -> list[dict]:
    """Lop error-based: voi moi endpoint kiem thu duoc, chen mot dau nháy va
    doi chieu phan hoi voi chu ky loi Microsoft.Data.Sqlite.

    `routes` la danh sach route DA PHAN TICH (main() doc ban do mot lan roi
    truyen vao - khong doc tep lan nua o day).

    Logic (error-based SQLi kinh dien):
      1. Dau vao lanh (test_seed) KHONG duoc gay loi CSDL - neu co san thi moc
         so sanh hong, bo qua endpoint do de tranh bao nham.
      2. Chen them mot dau nháy ('): neu phan hoi xuat hien loi CSDL thi gia tri
         dang duoc noi thang vao cau SQL -> SQL injection (CWE-89).
    Lop nay goi HTTP thang toi app (chi dung muc tieu base), doc lap voi ZAP.
    """
    ra: list[dict] = []
    for r in routes:
        if r.get("status") != "testable":
            continue
        seed = str(r.get("test_seed") or "a")
        path = r["url_path"]
        for p in r.get("params", []):
            lanh = f"{base}{path}?{urlencode({p: seed})}"
            _, body_lanh = _tai_trang(lanh, base, moi_timeout)
            if co_loi_sqlite(body_lanh):
                # app bao loi ngay voi dau vao lanh -> khong ket luan duoc
                continue
            payload = seed + "'"
            tan_cong = f"{base}{path}?{urlencode({p: payload})}"
            _, body = _tai_trang(tan_cong, base, moi_timeout)
            m = CHU_KY_SQLITE.search(body or "")
            if not m:
                continue
            ra.append({
                "alert": "SQL Injection (loi Microsoft.Data.Sqlite)",
                "risk": "High",
                "confidence": "High",
                "cweid": "89",
                "plugin": "kich-ban-loi-sqlite",
                "url": tan_cong,
                "param": p,
                "attack": payload,
                "evidence": (body[m.start():m.start() + 120]).strip(),
                "nguon": "kich-ban",
            })
    return ra


def nap_openapi(zap: Zap, base: str, tep: list[str]) -> list[str]:
    """Nap dac ta OpenAPI/Swagger vao ZAP de no biet moi endpoint + tham so.

    Ban do route chi doc duoc controller ASP.NET. Voi stack khac, dac ta API la
    nguon endpoint dang tin nhat - co thi dung, khong co thi con spider.
      - tep trong repo: ZAP chay trong container, workspace duoc mount o /zap/wrk
      - duong dan app tu phuc vu: thu cac duong dan quen thuoc cua framework
    """
    da_nap = []
    for f in tep:
        try:
            zap._get("/JSON/openapi/action/importFile/", file=f"/zap/wrk/{f}", target=base)
            da_nap.append(f)
        except Exception as exc:
            print(f"    (!) khong nap duoc {f}: {exc}")
    for duong in DUONG_OPENAPI:
        url = base + duong
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                d = json.loads(r.read().decode("utf-8", errors="replace"))
            if not isinstance(d, dict) or not ("openapi" in d or "swagger" in d):
                continue
            zap._get("/JSON/openapi/action/importUrl/", url=url)
            da_nap.append(url)
        except Exception:
            continue
    return da_nap


def cho(zap: Zap, view: str, scan_id: str, han: float, nhan: str) -> None:
    last = None
    while time.time() < han:
        st = zap._get(view, scanId=scan_id).get("status", "0")
        if st != last:
            print(f" {st}%", end="", flush=True)
            last = st
        if st == "100":
            print(f"  ({nhan} xong)", flush=True)
            return
        time.sleep(3)
    raise TimeoutError(f"{nhan} qua thoi gian cho phep")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--routes", default="routes_map.json")
    ap.add_argument("--base-url", default="http://localhost:5000")
    ap.add_argument("--zap", default="http://localhost:8090")
    ap.add_argument("--zap-api-key", default="")
    ap.add_argument("--timeout", type=int, default=1200,
                    help="tong so giay toi da cho spider + active scan")
    ap.add_argument("--openapi", default="",
                    help="tep dac ta OpenAPI/Swagger trong repo, cach nhau dau phay (duong dan tuong doi)")
    ap.add_argument("--out", default="reports/zap-alerts.json")
    ap.add_argument("--do-nhay", choices=["mac-dinh", "cao"], default="mac-dinh",
                    help="mac-dinh: policy goc cua ZAP (MEDIUM/MEDIUM). cao: day cac ho rule "
                         "ung voi CWE trong CWE_ZAP_SCANNER len cuong do HIGH, nguong LOW")
    ap.add_argument("--kich-ban-loi-sqlite", action="store_true",
                    help="bat lop error-based rieng cho Microsoft.Data.Sqlite (G3.2) - bat "
                         "ngu canh WHERE = '...' ma rule 40018 cua ZAP bo sot")
    ap.add_argument("--phien-moi", action="store_true",
                    help="mo phien ZAP moi truoc khi quet (xoa alert/cay Sites cu - dung khi do A/B)")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    zap = Zap(args.zap, args.zap_api_key, timeout=args.timeout)
    print(f"[*] ZAP {zap.ping()} | muc tieu {base} | do nhay {args.do_nhay}")
    bat_dau = time.time()
    han = bat_dau + args.timeout

    if args.phien_moi:
        zap._get("/JSON/core/action/newSession/", name="", overwrite="true")

    # Do nhay: policy mac dinh cua ZAP chay MEDIUM/MEDIUM. O muc do rule SQL
    # injection chi thu 6 payload boolean (bo qua nhom payload cho ngu canh
    # LIKE '%...%') va tat nhan dang loi CSDL chung chung. Xem G3.1.
    # LUU Y: chinh nay ghi vao policy cua CA phien ZAP - do A/B thi chay
    # mac-dinh truoc, cao sau.
    da_chinh: list[str] = []
    if args.do_nhay == "cao":
        for cwe in CWE_ZAP_SCANNER:
            da_chinh += zap.tune_scanners(cwe)
        print(f"[*] Da day {len(da_chinh)} rule len HIGH/LOW")

    # 1) Nap diem vao: trang goc + moi endpoint trong ban do route, kem gia tri
    #    moi. Spider chi thay trang co link toi - endpoint khong ai link toi
    #    (vi du action vua them trong PR) phai duoc nap tay tu ban do route.
    diem = [f"{base}/"]
    rp = Path(args.routes)
    cac_route = []
    if rp.is_file():
        cac_route = json.loads(rp.read_text(encoding="utf-8")).get("routes", [])
    for r in cac_route:
        if r.get("status") != "testable":
            continue
        p = r["params"][0]
        diem.append(f"{base}{r['url_path']}?{urlencode({p: r.get('test_seed') or 'a'})}")
    print(f"[*] Nap {len(diem)} diem vao tu ban do route")
    for u in diem:
        try:
            zap.access_url(u)
        except Exception as exc:  # 404/500 cua mot endpoint khong lam dung ca buoc
            print(f"    (!) {u}: {exc}")

    # 1b) Dac ta OpenAPI neu co - nguon endpoint cho stack khong phai .NET
    openapi = nap_openapi(zap, base, [f for f in args.openapi.split(",") if f.strip()])
    print(f"[*] OpenAPI: {', '.join(openapi) if openapi else 'khong co dac ta nao'}")

    timed_out = False
    # 2) Spider tu trang goc de tim them nhung gi ban do route bo sot
    print("[*] Spider", end="", flush=True)
    sid = zap._get("/JSON/spider/action/scan/", url=f"{base}/", recurse="true").get("scan", "")
    try:
        cho(zap, "/JSON/spider/view/status/", sid, han, "spider")
    except TimeoutError:
        zap._get("/JSON/spider/action/stop/", scanId=sid)
        timed_out = True
        print("\n    (!) spider qua gio - dung, di tiep voi nhung gi da co", flush=True)

    # 3) Active scan TOAN BO cay, moi rule trong policy mac dinh
    print("[*] Active scan toan bo", end="", flush=True)
    aid = zap._get("/JSON/ascan/action/scan/", url=f"{base}/", recurse="true",
                   inScopeOnly="false").get("scan", "")
    if not aid:
        print("\n[!] ZAP khong khoi tao duoc active scan")
        return 2
    try:
        cho(zap, "/JSON/ascan/view/status/", aid, han, "active scan")
    except TimeoutError:
        # Dung scan, GIU lai alert da tim duoc. Ket qua mot phan van hon la
        # khong co gi - va tep ket qua ghi ro "timed_out" de tom tat noi that.
        st = zap._get("/JSON/ascan/view/status/", scanId=aid).get("status", "?")
        zap._get("/JSON/ascan/action/stop/", scanId=aid)
        timed_out = True
        print(f"\n    (!) active scan qua gio o {st}% - dung, giu alert da co", flush=True)
        print(f"::warning::DAST chi chay duoc {st}% trong {args.timeout}s. Tang --timeout hoac "
              f"thu hep app. Ket qua la MOT PHAN.")

    # 4) Gom alert
    alerts = []
    for a in zap.alerts(base):
        alerts.append({
            "alert": a.get("alert"),
            "risk": a.get("risk"),
            "confidence": a.get("confidence"),
            "cweid": str(a.get("cweid", "")),
            "plugin": a.get("pluginId"),
            "url": a.get("url", ""),
            "param": a.get("param", ""),
            "attack": a.get("attack", ""),
            "evidence": (a.get("evidence") or "")[:200],
        })
    # bo trung (cung plugin, cung URL goc, cung tham so)
    seen, uniq = set(), []
    for a in alerts:
        k = (a["plugin"], a["url"].split("?")[0], a["param"])
        if k not in seen:
            seen.add(k)
            uniq.append(a)

    # 4b) Lop DAST thu hai: error-based cho Microsoft.Data.Sqlite (G3.2).
    #     Doc lap voi ZAP nen van chay duoc ke ca khi active scan qua gio.
    kich_ban = []
    if args.kich_ban_loi_sqlite:
        kich_ban = quet_loi_sqlite(cac_route, base)
        them = 0
        for a in kich_ban:
            k = (a["plugin"], a["url"].split("?")[0], a["param"])
            if k not in seen:
                seen.add(k)
                uniq.append(a)
                them += 1
        print(f"[*] Kich ban loi SQLite: {them} alert error-based")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"base_url": base, "scanned_urls": len(diem),
                               "openapi": openapi,
                               "do_nhay": args.do_nhay,
                               "kich_ban_loi_sqlite": args.kich_ban_loi_sqlite,
                               "rule_da_chinh": da_chinh,
                               "giay": round(time.time() - bat_dau),
                               "timed_out": timed_out,
                               "alerts": uniq}, indent=2, ensure_ascii=False),
                   encoding="utf-8")

    dem = {k: sum(1 for a in uniq if a["risk"] == k) for k in RISK_RANK}
    print(f"\n[*] {len(uniq)} alert: High {dem['High']} · Medium {dem['Medium']} · "
          f"Low {dem['Low']} · Info {dem['Informational']}")
    for a in uniq:
        if a["risk"] == "High":
            print(f"    HIGH  {a['alert']}  {a['url'].split('?')[0]}  ?{a['param']}=")
    print(f"Da ghi {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
