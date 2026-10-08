#!/usr/bin/env python3
"""
Cham diem cong cu quet tren bo do Juliet C# 1.3 cua NIST (SARD test suite #110).

Vi sao dung Juliet: bo do DOC LAP - NIST viet, khong phai nhom viet - nen tranh
duoc loi "tu viet case roi tu cham". Moi test case co ham LOI (ten chua "bad")
va ham AN TOAN (ten chua "good"), duoc viet theo nhieu "flow variant": cung mot
loi nhung du lieu di qua bien, qua ham khac, qua tep khac, qua collection, qua
ke thua... - dung nhung dang ma rule so khop mau hay gay.

Hai lenh:

  chon    Chep cac thu muc CWE can do tu ban Juliet da giai nen sang mot cho.
          python tools/cham_diem.py chon --goc <.../testcases> --cwe 89,78 --dich bench/src/testcases

  juliet  Doi chieu SARIF cua tung cong cu voi test case, ra bang diem.
          python tools/cham_diem.py juliet --goc bench/src/testcases \\
              --sarif semgrep-du-an=a.sarif --sarif codeql=b.sarif \\
              --chan "semgrep-du-an:level=error" --chan "codeql:sev>=7" \\
              --out ket-qua.json --md ket-qua.md

Cach cham (theo quy uoc cua Juliet va OWASP Benchmark):
  - Mot canh bao duoc tinh cho test case X neu no nam TRONG THAN mot ham cua X
    va CWE cua canh bao cung ho voi CWE cua X (vd CWE-22 ~ CWE-23/36).
  - Ham ten chua "bad"  -> canh bao o day la BAT DUNG (TP) cho X.
    Ham ten chua "good" -> canh bao o day la BAO NHAM (FP) cho X.
    Bien the 81 (qua lop con) de ma loi va ma an toan o TEP rieng:
    X_81_bad.cs, X_81_goodG2B.cs, X_81_goodB2G.cs (ham ben trong ten "Action")
    -> vai tro lay theo duoi ten tep.
  - Moi test case dem mot lan cho phan loi va mot lan cho phan an toan:
        ti le bat      = so case co it nhat 1 TP / tong case
        ti le bao nham = so case co it nhat 1 FP / tong case
        Youden         = ti le bat - ti le bao nham   (0 = khong hon doan mo)
  - "pipeline-chan" la hop cua cac canh bao CO QUYEN CHAN (--chan): cau tra loi
    cho cau hoi "loi da biet bi chan bao nhieu phan".
"""
from __future__ import annotations

import argparse
import itertools
import json
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path

# ho CWE: cac CWE xem nhu cung mot loai loi khi doi chieu
HO_CWE = [
    {89, 564, 943},                 # SQL injection
    {78, 77, 88},                   # OS command injection
    {79, 80, 81, 83, 84, 85, 86, 87},  # XSS
    {22, 23, 36, 73, 35},           # path traversal
    {90},                           # LDAP injection
    {643, 91},                      # XPath / XML injection
    {601},                          # open redirect
    {113, 93, 644},                 # CRLF / response splitting
    {209, 200, 497, 535, 550},      # lo thong tin qua loi
    {327, 328, 326, 916, 759, 760}, # mat ma yeu
    {330, 338, 331, 332, 336, 337}, # ngau nhien yeu
    {259, 321, 798, 547},           # khoa / mat khau viet cung
    {614, 1004, 315, 539},          # cookie
    {117, 93},                      # log injection
    {319, 311, 312},                # truyen / luu cleartext
    {470},                          # reflection khong an toan
    {502},                          # deserialization
    {611, 776},                     # XXE
    {94, 95, 96, 1336},             # chen ma / eval / template injection
    {918, 441},                     # SSRF
]
CWE_RE = re.compile(r"cwe[-_/ ]?0*(\d+)", re.I)
# X_01.cs | X_54a.cs | X_81_bad.cs / X_81_goodG2B.cs / X_81_base.cs
# Juliet Java dung y nguyen quy uoc dat ten nay, chi khac duoi tep, nen mot
# bieu thuc phuc vu ca hai bo do.
TEN_TEP_RE = re.compile(
    r"^(CWE(\d+)_[A-Za-z0-9_]+?__(.+?)_(\d{2}))(?:[a-z]|_(bad|good\w*|base))?\.(?:cs|java)$")

# nhom flow variant cua Juliet (so cuoi ten tep)
NHOM_FLOW = [
    (1, 1, "01 · cơ bản"),
    (2, 22, "02–22 · qua rẽ nhánh/vòng lặp"),
    (31, 31, "31 · qua biến trung gian"),
    (41, 45, "41–45 · qua hàm khác"),
    (51, 54, "51–54 · qua tệp khác"),
    (61, 68, "61–68 · qua giá trị trả về / mảng / trường"),
    (71, 75, "71–75 · qua collection"),
    (81, 84, "81 · qua lớp con (kế thừa)"),
]
# Nguon du lieu - lay tu ten test case that cua Juliet C# 1.3 (doc tu ket qua lan do
# dau tien, khong doan). Phan giua ten co the co tien to "Web_" / "CWE182_Web_"
# (case chay trong ung dung web) va duoi la ten sink ("_ExecuteNonQuery", "_addHeader").
NGUON = {
    "QueryString_Web": "1 · HTTP request (tham số, cookie)",
    "Params_Get_Web": "1 · HTTP request (tham số, cookie)",
    "Get_Cookies_Web": "1 · HTTP request (tham số, cookie)",
    "Connect_tcp": "2 · mạng (TCP, WebClient)",
    "Listen_tcp": "2 · mạng (TCP, WebClient)",
    "NetClient": "2 · mạng (TCP, WebClient)",
    "Database": "3 · CSDL (dữ liệu đã lưu)",
    "Environment": "4 · cục bộ (console, biến môi trường, tệp)",
    "File": "4 · cục bộ (console, biến môi trường, tệp)",
    "ReadLine": "4 · cục bộ (console, biến môi trường, tệp)",
    # Juliet Java 1.3 - 12 ho nguon, doc tu ten test case that trong bo do
    # (unittestbot/juliet-java-test-suite), khong doan. Chi 3/12 la HTTP.
    "getParameter_Servlet": "1 · HTTP request (tham số, cookie)",
    "getQueryString_Servlet": "1 · HTTP request (tham số, cookie)",
    "getCookies_Servlet": "1 · HTTP request (tham số, cookie)",
    "connect_tcp": "2 · mạng (TCP, WebClient)",
    "listen_tcp": "2 · mạng (TCP, WebClient)",
    "URLConnection": "2 · mạng (TCP, WebClient)",
    "database": "3 · CSDL (dữ liệu đã lưu)",
    "console_readLine": "4 · cục bộ (console, biến môi trường, tệp)",
    "PropertiesFile": "4 · cục bộ (console, biến môi trường, tệp)",
    "Property": "4 · cục bộ (console, biến môi trường, tệp)",
}
# CWE khong co khai niem "nguon du lieu" (mat ma, cau hinh, khoa viet cung...).
# CWE-319 co ten "connect_tcp_..." nhung o day tcp la noi GUI di, khong phai nguon.
KHONG_NGUON = {209, 259, 319, 321, 327, 328, 338, 614}
KHONG_NGUON_NHAN = "5 · không có nguồn (mật mã, cấu hình)"


def ho_cua(cwe: int) -> frozenset:
    for h in HO_CWE:
        if cwe in h:
            return frozenset(h)
    return frozenset({cwe})


def nhom_flow(so: int) -> str:
    for a, b, ten in NHOM_FLOW:
        if a <= so <= b:
            return ten
    return f"{so:02d} · khác"


def loai_nguon(cwe: int, phan_sau: str) -> tuple[str, str]:
    if cwe in KHONG_NGUON:
        return phan_sau, KHONG_NGUON_NHAN
    # Juliet goi test case chay trong ung dung web bang tien to "Web_" (C#) hoac
    # "Servlet_" (Java), co the kem "CWE182_" o truoc. Day la NOI CHAY, khong
    # phai nguon du lieu - nguon that nam ngay sau. Thieu nhanh Servlet_ thi
    # 1332/5772 case Java roi vao "chua phan loai" va bang theo nguon mat nghia.
    goc = re.sub(r"^(?:CWE\d+_)?(?:Web|Servlet)_", "", phan_sau)
    for n in sorted(NGUON, key=len, reverse=True):
        if goc.startswith(n):
            return n, NGUON[n]
    return goc, "6 · chưa phân loại"


# ------------------------------------------------------------------ doc C#
def cac_ham(src: str) -> list[tuple[str, int, int]]:
    """Tra ve [(ten_ham, dong_bat_dau, dong_ket_thuc)] - dem ngoac bo qua chuoi/chu thich."""
    ham = []
    i, n, dong = 0, len(src), 1
    ngan = []            # stack: (ten ham hoac None, dong mo)
    cho_ten = None       # ten ham vua thay, cho dau '{'
    tu = ""
    trang_thai = None    # None | 'cmt1' | 'cmtn' | 'str' | 'vstr' | 'chr'
    dau_dong_ham = 0
    # Duoi chu ky: C# co ": base(...)", Java co "throws A, B". Thieu nhanh throws
    # thi KHONG doc duoc ham nao trong tep Juliet Java (da do: 0/5 ham), va moi
    # canh bao se khong gan duoc vai tro bad/good -> bang ket qua ra 0% tron,
    # nhin y nhu "rule khong bat duoc gi". Day la mot cach sai im lang.
    sig_re = re.compile(
        r"(?:public|private|protected|internal|static|override|virtual|async|sealed|new"
        r"|final|abstract|synchronized|native|default)"
        r"[\w<>\[\],\s.?]*?\b(\w+)\s*\([^;{}()]*(?:\([^()]*\)[^;{}()]*)*\)\s*"
        r"(?::\s*base\([^)]*\)\s*|throws\s+[\w.<>,\s]+)?$")
    dem = []             # ky tu tu dau cau lenh hien tai
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "\n":
            dong += 1
        if trang_thai == "cmt1":
            if c == "\n":
                trang_thai = None
            i += 1; continue
        if trang_thai == "cmtn":
            if c == "*" and nxt == "/":
                trang_thai = None; i += 2; continue
            i += 1; continue
        if trang_thai == "str":
            if c == "\\":
                i += 2; continue
            if c == '"':
                trang_thai = None
            i += 1; continue
        if trang_thai == "vstr":
            if c == '"' and nxt == '"':
                i += 2; continue
            if c == '"':
                trang_thai = None
            i += 1; continue
        if trang_thai == "chr":
            if c == "\\":
                i += 2; continue
            if c == "'":
                trang_thai = None
            i += 1; continue
        if c == "/" and nxt == "/":
            trang_thai = "cmt1"; i += 2; continue
        if c == "/" and nxt == "*":
            trang_thai = "cmtn"; i += 2; continue
        if c == "@" and nxt == '"':
            trang_thai = "vstr"; dem.append('""'); i += 2; continue
        if c == "$" and nxt == '"':
            trang_thai = "str"; dem.append('""'); i += 2; continue
        if c == '"':
            trang_thai = "str"; dem.append('""'); i += 1; continue
        if c == "'":
            trang_thai = "chr"; i += 1; continue
        if c == "{":
            cau = "".join(dem).strip()
            m = sig_re.search(cau)
            ten = m.group(1) if m and m.group(1) not in ("if", "for", "foreach", "while", "switch", "catch", "using", "lock", "fixed") else None
            ngan.append((ten, dong))
            dem = []
            i += 1; continue
        if c == "}":
            if ngan:
                ten, bd = ngan.pop()
                if ten:
                    ham.append((ten, bd, dong))
            dem = []
            i += 1; continue
        if c == ";":
            dem = []
            i += 1; continue
        dem.append(c)
        i += 1
    return ham


def ham_chua(ds: list[tuple[str, int, int]], line: int) -> str | None:
    """Ham trong cung chua dong nay (ham long nhau: lay ham ngan nhat)."""
    tot = None
    for ten, a, b in ds:
        if a <= line <= b and (tot is None or (b - a) < (tot[2] - tot[1])):
            tot = (ten, a, b)
    return tot[0] if tot else None


def vai_tro_tep(duoi: str | None) -> str | None:
    """Duoi ten tep bien the 81: 'bad' | 'goodG2B' | 'goodB2G' | 'base'."""
    if not duoi or duoi == "base":
        return None
    return "bad" if duoi == "bad" else "good"


def vai_tro(ten: str | None) -> str | None:
    if not ten:
        return None
    t = ten.lower()
    if "bad" in t:
        return "bad"
    if "good" in t:
        return "good"
    return None


# ------------------------------------------------------------------ Juliet
def lap_chi_muc(goc: Path) -> tuple[dict, dict]:
    """case_id -> thong tin; ten_tep -> (case_id, danh sach ham, vai tro theo ten tep)."""
    cases, tep = {}, {}
    ds = sorted(list(goc.rglob("*.cs")) + list(goc.rglob("*.java")))
    for p in ds:
        m = TEN_TEP_RE.match(p.name)
        if not m:
            continue
        case_id, cwe, phan_sau, flow = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        nguon, kieu = loai_nguon(cwe, phan_sau)
        cases.setdefault(case_id, {"cwe": cwe, "flow": flow, "nhom_flow": nhom_flow(flow),
                                   "nguon": nguon, "kieu_nguon": kieu, "tep": []})
        cases[case_id]["tep"].append(p.name)
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        tep[p.name] = (case_id, cac_ham(src), vai_tro_tep(m.group(5)))
    return cases, tep


def doc_sarif(path: Path) -> list[dict]:
    d = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for run in d.get("runs", []):
        tool = run.get("tool", {})
        rules = {}
        for comp in [tool.get("driver", {})] + list(tool.get("extensions", []) or []):
            for r in comp.get("rules", []) or []:
                rules[r.get("id")] = r
        for res in run.get("results", []):
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id", "")
            rule = rules.get(rid, {})
            props = rule.get("properties", {}) or {}
            chu = json.dumps(props.get("tags", []), ensure_ascii=False) + " " + json.dumps(props.get("cwe", ""), ensure_ascii=False)
            cwes = {int(x) for x in CWE_RE.findall(chu)}
            if not cwes:
                cwes = {int(x) for x in CWE_RE.findall(res.get("message", {}).get("text", ""))}
            try:
                sev = float(props.get("security-severity", "") or 0)
            except ValueError:
                sev = 0.0
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level", "warning")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = int((loc.get("region") or {}).get("startLine", 0) or 0)
            out.append({"rule": rid.rsplit(".", 1)[-1], "cwes": cwes, "sev": sev, "level": level,
                        "file": Path(uri).name, "uri": uri, "line": line,
                        "suppressed": bool(res.get("suppressions"))})
    return out


def dieu_kien_chan(spec: str):
    """'level=error' | 'sev>=7' | 'sev>=4&!cwe=643,91' -> ham kiem tra ket qua.

    Phan '&!cwe=...' loai cac CWE do khoi tap canh bao CO QUYEN CHAN (van hien
    trong bao cao, chi la khong chan merge). Dung cho truy van cua cong cu ngoai
    ma do duoc la bao nham cao tren mot loai cu the - giong cach do an da ha muc
    nhom rule hinh dang cua chinh no o G2.3b.
    """
    bo_cwe: set[int] = set()
    if "&!cwe=" in spec:
        spec, _, ds = spec.partition("&!cwe=")
        bo_cwe = {int(x) for x in ds.split(",") if x.strip()}

    def loc(f):
        if not bo_cwe:
            return f
        return lambda r: f(r) and not (r["cwes"] & bo_cwe)

    if spec.startswith("level="):
        want = spec.split("=", 1)[1]
        return loc(lambda r: r["level"] == want)
    m = re.match(r"sev>=([\d.]+)$", spec)
    if m:
        nguong = float(m.group(1))
        return loc(lambda r: r["sev"] >= nguong)
    raise SystemExit(f"--chan khong hieu: {spec}")


def cham(cases: dict, tep: dict, ket_qua: dict[str, list[dict]]) -> dict:
    """ket_qua: ten_cong_cu -> danh sach canh bao. Tra ve {cong_cu: {case_id: {'tp':bool,'fp':bool}}}."""
    diem = {}
    for cc, ds in ket_qua.items():
        d = {cid: {"tp": False, "fp": False} for cid in cases}
        khong_gan = 0
        for r in ds:
            t = tep.get(r["file"])
            if not t:
                khong_gan += 1
                continue
            cid, hams, vt_tep = t
            # ham ten bad*/good* quyet dinh truoc; khong co thi theo ten tep (bien the 81)
            vt = vai_tro(ham_chua(hams, r["line"])) or vt_tep
            if vt is None:
                continue
            if not (r["cwes"] and ho_cua(cases[cid]["cwe"]) & set().union(*(ho_cua(c) for c in r["cwes"]))):
                continue
            d[cid]["tp" if vt == "bad" else "fp"] = True
        diem[cc] = d
        diem[cc]["__khong_gan__"] = khong_gan
    return diem


def tong_hop(cases: dict, diem: dict, theo: str) -> dict:
    """Gom theo mot thuoc tinh cua case ('cwe' | 'nhom_flow' | 'kieu_nguon')."""
    bang = defaultdict(lambda: defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0}))
    for cc, d in diem.items():
        for cid, info in cases.items():
            k = f"CWE-{info['cwe']}" if theo == "cwe" else info[theo]
            o = bang[k][cc]
            o["n"] += 1
            o["tp"] += d[cid]["tp"]
            o["fp"] += d[cid]["fp"]
    return bang


def ti_le(o: dict) -> tuple[float, float, float]:
    tpr = o["tp"] / o["n"] if o["n"] else 0.0
    fpr = o["fp"] / o["n"] if o["n"] else 0.0
    return tpr, fpr, tpr - fpr


def md_bang(ten: str, bang: dict, cong_cu: list[str]) -> str:
    dong = [f"#### {ten}", "", "| Nhóm | Số case | " + " | ".join(f"{c} (bắt / nhầm)" for c in cong_cu) + " |",
            "|---|---|" + "---|" * len(cong_cu)]
    for k in sorted(bang):
        n = next(iter(bang[k].values()))["n"]
        o = []
        for c in cong_cu:
            tpr, fpr, _ = ti_le(bang[k][c])
            o.append(f"{tpr:.0%} / {fpr:.0%}")
        dong.append(f"| {k} | {n} | " + " | ".join(o) + " |")
    return "\n".join(dong) + "\n"


# ------------------------------------------------- bo do BenchProctor (CSV)
# Khac Juliet o CHO GAN NHAN: Juliet gan nhan bang ten ham (bad/good) nam ngay
# trong ma nguon; BenchProctor giu nhan BEN NGOAI, trong mot tep CSV, va ma
# nguon khong he co dau vet nhan nao (khong comment, khong tag CWE, ten tep
# khong noi gi). Nho vay khong the "bat duoc" bang cach doc nhan.
#
# Don vi tinh la TEP, khong phai dong: moi benchmark_test_NNNNN.py la mot case
# doc lap chua dung mot cap nguon -> sink. CSV khong co cot so dong.
BENCH_TEN_RE = re.compile(r"benchmark_test_(\d{5,})\.\w+")
BENCH_KHONG_PHAI_CASE = {"app_runtime.py", "urls.py", "__init__.py"}


def doc_dap_an(csv_path: Path) -> dict:
    """Doc answer key CSV -> {ten_case: (category, co_loi, cwe)}.

    Tep la CRLF; khong strip \r thi int(cwe) se no.
    """
    ra = {}
    for dong in csv_path.read_text(encoding="utf-8").splitlines():
        d = dong.strip().replace("\r", "")
        if not d or d.startswith("#"):
            continue
        p = [x.strip() for x in d.split(",")]
        if len(p) < 4 or not p[3].isdigit():
            continue
        ra[p[0]] = (p[1], p[2].lower() == "true", int(p[3]))
    return ra


def lap_chi_muc_bench(bo: list[tuple[str, Path]]) -> tuple[dict, dict]:
    """bo: [(ten_khung, thu_muc_khung)] -> (cases, tep).

    cases[case_id] = {cwe, category, co_loi, khung, tep:[...]}
    tep[ten_tep] = (case_id, co_loi)   # khong co danh sach ham: don vi la tep
    """
    cases, tep = {}, {}
    for khung, d in bo:
        ds = sorted(d.glob("expectedresults-*.csv"))
        if not ds:
            raise SystemExit(f"Khong tim thay expectedresults-*.csv trong {d}")
        dap_an = doc_dap_an(ds[0])
        td = d / "testcode"
        thieu = []
        for ten, (cat, co_loi, cwe) in dap_an.items():
            m = re.search(r"(\d+)$", ten)
            if not m:
                continue
            ten_tep = f"benchmark_test_{int(m.group(1)):05d}.py"
            if not (td / ten_tep).is_file():
                thieu.append(ten_tep)
                continue
            cid = f"{khung}/{ten}"
            cases[cid] = {"cwe": cwe, "category": cat, "co_loi": co_loi,
                          "khung": khung, "tep": [ten_tep]}
            tep[f"{khung}/{ten_tep}"] = (cid, co_loi)
        mo_coi = [f.name for f in td.glob("*.py")
                  if f.name not in BENCH_KHONG_PHAI_CASE
                  and f"{khung}/{f.name}" not in tep]
        print(f"  {khung}: {len(dap_an)} case trong CSV, {sum(1 for c in cases if c.startswith(khung + '/'))} "
              f"gan duoc tep, {len(thieu)} thieu tep, {len(mo_coi)} tep mo coi")
        if thieu or mo_coi:
            # Khong im lang: lech giua CSV va thu muc lam sai mau so.
            print(f"    CANH BAO thieu={thieu[:3]} mo_coi={mo_coi[:3]}")
    return cases, tep


def cham_bench(cases: dict, tep: dict, ket_qua: dict[str, list[dict]]) -> dict:
    """Cham theo tep. Mot case duoc coi la BI BAO neu co it nhat mot canh bao
    tren tep do VA CWE cua canh bao cung ho voi CWE mong doi cua case.

    Doi chieu CWE la co y: khong doi chieu thi mot rule bao bua moi tep cung
    duoc diem cao. Doi chieu theo HO (ho_cua) chu khong theo so chinh xac, vi
    corpus gop path traversal vao CWE-22 trong khi rule cua du an co the phat
    CWE-23 hay CWE-36 - cung mot lo hong, khac cach danh so.
    """
    diem = {}
    for cc, ds in ket_qua.items():
        d = {cid: {"tp": False, "fp": False} for cid in cases}
        khong_gan = 0
        for r in ds:
            # uri trong SARIF chua ca ten khung: .../flask/testcode/benchmark_test_00116.py
            m = BENCH_TEN_RE.search(r.get("uri") or r["file"])
            if not m:
                khong_gan += 1
                continue
            khung = None
            for k in ("flask", "fastapi", "django"):
                if f"/{k}/" in (r.get("uri") or "") or (r.get("uri") or "").startswith(k + "/"):
                    khung = k
                    break
            khoa = f"{khung}/benchmark_test_{int(m.group(1)):05d}.py"
            t = tep.get(khoa)
            if not t:
                khong_gan += 1
                continue
            cid, co_loi = t
            cwe_case = cases[cid]["cwe"]
            if not (r["cwes"] and ho_cua(cwe_case) & set().union(*(ho_cua(c) for c in r["cwes"]))):
                continue
            d[cid]["tp" if co_loi else "fp"] = True
        diem[cc] = d
        diem[cc]["__khong_gan__"] = khong_gan
    return diem


def tong_hop_bench(cases: dict, diem: dict, theo: str) -> dict:
    bang = defaultdict(lambda: defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0, "co_loi": 0, "sach": 0}))
    for cc, d in diem.items():
        for cid, info in cases.items():
            k = f"CWE-{info['cwe']}" if theo == "cwe" else str(info[theo])
            o = bang[k][cc]
            o["n"] += 1
            o["co_loi"] += info["co_loi"]
            o["sach"] += (not info["co_loi"])
            o["tp"] += d[cid]["tp"]
            o["fp"] += d[cid]["fp"]
    return bang


def ti_le_bench(o: dict) -> tuple[float, float, float]:
    """TPR tren so case CO LOI, FPR tren so case SACH - khac Juliet, noi moi
    case co ca ham bad lan ham good nen mau so la toan bo case."""
    tpr = o["tp"] / o["co_loi"] if o["co_loi"] else 0.0
    fpr = o["fp"] / o["sach"] if o["sach"] else 0.0
    return tpr, fpr, tpr - fpr


def md_bang_bench(ten: str, bang: dict, cong_cu: list[str]) -> str:
    dong = [f"#### {ten}", "",
            "| Nhóm | Case | Có lỗi | Sạch | " + " | ".join(f"{c} (bắt / nhầm)" for c in cong_cu) + " |",
            "|---|---|---|---|" + "---|" * len(cong_cu)]
    for k in sorted(bang):
        b = bang[k]
        m = next(iter(b.values()))
        o = []
        for c in cong_cu:
            tpr, fpr, _ = ti_le_bench(b[c])
            o.append(f"{tpr:.0%} / {fpr:.0%}")
        dong.append(f"| {k} | {m['n']} | {m['co_loi']} | {m['sach']} | " + " | ".join(o) + " |")
    return "\n".join(dong) + "\n"


# --------------------------------------------------------------- do nguong
# Khong gian nguong cua cong chan. Moi truc = mot cong cu, moi muc = tap dieu
# kien duoc hop lai. "-" nghia la khong cho cong cu do quyen chan.
#
# Vi sao lam bang liet ke het thay vi chon tay: nguong hien tai (Semgrep ERROR
# + CodeQL-local medium) la mot lua chon co ly nhung chua bao gio duoc dat canh
# 80 lua chon con lai. Youden cua mot to hop khong suy ra duoc tu Youden tung
# cong cu, vi hai cong cu bat trung nhau o phan nao thi phan do khong cong don.
# Phai do.
TRUC_NGUONG = {
    "semgrep-du-an":     [("-", []), ("E", ["level=error"]),
                          ("E+W", ["level=error", "level=warning"])],
    "semgrep-cong-dong": [("-", []), ("E", ["level=error"]),
                          ("E+W", ["level=error", "level=warning"])],
    # Muc "med-643": medium nhung bo CWE-643 khoi quyen chan. Phong do #26:
    # codeql-local bat CWE-643 76% va bao nham cung 76% - toan bo 5.2% bao nham
    # cua cong chan den tu day. Trong khi dso-taint-xpathi cua du an bat CWE-643
    # 49% voi 0% bao nham, nen bo quyen chan cua CodeQL o rieng loai nay mat rat
    # it do phu. Co mat trong bang de do, khong phai de mac dinh.
    "codeql":            [("-", []), ("high", ["sev>=7"]), ("medium", ["sev>=4"]),
                          ("med-643", ["sev>=4&!cwe=643"])],
    "codeql-local":      [("-", []), ("high", ["sev>=7"]), ("medium", ["sev>=4"]),
                          ("med-643", ["sev>=4&!cwe=643"])],
}


def nhan_dang_chay(chan: list[str]) -> dict:
    """Suy ra nhan cua nguong DANG CHAY tu chinh cac --chan duoc truyen vao.

    Truoc day nhan nay viet cung trong ma. Doi nguong o workflow ma quen sua o
    day thi bang xep hang danh dau sai dong - bao cao noi mot dieu khong dung,
    va do la thu te nhat mot bo do co the lam. Suy ra thi khong the lech.

    Muc nao khong khop danh sach trong TRUC_NGUONG thi ghi "?" - noi thang la
    khong dinh vi duoc, hon la danh dau bua mot dong.
    """
    gom: dict[str, set[str]] = {}
    for spec in chan:
        m = re.match(r"^(?:(?P<nhom>[\w.-]+)=)?(?P<ten>[\w.-]+):(?P<dk>.+)$", spec)
        if not m or (m.group("nhom") or "") != "pipeline-hien-tai":
            continue
        gom.setdefault(m.group("ten"), set()).add(m.group("dk"))
    return {tool: next((ten for ten, dks in muc if set(dks) == gom.get(tool, set())), "?")
            for tool, muc in TRUC_NGUONG.items()}


def quet_nguong(cases: dict, tep: dict, ket_qua: dict[str, list[dict]],
                hien_tai: dict | None = None, cham_fn=None) -> str:
    """Do MOI to hop nguong va xep hang theo Youden.

    tp cua mot to hop = co canh bao nao cua to hop do roi vao ham bad; fp =
    roi vao ham good. Vi to hop la HOP cua cac tap canh bao, khong the suy ra
    bang cong tru tu so cua tung cong cu - nen moi to hop duoc cham lai that.
    """
    truc = {k: v for k, v in TRUC_NGUONG.items() if k in ket_qua}
    if not truc:
        return ""
    ten_truc = list(truc)

    ds = []
    for chon in itertools.product(*(truc[k] for k in ten_truc)):
        nhan = {k: c[0] for k, c in zip(ten_truc, chon)}
        canh_bao = []
        for k, (_, dks) in zip(ten_truc, chon):
            for dk in dks:
                f = dieu_kien_chan(dk)
                canh_bao.extend(r for r in ket_qua[k] if f(r))
        if not canh_bao:
            continue
        d = (cham_fn or cham)(cases, tep, {"x": canh_bao})["x"]
        d.pop("__khong_gan__", None)
        o = {"n": len(cases), "tp": sum(v["tp"] for v in d.values()),
             "fp": sum(v["fp"] for v in d.values())}
        tpr, fpr, j = ti_le(o)
        ds.append({"nhan": nhan, "bat": tpr, "nham": fpr, "youden": j,
                   "canh_bao": len(canh_bao)})

    # Hoa Youden thi uu tien to hop bao nham THAP hon: mot cong chan hay chan
    # oan se bi nguoi dung tat di hoac xin ngoai le hang loat, luc do no khong
    # con chan gi nua. Bat it hon mot it de doi lay long tin thi con giu duoc cong.
    ds.sort(key=lambda x: (-x["youden"], x["nham"]))
    def la_ht(n: dict) -> bool:
        if hien_tai is None:
            return False
        return all(n[k] == hien_tai.get(k, "-") for k in ten_truc)

    # In 20 dong dau, cong them dong cua nguong dang chay neu no nam ngoai 20.
    # Do het 143 to hop nhung in het thi khong ai doc, va 120 dong duoi cung
    # chi de chung minh chung kem hon - khong can nhin tung dong.
    GIOI_HAN = 20
    hien = [i for i, x in enumerate(ds) if la_ht(x["nhan"])]
    chon = list(range(min(GIOI_HAN, len(ds))))
    them = [i for i in hien if i not in chon]

    md = [f"#### Dò ngưỡng — đo {len(ds)} tổ hợp, xếp theo Youden"
          + (f" (hiện {len(chon) + len(them)} dòng đầu)" if len(ds) > len(chon) + len(them) else ""), "",
          "| # | " + " | ".join(ten_truc) + " | Tỉ lệ bắt | Tỉ lệ báo nhầm | Youden |",
          "|---|" + "---|" * (len(ten_truc) + 3)]

    def dong(i: int) -> str:
        x = ds[i]
        dau = " **← đang dùng**" if la_ht(x["nhan"]) else ""
        o = " | ".join(x["nhan"][k] for k in ten_truc)
        return (f"| {i + 1} | {o} | {x['bat']:.1%} | {x['nham']:.1%} "
                f"| {x['youden']:+.3f}{dau} |")

    for i in chon:
        md.append(dong(i))
    for i in them:
        md.append("| … | " + " | ".join("" for _ in ten_truc) + " |  |  |  |")
        md.append(dong(i))
    md += ["",
           "> Mỗi trục là một công cụ; `-` = công cụ đó không có quyền chặn. "
           "`E` / `E+W` = mức severity của Semgrep được tính; `high` = CodeQL "
           "security-severity ≥ 7, `medium` = ≥ 4. "
           "Youden = tỉ lệ bắt − tỉ lệ báo nhầm, nên nó cân đúng hai vế "
           "*đừng để lỗi vẫn pass* và *không lỗi vẫn block*.", ""]
    return "\n".join(md)


def lenh_juliet(a: argparse.Namespace) -> int:
    goc = Path(a.goc)
    cases, tep = lap_chi_muc(goc)
    if not cases:
        print(f"Khong tim thay test case Juliet nao trong {goc}")
        return 2
    ket_qua = {}
    for s in a.sarif:
        ten, duong = s.split("=", 1)
        if not Path(duong).is_file():
            print(f"::warning::Thieu SARIF cua {ten}: {duong} - bo qua cong cu nay")
            continue
        ket_qua[ten] = doc_sarif(Path(duong))
    # Nhom "pipeline": hop cac canh bao CO QUYEN CHAN. Cu phap --chan:
    #   [ten-nhom=]cong-cu:dieu-kien     vd  pipeline-hien-tai=semgrep-du-an:level=error
    # Nhieu --chan cung ten nhom thi gop lai (hop).
    nhom = {}
    for spec in a.chan:
        m = re.match(r"^(?:(?P<nhom>[\w.-]+)=)?(?P<ten>[\w.-]+):(?P<dk>.+)$", spec)
        if not m:
            raise SystemExit(f"--chan khong hieu: {spec}")
        ten_nhom, ten, dk = m.group("nhom") or "pipeline-chan", m.group("ten"), m.group("dk")
        nhom.setdefault(ten_nhom, [])
        if ten in ket_qua:
            f = dieu_kien_chan(dk)
            nhom[ten_nhom].extend(r for r in ket_qua[ten] if f(r))
    ket_qua.update(nhom)

    diem = cham(cases, tep, ket_qua)
    cong_cu = list(ket_qua)
    tong = {}
    for cc in cong_cu:
        o = {"n": len(cases), "tp": sum(v["tp"] for k, v in diem[cc].items() if k != "__khong_gan__"),
             "fp": sum(v["fp"] for k, v in diem[cc].items() if k != "__khong_gan__")}
        tpr, fpr, j = ti_le(o)
        tong[cc] = {**o, "ti_le_bat": round(tpr, 4), "ti_le_bao_nham": round(fpr, 4), "youden": round(j, 4),
                    "canh_bao": len(ket_qua[cc]), "canh_bao_ngoai_bo_do": diem[cc]["__khong_gan__"]}
        diem[cc].pop("__khong_gan__")

    bang_cwe = tong_hop(cases, diem, "cwe")
    bang_flow = tong_hop(cases, diem, "nhom_flow")
    bang_nguon = tong_hop(cases, diem, "kieu_nguon")

    out = {"bo_do": a.ten_bo_do, "so_case": len(cases), "tong": tong,
           "theo_cwe": bang_cwe, "theo_flow": bang_flow, "theo_nguon": bang_nguon,
           "case": {cid: {**info, "ket_qua": {cc: diem[cc][cid] for cc in cong_cu}} for cid, info in cases.items()}}
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1, default=list), encoding="utf-8")

    # Ten bo do lay tu --ten-bo-do. Truoc day ghi cung "Juliet C# 1.3" nen ban
    # chay tren Juliet JAVA in ra dong "Juliet C# 1.3" - bao cao noi mot dieu
    # khong dung ve chinh no.
    md = [f"### Phòng đo — {a.ten_bo_do}, {len(cases)} test case", "",
          "| Công cụ | Tỉ lệ bắt | Tỉ lệ báo nhầm | Youden | Cảnh báo | Không gắn được case |",
          "|---|---|---|---|---|---|"]
    for cc in cong_cu:
        t = tong[cc]
        md.append(f"| {cc} | {t['ti_le_bat']:.1%} | {t['ti_le_bao_nham']:.1%} | {t['youden']:+.2f} "
                  f"| {t['canh_bao']} | {t['canh_bao_ngoai_bo_do']} |")
    md.append("")
    md.append("> Youden = tỉ lệ bắt − tỉ lệ báo nhầm; 0 nghĩa là không hơn đoán mò. "
              "`pipeline-*` = chỉ tính cảnh báo có quyền chặn merge. "
              "*Không gắn được case* = cảnh báo nằm ngoài tệp test case (tệp hỗ trợ của Juliet) — "
              "số này lớn bất thường là dấu hiệu bộ chấm đọc sai tên tệp.\n")
    md.append(md_bang("Theo CWE", bang_cwe, cong_cu))
    md.append(md_bang("Theo đường đi của dữ liệu (flow variant)", bang_flow, cong_cu))
    md.append(md_bang("Theo loại nguồn dữ liệu", bang_nguon, cong_cu))
    if getattr(a, "do_nguong", False):
        ht = nhan_dang_chay(a.chan)
        bang = quet_nguong(cases, tep, {k: v for k, v in ket_qua.items() if k in TRUC_NGUONG}, ht)
        if bang:
            md.append(bang)
    text = "\n".join(md)
    if a.md:
        Path(a.md).write_text(text, encoding="utf-8")
    print(text)
    return 0


def lenh_bench(a: argparse.Namespace) -> int:
    """Cham tren bo do dang BenchProctor: answer key CSV + mot tep mot case."""
    bo = []
    for s in a.bo:
        ten, _, duong = s.partition("=")
        bo.append((ten, Path(duong)))
    print(f"[*] {len(bo)} khung: {', '.join(t for t, _ in bo)}")
    cases, tep = lap_chi_muc_bench(bo)
    if not cases:
        print("Khong gan duoc case nao")
        return 2
    co_loi = sum(1 for c in cases.values() if c["co_loi"])
    print(f"[*] {len(cases)} case: {co_loi} co loi, {len(cases) - co_loi} sach")

    ket_qua = {}
    for s in a.sarif:
        ten, duong = s.split("=", 1)
        if not Path(duong).is_file():
            print(f"::warning::Thieu SARIF cua {ten}: {duong} - bo qua cong cu nay")
            continue
        ket_qua[ten] = doc_sarif(Path(duong))

    nhom = {}
    for spec in a.chan:
        m = re.match(r"^(?:(?P<nhom>[\w.-]+)=)?(?P<ten>[\w.-]+):(?P<dk>.+)$", spec)
        if not m:
            raise SystemExit(f"--chan khong hieu: {spec}")
        tn, ten, dk = m.group("nhom") or "pipeline-chan", m.group("ten"), m.group("dk")
        nhom.setdefault(tn, [])
        if ten in ket_qua:
            f = dieu_kien_chan(dk)
            nhom[tn].extend(r for r in ket_qua[ten] if f(r))
    ket_qua.update(nhom)

    diem = cham_bench(cases, tep, ket_qua)
    cong_cu = list(ket_qua)
    tong = {}
    for cc in cong_cu:
        d = diem[cc]
        kg = d.pop("__khong_gan__", 0)
        o = {"n": len(cases), "co_loi": co_loi, "sach": len(cases) - co_loi,
             "tp": sum(v["tp"] for v in d.values()), "fp": sum(v["fp"] for v in d.values())}
        tpr, fpr, j = ti_le_bench(o)
        tong[cc] = {**o, "ti_le_bat": round(tpr, 4), "ti_le_bao_nham": round(fpr, 4),
                    "youden": round(j, 4), "canh_bao": len(ket_qua[cc]),
                    "canh_bao_ngoai_bo_do": kg}

    md = [f"### Phòng đo Python — BenchProctor quicktest, {len(cases)} test case "
          f"({co_loi} có lỗi / {len(cases) - co_loi} sạch)", "",
          "| Công cụ | Tỉ lệ bắt | Tỉ lệ báo nhầm | Youden | Cảnh báo | Không gắn được case |",
          "|---|---|---|---|---|---|"]
    for cc in cong_cu:
        x = tong[cc]
        md.append(f"| {cc} | {x['ti_le_bat']:.1%} | {x['ti_le_bao_nham']:.1%} | {x['youden']:+.2f} "
                  f"| {x['canh_bao']} | {x['canh_bao_ngoai_bo_do']} |")
    md += ["",
           "> Khác phòng đo Juliet ở mẫu số: Juliet mỗi case có cả hàm `bad` lẫn hàm `good` "
           "nên mẫu số của cả hai tỉ lệ là toàn bộ case. BenchProctor mỗi case là **một tệp "
           "riêng**, hoặc có lỗi hoặc sạch — nên tỉ lệ bắt tính trên số case có lỗi và tỉ lệ "
           "báo nhầm tính trên số case sạch. Nhãn nằm ngoài mã nguồn (trong CSV), mã nguồn "
           "không có dấu vết nhãn nào.", ""]
    md.append(md_bang_bench("Theo CWE", tong_hop_bench(cases, diem, "cwe"), cong_cu))
    md.append(md_bang_bench("Theo khung web", tong_hop_bench(cases, diem, "khung"), cong_cu))

    if getattr(a, "do_nguong", False):
        ht = nhan_dang_chay(a.chan)
        bang = quet_nguong(cases, tep, {k: v for k, v in ket_qua.items() if k in TRUC_NGUONG},
                           ht, cham_fn=cham_bench)
        if bang:
            md.append(bang)

    text = "\n".join(md)
    if a.md:
        Path(a.md).write_text(text, encoding="utf-8")
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(
            {"bo_do": "BenchProctor Python quicktest", "so_case": len(cases), "tong": tong,
             "theo_cwe": tong_hop_bench(cases, diem, "cwe"),
             "case": {cid: {**i, "ket_qua": {cc: diem[cc][cid] for cc in cong_cu}}
                      for cid, i in cases.items()}},
            ensure_ascii=False, indent=1, default=list), encoding="utf-8")
    print(text)
    return 0


def lenh_chon(a: argparse.Namespace) -> int:
    goc, dich = Path(a.goc), Path(a.dich)
    muon = {int(x) for x in a.cwe.split(",") if x.strip()}
    dich.mkdir(parents=True, exist_ok=True)
    so = 0
    # Hai bo do, hai bo cuc thu muc: Juliet C# dat "CWE89_SQL_Injection/", ban
    # mirror cua Juliet Java dat "juliet-cwe89/src/main/java/...".
    RE_THU_MUC = re.compile(r"^(?:CWE(\d+)_|juliet-cwe(\d+)$)", re.I)
    for d in sorted(goc.iterdir()):
        m = RE_THU_MUC.match(d.name)
        if d.is_dir() and m and int(m.group(1) or m.group(2)) in muon:
            shutil.copytree(d, dich / d.name, dirs_exist_ok=True)
            n = sum(1 for e in ("*.cs", "*.java") for _ in (dich / d.name).rglob(e))
            print(f"  {d.name}: {n} tep")
            so += n
    co = {int(m.group(1) or m.group(2)) for d in goc.iterdir()
          if (m := RE_THU_MUC.match(d.name))}
    thieu = sorted(muon - co)
    if thieu:
        print(f"Juliet C# khong co cac CWE: {', '.join(map(str, thieu))}")
    print(f"Tong: {so} tep ma nguon")
    return 0


def lenh_mau(a: argparse.Namespace) -> int:
    """In ham Bad VA ham Good (bien the 01) cua mot test case moi CWE ra Markdown.

    Dung de doc sink THAT cua nhung CWE chua cong cu nao bat truoc khi viet rule,
    thay vi doan. Cu phap --cwe: "23,36,89:CommandText" (sau dau ':' la chuoi
    phai co trong ten tep, de chon dung bien the).

    VI SAO PHAI IN CA HAM GOOD
    Doc mot minh ham Bad chi tra loi duoc nua cau hoi: "bat cai gi". Nua con lai -
    "khong duoc bat cai gi" - nam trong ham Good, va do moi la nua de viet sai.
    Juliet co hai kieu Good:
      goodG2B = nguon an toan  + sink cu   -> cho biet nguon bien mat the nao
      goodB2G = nguon cu       + sink an toan -> cho biet SANITIZER co hinh dang gi
    Viet rule chi theo ham Bad thi rat de ra mot rule bat dung 100% va bao nham
    100% - dung cai da xay ra voi nhom rule hinh dang o G2.3b. Uu tien in goodB2G
    vi no giu nguyen nguon, nen khac biet duy nhat so voi Bad chinh la cho can
    khai bao sanitizer.
    """
    goc = Path(a.goc)
    uu_tien = ("QueryString_Web", "Params_Get_Web", "Get_Cookies_Web")
    out = ["### Mã mẫu — hàm `Bad` (biến thể 01) của các CWE chưa công cụ nào bắt", ""]
    for tok in [x.strip() for x in a.cwe.split(",") if x.strip()]:
        cwe, _, loc = tok.partition(":")
        tep = sorted(p for p in goc.glob(f"CWE{cwe}_*/**/*_01.cs") if loc in p.name)
        if not tep:
            out.append(f"- CWE-{tok}: không có tệp mẫu\n")
            continue
        chon = next((p for u in uu_tien for p in tep if u in p.name), tep[0])
        src = chon.read_text(encoding="utf-8", errors="replace")
        dong = src.splitlines()
        hams = [h for h in cac_ham(src) if vai_tro(h[0]) == "bad"]
        if not hams:
            out.append(f"- CWE-{tok}: không tìm thấy hàm bad trong `{chon.name}`\n")
            continue
        def than_ham(h: tuple[str, int, int]) -> str:
            _, a0, b0 = h
            s = "\n".join(dong[max(0, a0 - 2):b0])
            return s if len(s) <= 4000 else s[:4000] + "\n// ... (cat bot)"

        ten, _, _ = xau = max(hams, key=lambda h: h[2] - h[1])
        khoi = [f"<details><summary>CWE-{tok} — <code>{chon.name}</code> ({ten})</summary>", "",
                "```csharp", than_ham(xau), "```"]

        # Ham Good: uu tien goodB2G (giu nguon, sua sink) vi no lo ra sanitizer.
        goods = [h for h in cac_ham(src) if vai_tro(h[0]) == "good"]
        tot = next((h for h in goods if "b2g" in h[0].lower()), None)
        if tot is None and goods:
            tot = max(goods, key=lambda h: h[2] - h[1])
        if tot is not None:
            khoi += ["", f"Doi trong an toan — `{tot[0]}`:", "", "```csharp", than_ham(tot), "```"]
        else:
            khoi += ["", "_Khong tim thay ham good trong tep nay._"]

        out += khoi + ["</details>", ""]
    text = "\n".join(out)
    if a.md:
        Path(a.md).write_text(text, encoding="utf-8")
    print(text)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("chon")
    c.add_argument("--goc", required=True)
    c.add_argument("--cwe", required=True)
    c.add_argument("--dich", required=True)
    j = sub.add_parser("juliet")
    j.add_argument("--goc", required=True)
    j.add_argument("--sarif", action="append", default=[], help="ten=duong/dan.sarif")
    j.add_argument("--chan", action="append", default=[], help="ten:level=error | ten:sev>=7")
    j.add_argument("--out", default="")
    j.add_argument("--md", default="")
    j.add_argument("--do-nguong", action="store_true",
                   help="do moi to hop nguong cua cong chan va xep hang theo Youden")
    j.add_argument("--ten-bo-do", default="Juliet C# 1.3 (NIST SARD #110)",
                   help="ten bo do de ghi vao bao cao; sai ten thi bao cao noi sai")
    m = sub.add_parser("mau")
    m.add_argument("--goc", required=True)
    m.add_argument("--cwe", required=True)
    m.add_argument("--md", default="")

    b = sub.add_parser("bench-csv", help="cham tren bo do co answer key CSV (BenchProctor)")
    b.add_argument("--bo", action="append", required=True,
                   help="ten_khung=duong/dan/thu-muc-khung (chua expectedresults-*.csv va testcode/)")
    b.add_argument("--sarif", action="append", default=[], help="ten=duong/dan.sarif")
    b.add_argument("--chan", action="append", default=[], help="ten:level=error | ten:sev>=7")
    b.add_argument("--do-nguong", action="store_true")
    b.add_argument("--out", default="")
    b.add_argument("--md", default="")
    a = ap.parse_args()
    return {"chon": lenh_chon, "juliet": lenh_juliet, "mau": lenh_mau,
            "bench-csv": lenh_bench}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
