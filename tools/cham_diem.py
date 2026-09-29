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
  - Moi test case dem mot lan cho phan loi va mot lan cho phan an toan:
        ti le bat      = so case co it nhat 1 TP / tong case
        ti le bao nham = so case co it nhat 1 FP / tong case
        Youden         = ti le bat - ti le bao nham   (0 = khong hon doan mo)
  - "pipeline-chan" la hop cua cac canh bao CO QUYEN CHAN (--chan): cau tra loi
    cho cau hoi "loi da biet bi chan bao nhieu phan".
"""
from __future__ import annotations

import argparse
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
]
CWE_RE = re.compile(r"cwe[-_/ ]?0*(\d+)", re.I)
TEN_TEP_RE = re.compile(r"^(CWE(\d+)_[A-Za-z0-9_]+?__(.+?)_(\d{2}))([a-z])?\.cs$")

# nhom flow variant cua Juliet (so cuoi ten tep)
NHOM_FLOW = [
    (1, 1, "01 · cơ bản"),
    (2, 22, "02–22 · qua rẽ nhánh/vòng lặp"),
    (31, 31, "31 · qua biến trung gian"),
    (41, 45, "41–45 · qua hàm khác"),
    (51, 54, "51–54 · qua tệp khác"),
    (61, 68, "61–68 · qua giá trị trả về / mảng / trường"),
    (71, 75, "71–75 · qua collection"),
    (81, 84, "81–84 · qua kế thừa / đa hình"),
]
# nguon du lieu trong ten tep Juliet: nguon tu xa (ke tan cong gui duoc) va nguon cuc bo
NGUON_TU_XA = ("Connect_tcp", "Listen_tcp", "NetClient", "QueryString_Web", "Params_Get_Web",
               "Params_Post_Web", "Cookies_Web", "Database", "Get_web", "Post_web")
NGUON_CUC_BO = ("Console_ReadLine", "ReadLine", "Environment", "File", "Property", "Registry")


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


def loai_nguon(phan_sau: str) -> tuple[str, str]:
    for n in NGUON_TU_XA:
        if phan_sau.startswith(n):
            return n, "từ xa"
    for n in NGUON_CUC_BO:
        if phan_sau.startswith(n):
            return n, "cục bộ"
    return phan_sau.split("_")[0], "khác"


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
    sig_re = re.compile(r"(?:public|private|protected|internal|static|override|virtual|async|sealed|new)[\w<>\[\],\s.?]*?\b(\w+)\s*\([^;{}()]*(?:\([^()]*\)[^;{}()]*)*\)\s*(?::\s*base\([^)]*\)\s*)?$")
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
    """case_id -> thong tin; ten_tep -> (case_id, danh sach ham)."""
    cases, tep = {}, {}
    for p in sorted(goc.rglob("*.cs")):
        m = TEN_TEP_RE.match(p.name)
        if not m:
            continue
        case_id, cwe, phan_sau, flow = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        nguon, kieu = loai_nguon(phan_sau)
        cases.setdefault(case_id, {"cwe": cwe, "flow": flow, "nhom_flow": nhom_flow(flow),
                                   "nguon": nguon, "kieu_nguon": kieu, "tep": []})
        cases[case_id]["tep"].append(p.name)
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        tep[p.name] = (case_id, cac_ham(src))
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
                        "file": Path(uri).name, "line": line, "suppressed": bool(res.get("suppressions"))})
    return out


def dieu_kien_chan(spec: str):
    """'level=error' | 'sev>=7' -> ham kiem tra ket qua."""
    if spec.startswith("level="):
        want = spec.split("=", 1)[1]
        return lambda r: r["level"] == want
    m = re.match(r"sev>=([\d.]+)", spec)
    if m:
        nguong = float(m.group(1))
        return lambda r: r["sev"] >= nguong
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
            cid, hams = t
            vt = vai_tro(ham_chua(hams, r["line"]))
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

    out = {"bo_do": "Juliet C# 1.3 (NIST SARD #110)", "so_case": len(cases), "tong": tong,
           "theo_cwe": bang_cwe, "theo_flow": bang_flow, "theo_nguon": bang_nguon,
           "case": {cid: {**info, "ket_qua": {cc: diem[cc][cid] for cc in cong_cu}} for cid, info in cases.items()}}
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1, default=list), encoding="utf-8")

    md = [f"### Phòng đo — Juliet C# 1.3 (NIST), {len(cases)} test case", "",
          "| Công cụ | Tỉ lệ bắt | Tỉ lệ báo nhầm | Youden | Cảnh báo |", "|---|---|---|---|---|"]
    for cc in cong_cu:
        t = tong[cc]
        md.append(f"| {cc} | {t['ti_le_bat']:.1%} | {t['ti_le_bao_nham']:.1%} | {t['youden']:+.2f} | {t['canh_bao']} |")
    md.append("")
    md.append("> Youden = tỉ lệ bắt − tỉ lệ báo nhầm; 0 nghĩa là không hơn đoán mò. "
              "`pipeline-chan` = chỉ tính cảnh báo có quyền chặn merge.\n")
    md.append(md_bang("Theo CWE", bang_cwe, cong_cu))
    md.append(md_bang("Theo đường đi của dữ liệu (flow variant)", bang_flow, cong_cu))
    md.append(md_bang("Theo loại nguồn dữ liệu", bang_nguon, cong_cu))
    text = "\n".join(md)
    if a.md:
        Path(a.md).write_text(text, encoding="utf-8")
    print(text)
    return 0


def lenh_chon(a: argparse.Namespace) -> int:
    goc, dich = Path(a.goc), Path(a.dich)
    muon = {int(x) for x in a.cwe.split(",") if x.strip()}
    dich.mkdir(parents=True, exist_ok=True)
    so = 0
    for d in sorted(goc.iterdir()):
        m = re.match(r"CWE(\d+)_", d.name)
        if d.is_dir() and m and int(m.group(1)) in muon:
            shutil.copytree(d, dich / d.name, dirs_exist_ok=True)
            n = sum(1 for _ in (dich / d.name).rglob("*.cs"))
            print(f"  {d.name}: {n} tep")
            so += n
    co = {int(re.match(r'CWE(\d+)_', d.name).group(1)) for d in goc.iterdir() if re.match(r'CWE(\d+)_', d.name)}
    thieu = sorted(muon - co)
    if thieu:
        print(f"Juliet C# khong co cac CWE: {', '.join(map(str, thieu))}")
    print(f"Tong: {so} tep .cs")
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
    a = ap.parse_args()
    return lenh_chon(a) if a.cmd == "chon" else lenh_juliet(a)


if __name__ == "__main__":
    sys.exit(main())
