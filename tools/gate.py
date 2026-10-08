#!/usr/bin/env python3
"""
TOM TAT CHO DEV - tra loi dung mot cau hoi: lan thay doi nay co gi PHAI SUA khong?

VAI TRO (So do 6): tep nay KHONG chan gi ca - no luon thoat ma 0. Viec khoa merge
la cua GitHub: ruleset "Require code scanning results" doc cac SARIF da upload va
khoa theo nguong tung cong cu. Tep nay chi viet lai ket qua do thanh mot bang
ngan tren trang Summary de dev doc la biet sua o dau, khong phai tra tab Security.
Hai nguon (GitHub va tom tat nay) dung cung nguong: SAST level error, ZAP High,
secret, CVE High tro len tren goi moi.

"MOI" tinh theo diff: alert nam tren dong ma lan thay doi nay dong vao (tu
`git diff --unified=0 <moc>..HEAD`), gan giong cach GitHub tinh. Khong co moc
(chay tay) thi coi tat ca la moi.

NGUYEN TAC: chan, tru khi co ly do cho qua. Khong nguoc lai.

Thiet ke cu cho qua moi thu tru khi ZAP chung minh duoc la co loi. ZAP khong
chung minh duoc (mui sai, payload truot, tham so POST...) thi lo hong that
di thang vao main. Do la coi im lang la an toan - trai voi chinh nguyen tac
cua do an.

Nam nguon chan, doc lap nhau, CONG DON (khong nguon nao gat duoc nguon khac):
  1. SAST  - canh bao MOI muc ERROR (rule tin cay cao/vua)
  2. DAST  - alert muc High cua ZAP khi quet TOAN BO app dung tu code PR
  3. Secret - khoa/mat khau xuat hien trong cac commit cua PR
  4. CVE   - goi Critical, chi khi PR THEM/DOI thu vien (hoac che do nghiem)
  5. (khong co nguon thu 5: nhan "da khai thac" chi de xep uu tien)

Cho qua duy nhat theo hai cach, ca hai de lai dau vet:
  - Rule bi ha xuong WARNING o cap bo cong cu (ly do ghi trong tep rule)
  - Ngoai le trong .devsecops/ngoai-le.json cua repo dich: co ly do, nguoi
    duyet, ngay het han. Tep do nen duoc bao ve bang CODEOWNERS.

Dev chi thay hai trang thai: CHAN (kem tep:dong, loi gi, sua the nao) hoac QUA.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from correlate import find_route  # noqa: E402

CWE_RE = re.compile(r"CWE-(\d+)")

# Huong dan sua ngan - dev doc la biet phai lam gi, khong can tra tai lieu.
CACH_SUA = {
    "89":  "Tham so hoa truy van: CommandText = \"... WHERE X = @x\"; Parameters.AddWithValue(\"@x\", x). EF dung FromSqlInterpolated.",
    "79":  "De Razor tu ma hoa (@bien), bo Html.Raw/HtmlString; tu ghep HTML thi HtmlEncoder.Default.Encode(x).",
    "78":  "Khong goi shell. Dung ProcessStartInfo.ArgumentList.Add(x) cho tung doi so.",
    "22":  "Path.GetFileName(x) roi Path.Combine voi thu muc goc; kiem tra ket qua van nam trong thu muc goc.",
    "611": "XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }.",
    "918": "Chi goi toi danh sach may chu cho phep; khong lay URL truc tiep tu input.",
    "601": "Dung LocalRedirect(url) hoac kiem tra Url.IsLocalUrl(url) truoc khi chuyen huong.",
    "90":  "Escape ky tu dac biet LDAP ( ) * \\ NUL truoc khi ghep vao Filter.",
    "643": "Khong ghep input vao bieu thuc XPath; dung bien XPath hoac kiem tra danh sach gia tri.",
    "91":  "SecurityElement.Escape(x) hoac ghi qua XmlWriter.",
    "113": "Loai bo \\r \\n khoi gia tri truoc khi dat vao header.",
    "94":  "Khong bien dich/chay chuoi lay tu input.",
}


# ---------------------------------------------------------------------------
# Doc du lieu
# ---------------------------------------------------------------------------
def doc_json(p: str | None):
    if not p:
        return None
    q = Path(p)
    if not q.is_file():
        return None
    try:
        return json.loads(q.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def duong_dan_trong_thu_muc(duong: str, goc: Path | None = None) -> Path:
    """Chuan hoa duong dan va BAT BUOC no nam trong thu muc lam viec.

    Vi sao can: gate.py nhan duong dan tep tu doi so dong lenh cua workflow.
    Mot gia tri kieu "../../.." hay mot duong dan tuyet doi se doc/ghi ra
    ngoai vung lam viec cua CI. Chan bang cach chuan hoa roi doi chieu voi
    goc - cung cach doc_cau_hinh() trong idor.py da lam.

    Nem ValueError neu nam ngoai; noi goi quyet dinh xu ly.
    """
    g = (goc or Path.cwd()).resolve()
    p = Path(duong).resolve()
    p.relative_to(g)          # nam ngoai goc -> ValueError
    return p


def doc_sarif(p: str | None) -> list[dict] | None:
    """Tra ve danh sach ket qua kem MUC (error/warning/note). None neu khong co tep."""
    data = doc_json(p)
    if data is None:
        return None
    out = []
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            level = (res.get("level")
                     or rule.get("defaultConfiguration", {}).get("level")
                     or "warning")
            msg = res.get("message", {}).get("text", "").strip()
            m = CWE_RE.search(msg) or CWE_RE.search(json.dumps(rule, ensure_ascii=False))
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            out.append({
                "rule": rid,
                "level": level,
                "cwe": m.group(1) if m else "",
                "file": loc.get("artifactLocation", {}).get("uri", "").replace("\\", "/").lstrip("./"),
                "line": loc.get("region", {}).get("startLine", 0),
                "msg": msg.split("\n")[0][:160],
            })
    return out


def dong_thay_doi(moc: str) -> dict[str, list[tuple[int, int]]] | None:
    """{tep: [(dau, cuoi), ...]} cac dong bi dong vao ke tu moc. None neu khong tinh duoc."""
    import subprocess
    try:
        out = subprocess.run(["git", "diff", "--unified=0", "--no-color", f"{moc}...HEAD"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        if out.returncode != 0:
            out = subprocess.run(["git", "diff", "--unified=0", "--no-color", f"{moc}..HEAD"],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        if out.returncode != 0:
            return None
    except Exception:
        return None
    kq: dict[str, list[tuple[int, int]]] = {}
    tep = None
    for line in out.stdout.splitlines():
        if line.startswith("+++ "):
            tep = line[4:].strip()
            tep = tep[2:] if tep.startswith("b/") else tep
            tep = None if tep == "/dev/null" else tep.replace("\\", "/")
        elif line.startswith("@@") and tep:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                a = int(m.group(1)); n = int(m.group(2) or 1)
                if n > 0:
                    kq.setdefault(tep, []).append((a, a + n - 1))
    return kq


def la_moi(f: str, line: int, vung: dict | None) -> bool:
    if vung is None:
        return True
    return any(a <= line <= b for a, b in vung.get(f, []))


def doc_ngoai_le(p: str | None) -> tuple[list[dict], list[dict]]:
    """(con hieu luc, da het han). Thieu ngay het han hoac ly do -> khong hop le."""
    data = doc_json(p) or []
    hom_nay = dt.date.today().isoformat()
    con, het = [], []
    for e in data if isinstance(data, list) else []:
        if not e.get("ly_do") or not e.get("het_han") or not e.get("nguoi_duyet"):
            het.append(dict(e, _vi_sao="thieu ly_do / nguoi_duyet / het_han"))
            continue
        (con if e["het_han"] >= hom_nay else het).append(e)
    return con, het


def khop_ngoai_le(ds: list[dict], loai: str, **k) -> dict | None:
    for e in ds:
        if e.get("loai") != loai:
            continue
        ok = True
        for key, val in k.items():
            want = e.get(key)
            if want is None:
                continue
            if key in ("tep", "url"):
                ok &= str(val).startswith(str(want))
            else:
                ok &= str(want) == str(val)
        if ok:
            return e
    return None


# ---------------------------------------------------------------------------
# BACKSTOP - lo hong DA XAC NHAN khai thac dong, chan BAT KE dong da doi
#
# GitHub ruleset chi chan canh bao MOI trong code PR DA DOI. Mot lo hong that -
# da bi ZAP ban payload khai thac thanh cong, hoac IDOR truy cap cheo tai khoan -
# nhung duoc neo vao mot tep PR khong dong vao (vi du SQLi o Db.cs trong khi PR
# chi them Controller) thi GitHub KHONG tinh la moi va cho merge. Do la PR #18.
#
# Backstop nay doc thang zap-alerts.json (khong qua buoc neo route cua SARIF),
# nen no thay lo hong du no nam o dau. Chi tinh phat hien DA KIEM CHUNG DONG:
#   - ZAP risk=High, confidence khong thuoc (Low, False Positive): active scan
#     da ban payload va app phan hoi dung dau hieu khai thac.
#   - IDOR/BOLA: probe co xac thuc doc duoc tai nguyen cua tai khoan khac.
# SAST tinh (doan theo hinh dang code) KHONG vao day - no van theo mo hinh
# "moi trong code da doi" cua GitHub de khong chan no tinh cu cua nguoi khac.
# ---------------------------------------------------------------------------
def _duong_dan(url: str) -> str:
    """Lay phan path cua URL, chuan hoa de so van tay on dinh."""
    from urllib.parse import urlparse
    p = urlparse(url or "").path or (url or "")
    return p.rstrip("/") or "/"


def phat_hien_da_xac_nhan(zap: dict | None) -> list[dict]:
    """Danh sach phat hien DAST da xac nhan khai thac, kem van tay on dinh."""
    if not zap:
        return []
    out: list[dict] = []
    for a in zap.get("alerts", []):
        if a.get("risk") != "High":
            continue
        if str(a.get("confidence", "")) in ("Low", "False Positive"):
            continue
        ep = _duong_dan(a.get("url", ""))
        out.append({
            "loai": "dast", "nguon": "DAST", "cwe": str(a.get("cweid") or ""),
            "plugin": str(a.get("plugin") or ""), "endpoint": ep,
            "param": a.get("param") or "",
            "loi": a.get("alert", ""),
            "bang_chung": (f"payload: {a.get('attack', '')[:80]}" if a.get("attack")
                           else (a.get("evidence", "") or "")[:80]),
            "van_tay": f"zap|{a.get('cweid') or ''}|{ep}|{a.get('param') or ''}",
        })
    for f in zap.get("idor", []):
        ep = _duong_dan(f.get("url", ""))
        out.append({
            "loai": "idor", "nguon": "DAST-idor", "cwe": "639",
            "plugin": "idor", "endpoint": ep, "param": "",
            "loi": f.get("alert", "IDOR/BOLA (CWE-639)"),
            "bang_chung": (f.get("attack", "") or "")[:80],
            "van_tay": f"idor|{ep}",
        })
    return out


def _tai_baseline_xac_nhan(p: str | None) -> set[str]:
    """Van tay cac phat hien xac nhan da biet tren main. Chap nhan 2 dang tep:
    danh sach chuoi van tay, hoac {"van_tay": [...]}."""
    if not p:
        return set()
    try:
        # Ngoai thu muc lam viec -> coi nhu KHONG co baseline. Fail-closed:
        # moi phat hien xac nhan deu thanh "moi", tuc chat hon chu khong long hon.
        duong_dan_trong_thu_muc(p)
    except ValueError:
        print(f"::warning::--baseline-xac-nhan tro ra ngoai thu muc lam viec, "
              f"bo qua baseline: {p}")
        return set()
    d = doc_json(p)
    if isinstance(d, list):
        return {str(x) for x in d}
    if isinstance(d, dict):
        return {str(x) for x in d.get("van_tay", [])}
    return set()


def _cong_xac_nhan(args, ngoai_le: list[dict]) -> int:
    """Cong chan backstop, chay DOC LAP voi tom tat thuong. Thoat 1 neu con lo
    hong DAST da xac nhan khong nam trong baseline/ngoai-le."""
    zap = doc_json(args.zap)
    baseline = _tai_baseline_xac_nhan(args.baseline_xac_nhan)
    con_lai: list[dict] = []
    da_ngoai_le: list[dict] = []
    for p in phat_hien_da_xac_nhan(zap):
        if p["van_tay"] in baseline:
            continue
        e = (khop_ngoai_le(ngoai_le, "dast-xac-nhan", url=p["endpoint"])
             or khop_ngoai_le(ngoai_le, "idor", url=p["endpoint"])
             or khop_ngoai_le(ngoai_le, "dast", plugin=p["plugin"], url=p["endpoint"]))
        if e:
            da_ngoai_le.append(e)
            continue
        con_lai.append(p)

    con_lai.sort(key=lambda c: (c["nguon"], c["endpoint"]))
    ket_luan = "CHAN" if con_lai else "QUA"

    print("=" * 70)
    if con_lai:
        print(f"CONG XAC NHAN: CHAN - {len(con_lai)} lo hong DAST DA XAC NHAN khai thac")
        print("  (chan bat ke tep do co nam trong thay doi cua PR hay khong)")
        for i, p in enumerate(con_lai, 1):
            o = p["endpoint"] + (f"?{p['param']}=" if p["param"] else "")
            print(f"\n {i}. {p['nguon']}  CWE-{p['cwe']}  {o}")
            print(f"    Loi : {p['loi']}")
            if p["bang_chung"]:
                print(f"    Bang chung: {p['bang_chung']}")
        print("\n  Cho qua: sua lo hong, hoac ghi ngoai le co ly_do / nguoi_duyet / het_han")
        print("  trong .devsecops/ngoai-le.json (loai 'dast-xac-nhan', khop theo 'url').")
    else:
        print("CONG XAC NHAN: QUA - khong co lo hong DAST da xac nhan nao ngoai baseline/ngoai-le.")
    print("=" * 70)

    # args.summary KHONG rang buoc vao thu muc lam viec duoc: mac dinh cua no la
    # $GITHUB_STEP_SUMMARY, ma GitHub dat tep do NGOAI workspace (trong thu muc
    # runner). Rang buoc vao cwd la mat han trang tom tat tren CI. Gia tri nay
    # den tu moi truong cua runner chu khong tu noi dung repo, nen khong phai
    # duong vao cua ke tan cong qua pull request.
    if args.summary:
        md = []
        if con_lai:
            md.append(f"\n## 🚫 Cổng xác nhận — CHẶN {len(con_lai)} lỗ hổng DAST đã chứng minh khai thác\n")
            md.append("_Chặn bất kể dòng đó có nằm trong thay đổi của PR hay không — vì đây là lỗ hổng "
                      "đã bị khai thác động thành công, không phải suy đoán tĩnh._\n")
            md.append("| # | Nguồn | Endpoint | Lỗi | Bằng chứng |")
            md.append("|---|---|---|---|---|")
            for i, p in enumerate(con_lai, 1):
                o = p["endpoint"] + (f"?{p['param']}=" if p["param"] else "")
                md.append(f"| {i} | {p['nguon']} CWE-{p['cwe']} | `{o}` | {p['loi']} | {p['bang_chung']} |")
        else:
            md.append("\n## ✅ Cổng xác nhận — không có lỗ hổng DAST đã chứng minh nào mới\n")
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(md) + "\n")

    try:
        out = duong_dan_trong_thu_muc(args.out)
    except ValueError:
        # Loi CAU HINH, khong phai ket luan bao mat. Dung ma 2 de khong ai doc
        # lan thanh "co lo hong" (0 = qua, 1 = chan).
        print(f"::error::--out tro ra ngoai thu muc lam viec: {args.out}")
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"ket_luan": ket_luan, "xac_nhan": con_lai,
                               "ngoai_le_ap_dung": da_ngoai_le}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    return 1 if con_lai else 0


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sast", help="SARIF Semgrep quet day du")
    ap.add_argument("--moc", default="", help="commit goc de tinh alert MOI theo diff (PR: base sha)")
    ap.add_argument("--gitleaks", help="SARIF Gitleaks quet day du")
    ap.add_argument("--gitleaks-moi", help="SARIF Gitleaks chi tren cac commit cua PR")
    ap.add_argument("--sca", help="sca.json")
    ap.add_argument("--deps-changed", action="store_true",
                    help="PR co sua tep khai bao thu vien")
    ap.add_argument("--cve-strict", action="store_true",
                    help="chan CVE Critical ke ca khi khong doi thu vien (quet dinh ky)")
    ap.add_argument("--zap", help="zap-alerts.json tu dast_scan.py")
    ap.add_argument("--chan-xac-nhan", action="store_true",
                    help="BACKSTOP (cong chan rieng): thoat ma 1 neu co phat hien DAST DA XAC NHAN "
                         "khai thac - ZAP High tin cay khong-thap, hoac IDOR/BOLA - ma khong nam "
                         "trong baseline/ngoai-le. CHAN BAT KE dong do co nam trong code PR da doi "
                         "hay khong. Bit lo 'lo hong that nhung o tep khong doi nen GitHub khong "
                         "tinh la moi' (PR #18 cua VulnShop-App). Lo logic doanh nghiep khong co "
                         "probe xac nhan nen tu nhien khong roi vao day.")
    ap.add_argument("--baseline-xac-nhan", default=".devsecops/baseline-confirmed.json",
                    help="Danh sach van tay phat hien DAST da xac nhan CO SAN tren main (no ky thuat "
                         "da biet). Khong co tep -> coi main sach -> moi phat hien xac nhan deu la "
                         "moi (fail-closed, chat hon chu khong long hon).")
    ap.add_argument("--dast-skipped", default="", help="ly do tang dong bi bo qua, neu co")
    ap.add_argument("--routes", default="routes_map.json")
    ap.add_argument("--ngoai-le", default=".devsecops/ngoai-le.json")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""))
    ap.add_argument("--out", default="reports/gate.json")
    ap.add_argument("--title", default="")
    args = ap.parse_args()

    chan: list[dict] = []     # phai sua
    tham_khao: list[str] = [] # dong ghi chu khong chan
    ghi_chu: list[str] = []   # ve pham vi / bo qua
    ngoai_le, ngoai_le_het = doc_ngoai_le(args.ngoai_le)

    # Backstop chay doc lap voi tom tat thuong: khong dong vao nhanh logic cu.
    if args.chan_xac_nhan:
        return _cong_xac_nhan(args, ngoai_le)

    def thieu_tang(ten: str, vi_sao: str) -> None:
        """Mot tang DUOC YEU CAU chay nhung khong co ket qua -> CHAN.
        Khong co ket qua khong phai la sach; cho qua o day la coi im lang la an toan."""
        chan.append({"nguon": "HE THONG", "cwe": "-", "rule": "thieu-ket-qua",
                     "o_dau": ten, "loi": f"Tang {ten} khong co ket qua: {vi_sao}",
                     "da_khai_thac": False, "bang_chung": "",
                     "cach_sua": "Xem log buoc tuong ung trong tab Actions; chay lai job. "
                                 "Loi ha tang, khong phai loi code - nhung chua kiem tra thi chua duoc qua."})
    da_dung_ngoai_le: list[dict] = []

    routes = (doc_json(args.routes) or {}).get("routes", [])
    zap = doc_json(args.zap)
    zap_alerts = (zap or {}).get("alerts", [])
    if zap and zap.get("timed_out"):
        ghi_chu.append("DAST chi chay duoc MOT PHAN (qua thoi gian) - alert ben duoi la phan da quet, "
                       "khong phai toan bo app.")

    # ---- 1. SAST ----------------------------------------------------------
    vung = dong_thay_doi(args.moc) if args.moc else None
    if args.moc and vung is None:
        ghi_chu.append(f"Khong tinh duoc diff so voi {args.moc[:7]}: coi TAT CA canh bao la moi (chat hon).")
    sast_full = doc_sarif(args.sast)
    if sast_full is None:
        thieu_tang("SAST", f"khong doc duoc {args.sast or '(khong truyen --sast)'}")
        sast_xet, sast_cu = [], []
    else:
        sast_xet = [f for f in sast_full if la_moi(f["file"], f["line"], vung)]
        sast_cu = [f for f in sast_full if f not in sast_xet]

    for f in sast_xet:
        if f["level"] != "error":
            continue
        e = khop_ngoai_le(ngoai_le, "sast", rule=f["rule"], tep=f["file"])
        if e:
            da_dung_ngoai_le.append(e)
            continue
        route = find_route(f["file"], f["line"], routes) if routes else None
        # sarif_tools.py co the da gan nhan vao thong diep - bo tien to de khong in hai lan
        m_kt = re.match(r"^\[DA KHAI THAC DUOC - ([^\]]*)\] ", f["msg"])
        if m_kt:
            f["msg"] = f["msg"][m_kt.end():]
        # Nhan uu tien: ZAP co alert cung CWE tren dung endpoint nay khong?
        khai_thac = {"alert": m_kt.group(1)} if m_kt else None
        if route and f["cwe"]:
            for a in zap_alerts:
                if khai_thac:
                    break
                if a["cweid"] == f["cwe"] and a["url"].split("?")[0].endswith(route["url_path"]):
                    khai_thac = a
        chan.append({
            "nguon": "SAST", "cwe": f["cwe"], "rule": f["rule"],
            "o_dau": f"{f['file']}:{f['line']}", "file": f["file"], "line": f["line"],
            "endpoint": route["url_path"] if route else "",
            "loi": f["msg"],
            "da_khai_thac": bool(khai_thac),
            "bang_chung": (khai_thac['alert'] if m_kt else f"ZAP khai thac duoc: {khai_thac['alert']}") if khai_thac else "",
            "cach_sua": CACH_SUA.get(f["cwe"], "Xem thong diep cua rule."),
        })
    n_warn = sum(1 for f in sast_xet if f["level"] != "error")
    if n_warn:
        tham_khao.append(f"{n_warn} canh bao SAST muc tham khao (rule tin cay thap) - khong chan.")
    if vung is not None:
        n_cu = sum(1 for f in sast_cu if f["level"] == "error")
        if n_cu > 0:
            tham_khao.append(f"{n_cu} canh bao SAST muc ERROR co tu truoc lan thay doi nay "
                             f"(no cu) - khong chan PR nay, van nam trong bao cao.")

    # ---- 2. DAST ----------------------------------------------------------
    if zap is None and args.zap:
        thieu_tang("DAST", f"khong doc duoc {args.zap} - ZAP hoac app gap su co")
    elif zap is None:
        ghi_chu.append("Tang dong (DAST) KHONG chay"
                       + (f": {args.dast_skipped}" if args.dast_skipped else "")
                       + ". Chi co bang chung tu phan tich tinh.")
    else:
        da_gan = {(c["endpoint"], c["cwe"]) for c in chan if c.get("da_khai_thac")}
        for a in zap_alerts:
            if a["risk"] != "High" or a["confidence"] in ("Low", "False Positive"):
                continue
            path = a["url"].split("?")[0]
            ep = "/" + path.split("/", 3)[3] if path.count("/") >= 3 else path
            e = khop_ngoai_le(ngoai_le, "dast", plugin=a["plugin"], url=ep)
            if e:
                da_dung_ngoai_le.append(e)
                continue
            if (ep, a["cweid"]) in da_gan:
                continue  # da nam trong muc SAST tuong ung, kem nhan da khai thac
            r_ep = next((r for r in routes if r.get("url_path") == ep), None)
            if vung is not None and r_ep and r_ep.get("file") not in vung:
                tham_khao.append(f"DAST High tren {ep} thuoc tep khong doi trong lan nay (no cu) - GitHub khong tinh la moi.")
                continue
            chan.append({
                "nguon": "DAST", "cwe": a["cweid"], "rule": f"zap-{a['plugin']}",
                "o_dau": f"{ep}?{a['param']}=" if a["param"] else ep,
                "endpoint": ep, "loi": a["alert"],
                "da_khai_thac": True,
                "bang_chung": f"payload: {a['attack'][:80]}" if a.get("attack") else "",
                "cach_sua": CACH_SUA.get(a["cweid"], "Xem mo ta alert trong bao cao ZAP."),
            })
        n_med = sum(1 for a in zap_alerts if a["risk"] == "Medium")
        if n_med:
            tham_khao.append(f"{n_med} alert DAST muc Medium - khong chan, xem bao cao.")

    # ---- 3. Secret --------------------------------------------------------
    sec = doc_sarif(args.gitleaks_moi) if args.gitleaks_moi else doc_sarif(args.gitleaks)
    if sec is None and (args.gitleaks or args.gitleaks_moi):
        thieu_tang("Secret", "khong doc duoc ket qua Gitleaks")
    elif sec is None:
        ghi_chu.append("Khong quet secret o lan chay nay.")
    for s in sec or []:
        e = khop_ngoai_le(ngoai_le, "secret", rule=s["rule"], tep=s["file"])
        if e:
            da_dung_ngoai_le.append(e)
            continue
        chan.append({
            "nguon": "SECRET", "cwe": "798", "rule": s["rule"],
            "o_dau": f"{s['file']}:{s['line']}", "file": s["file"], "line": s["line"],
            "loi": f"Secret bi lo ({s['rule']})", "da_khai_thac": False, "bang_chung": "",
            "cach_sua": "Thu hoi khoa NGAY tai nha cung cap (xoa commit khong go duoc khoi lich su git), "
                        "roi doc tu bien moi truong / GitHub Secrets.",
        })

    # ---- 4. CVE -----------------------------------------------------------
    sca = doc_json(args.sca)
    if sca:
        crit = [f for f in sca.get("findings", [])
                if f["severity"] == "Critical" and not f.get("is_test_project")]
        chan_cve = args.deps_changed or args.cve_strict
        for f in crit:
            e = khop_ngoai_le(ngoai_le, "cve", goi=f["package"])
            if e:
                da_dung_ngoai_le.append(e)
                continue
            if chan_cve:
                chan.append({
                    "nguon": "CVE", "cwe": "1395", "rule": ",".join(f["advisories"][:2]),
                    "o_dau": f"{f['package']} {f['version']}", "loi": "Thu vien dinh CVE Critical",
                    "da_khai_thac": False, "bang_chung": f["dependency"],
                    "cach_sua": "Nang phien ban goi (dotnet add package <ten>). Goi transitive thi "
                                "nang goi cha hoac khai bao truc tiep phien ban da va.",
                })
        n_khac = sum(1 for f in sca.get("findings", []) if f["severity"] in ("High", "Critical")) \
            - (len(crit) if chan_cve else 0)
        if n_khac > 0:
            tham_khao.append(f"{n_khac} goi dinh CVE High/Critical khong chan lan nay "
                             f"(PR khong doi thu vien) - quet dinh ky se nhac.")

    for e in ngoai_le_het:
        tham_khao.append(f"Ngoai le KHONG con hieu luc ({e.get('_vi_sao', 'het han ' + str(e.get('het_han')))}): "
                         f"{e.get('loai')} {e.get('rule') or e.get('goi') or e.get('plugin')}")

    # ---- Ket luan ---------------------------------------------------------
    chan.sort(key=lambda c: (not c.get("da_khai_thac"), c["nguon"], c["o_dau"]))
    ket_luan = "CHAN" if chan else "QUA"
    # Luon thoat 0: GitHub khoa merge qua Code scanning results, khong phai tep nay.

    # Chu thich ngay tren dong code trong tab Files changed cua PR
    for c in chan:
        if c.get("file"):
            tieu_de = f"{c['nguon']} CWE-{c['cwe']}" + (" - DA KHAI THAC" if c.get("da_khai_thac") else "")
            print(f"::error file={c['file']},line={c['line']},title={tieu_de}::"
                  f"{c['loi']} | Sua: {c['cach_sua']}")

    # ---- In ra log ----------------------------------------------------------
    print()
    print("=" * 70)
    if chan:
        print(f"CONG: CHAN - {len(chan)} van de phai sua truoc khi merge")
        for i, c in enumerate(chan, 1):
            uu = "  [DA KHAI THAC]" if c.get("da_khai_thac") else ""
            print(f"\n {i}. {c['nguon']}  CWE-{c['cwe']}  {c['o_dau']}{uu}")
            print(f"    Loi : {c['loi']}")
            if c.get("bang_chung"):
                print(f"    Bang chung: {c['bang_chung']}")
            print(f"    Sua : {c['cach_sua']}")
    else:
        print("CONG: QUA - khong co van de nao phai sua.")
    for t in tham_khao:
        print(f"  (tham khao) {t}")
    for g in ghi_chu:
        print(f"  (luu y) {g}")
    print("=" * 70)

    # ---- Trang tom tat tren GitHub ------------------------------------------
    md = []
    if args.title:
        md.append(f"# {args.title}\n")
    if chan:
        md.append(f"## ❌ CHẶN — {len(chan)} vấn đề phải sửa trước khi merge\n")
        md.append("_Merge bị khoá bởi check **Code scanning results** của GitHub theo cùng ngưỡng bảng này. "
                  "Báo nhầm → tab Security → Dismiss alert kèm lý do; không sửa code để né._\n")
        md.append("| # | Nguồn | Ở đâu | Lỗi | Cách sửa |")
        md.append("|---|---|---|---|---|")
        for i, c in enumerate(chan, 1):
            uu = " **🔥 đã khai thác được**" if c.get("da_khai_thac") else ""
            bc = f"<br><sub>{c['bang_chung']}</sub>" if c.get("bang_chung") else ""
            md.append(f"| {i} | {c['nguon']} CWE-{c['cwe']} | `{c['o_dau']}` | "
                      f"{c['loi']}{uu}{bc} | {c['cach_sua']} |")
        md.append("\nSửa xong, push lại lên cùng nhánh — pipeline tự chạy lại. "
                  "Chú thích đỏ nằm ngay trên dòng code trong tab **Files changed**.")
    else:
        md.append("## ✅ QUA — không có vấn đề nào phải sửa\n")
    if tham_khao or ghi_chu or da_dung_ngoai_le:
        md.append("\n### Tham khảo — không chặn\n")
        for t in tham_khao:
            md.append(f"- {t}")
        for e in da_dung_ngoai_le:
            md.append(f"- Ngoại lệ áp dụng: {e.get('loai')} `{e.get('rule') or e.get('goi') or e.get('plugin')}` "
                      f"— {e['ly_do']} (duyệt: {e['nguoi_duyet']}, hết hạn {e['het_han']})")
        for g in ghi_chu:
            md.append(f"- ⚠️ {g}")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(md) + "\n")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"ket_luan": ket_luan, "chan": chan, "tham_khao": tham_khao,
                               "ghi_chu": ghi_chu,
                               "ngoai_le_ap_dung": da_dung_ngoai_le}, indent=2, ensure_ascii=False),
                   encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
