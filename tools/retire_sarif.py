#!/usr/bin/env python3
"""
Tang 1b - thu vien JS NHUNG SAN: doi ket qua retire.js (JSON) sang SARIF de
day len Code Scanning.

VI SAO CAN TANG NAY
Thu vien chep thang vao repo (wwwroot/lib/jquery, vendor/, *.min.js) khong
nam trong package.json hay packages.lock.json nao. Ca ba cong cu SCA dang co
deu doc TEP KHAI BAO goi:
  - sca.py          -> dotnet list package --vulnerable (chi NuGet)
  - dependency-review -> chi so tep khai bao giua hai nhanh
  - Trivy SBOM      -> cung dua tren tep khai bao / lockfile
Nen mot ban jQuery 1.8 nam trong wwwroot/lib di qua ca ba ma khong ai thay.
retire.js nhan thu vien theo NOI DUNG tep (chu thich dau tep, ten tep, ham
bam) roi doi chieu voi CSDL lo hong cua no - dung loai cong cu cho cho trong nay.

GIONG SCA, KHONG DOAN: trung phien ban la trung. Cau hoi "ham dinh loi co
duoc goi trong app khong" (reachability) van con mo - giong sca.py.

MUC DO -> security-severity (GitHub chia nguong: Critical >= 9.0,
High 7.0-8.9, Medium 4.0-6.9, Low < 4.0). retire.js chi cho muc chu, khong
cho diem CVSS, nen anh xa co dinh vao GIUA moi khoang:
    critical 9.5   high 8.0   medium 5.5   low 2.5

CHAY
    npx retire@5.7.0 --path . --verbose --outputformat json --outputpath r.json --exitwith 0
    python tools/retire_sarif.py --vao r.json --ra thu-vien-nhung.sarif --bo .devsecops-toolkit --summary

Thieu tep vao hoac tep hong -> thoat ma 2 va KHONG ghi SARIF: "khong chay
duoc" phai khac "chay xong, khong co gi". Ghi SARIF rong luc loi thi Code
Scanning se hieu la sach.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

TEN_CONG_CU = "retire.js"
DIEM = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.5"}
MUC = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
THU_TU = ["critical", "high", "medium", "low"]
# Thu muc khong phai cua repo duoc quet: goi npm (do dependency-review lo),
# thu muc cua git, va fixture kiem thu cua bo cong cu (kiem-thu-rule - co tep
# jQuery GIA de kiem thu chinh tang nay, khong duoc thanh canh bao that).
BO_MAC_DINH = ["node_modules", ".git", "kiem-thu-rule"]


def ma_lo_hong(v: dict) -> str:
    """Ma on dinh cho mot lo hong: CVE > GHSA > so issue > bam cua tom tat."""
    ids = v.get("identifiers") or {}
    cve = ids.get("CVE") or []
    if isinstance(cve, str):
        cve = [cve]
    if cve:
        return cve[0]
    for k in ("githubID", "GHSA"):
        if ids.get(k):
            return str(ids[k])
    for k in ("issue", "bug", "PR"):
        if ids.get(k):
            return f"{k}-{ids[k]}"
    tom_tat = ids.get("summary") or json.dumps(v, sort_keys=True)
    return "retire-" + hashlib.sha1(tom_tat.encode("utf-8")).hexdigest()[:10]


def cwe_cua(v: dict) -> list[str]:
    ra = []
    for c in v.get("cwe") or []:
        so = str(c).upper().replace("CWE-", "").strip()
        if so.isdigit():
            ra.append(so)
    return ra


def duong_dan_tuong_doi(tep: str, goc: Path) -> str:
    p = Path(tep)
    if not p.is_absolute():
        p = (goc / p)
    try:
        return p.resolve().relative_to(goc.resolve()).as_posix()
    except ValueError:
        return Path(tep).as_posix().lstrip("./")


def bi_bo(rel: str, bo: list[str]) -> bool:
    phan = rel.split("/")
    for b in bo:
        b = b.strip("/")
        if not b:
            continue
        if rel == b or rel.startswith(b + "/") or b in phan[:-1]:
            return True
    return False


def doi(du_lieu: dict, goc: Path, bo: list[str]) -> tuple[dict, list[dict], list[tuple]]:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    phat_hien: list[dict] = []
    nhan_ra: set[tuple] = set()     # (tep, thu vien, phien ban) - ca ban khong dinh loi

    for muc in du_lieu.get("data") or []:
        rel = duong_dan_tuong_doi(muc.get("file", ""), goc)
        if not rel or bi_bo(rel, bo):
            continue
        for kq in muc.get("results") or []:
            ten = kq.get("component", "?")
            pb = kq.get("version", "?")
            nhan_ra.add((rel, ten, pb))
            for v in kq.get("vulnerabilities") or []:
                sev = str(v.get("severity", "medium")).lower()
                if sev not in DIEM:
                    sev = "medium"
                ma = ma_lo_hong(v)
                rid = f"retire/{ten}/{ma}"
                ids = v.get("identifiers") or {}
                tom_tat = (ids.get("summary") or "").strip() or f"{ten} co lo hong da cong bo ({ma})"
                sua = f">= {v['below']}" if v.get("below") else "ban moi nhat"
                info = [u for u in (v.get("info") or []) if isinstance(u, str)]
                cwes = cwe_cua(v)
                if rid not in rules:
                    rules[rid] = {
                        "id": rid,
                        "name": f"{ten}-{ma}",
                        "shortDescription": {"text": f"{ten}: {ma} ({sev})"},
                        "fullDescription": {"text": tom_tat[:1000]},
                        **({"helpUri": info[0]} if info else {}),
                        "help": {
                            "text": f"{tom_tat}\nSua: nang {ten} len {sua}.",
                            "markdown": f"{tom_tat}\n\n**Sửa:** nâng `{ten}` lên {sua}.\n\n"
                                        + "\n".join(f"- {u}" for u in info),
                        },
                        "defaultConfiguration": {"level": MUC[sev]},
                        "properties": {
                            "tags": ["security", "vulnerable-library", "vendored-js"]
                                    + [f"external/cwe/cwe-{c}" for c in cwes],
                            "security-severity": DIEM[sev],
                            "precision": "very-high",
                            "problem.severity": "error" if MUC[sev] == "error" else "warning",
                        },
                    }
                dau_van_tay = hashlib.sha256(f"{rel}|{ten}|{ma}".encode()).hexdigest()
                results.append({
                    "ruleId": rid,
                    "level": MUC[sev],
                    "message": {"text": f"Thư viện nhúng sẵn {ten} {pb} dính {ma} ({sev}): {tom_tat} "
                                        f"Sửa: nâng {ten} lên {sua}."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": rel},
                        "region": {"startLine": 1},
                    }}],
                    "partialFingerprints": {"thuVienNhung/v1": dau_van_tay},
                    "properties": {"component": ten, "version": pb, "severity": sev},
                })
                phat_hien.append({"tep": rel, "ten": ten, "phien_ban": pb, "ma": ma,
                                  "muc": sev, "sua": sua})

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TEN_CONG_CU,
                "semanticVersion": str(du_lieu.get("version") or ""),
                "informationUri": "https://retirejs.github.io/retire.js/",
                "rules": sorted(rules.values(), key=lambda r: r["id"]),
            }},
            "results": results,
        }],
    }
    if not sarif["runs"][0]["tool"]["driver"]["semanticVersion"]:
        del sarif["runs"][0]["tool"]["driver"]["semanticVersion"]
    return sarif, phat_hien, sorted(nhan_ra)


def khoa_phien_ban(chuoi: str) -> tuple:
    """">= 3.5.0" -> (3, 5, 0) de chon phien ban sua CAO NHAT (sua het moi lo)."""
    so = re.findall(r"\d+", chuoi.split("b")[0] if re.search(r"\d+b\d", chuoi) else chuoi)
    return tuple(int(x) for x in so) or (0,)


def bang_tom_tat(phat_hien: list[dict], nhan_ra: list[tuple]) -> str:
    dong = ["### Tầng 1b · Thư viện JS nhúng sẵn (retire.js)", ""]
    thu_vien = sorted({f"{ten} {pb}" for _, ten, pb in nhan_ra})
    dong.append(f"Nhận ra {len(thu_vien)} thư viện trong {len({t for t, _, _ in nhan_ra})} tệp: "
                + (", ".join(thu_vien) if thu_vien else "không có") + ".")
    dong.append("")
    if not phat_hien:
        dong.append("Không thư viện nào dính lỗ hổng đã công bố.")
        return "\n".join(dong) + "\n"
    dem = {m: sum(1 for p in phat_hien if p["muc"] == m) for m in THU_TU}
    tep = sorted({p["tep"] for p in phat_hien})
    dong.append(f"{len(phat_hien)} lỗ hổng trong {len(tep)} tệp — "
                + ", ".join(f"{dem[m]} {m}" for m in THU_TU if dem[m]) + ".")
    dong += ["", "| Tệp | Thư viện | Lỗ hổng | Sửa |", "|---|---|---|---|"]
    gop: dict[tuple, list] = {}
    for p in phat_hien:
        gop.setdefault((p["tep"], p["ten"], p["phien_ban"]), []).append(p)
    for (t, ten, pb), ds in sorted(gop.items()):
        ds = sorted(ds, key=lambda p: THU_TU.index(p["muc"]))
        ma = ", ".join(f"{p['ma']} ({p['muc']})" for p in ds)
        sua = max((p["sua"] for p in ds), key=khoa_phien_ban)
        dong.append(f"| `{t}` | {ten} {pb} | {ma} | nâng lên {sua} |")
    return "\n".join(dong) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--vao", required=True, help="JSON cua retire.js (--outputformat json)")
    ap.add_argument("--ra", required=True, help="tep SARIF ghi ra")
    ap.add_argument("--goc", default=".", help="thu muc goc repo (de doi duong dan tuong doi)")
    ap.add_argument("--bo", action="append", default=[], help="thu muc bo qua (lap lai duoc)")
    ap.add_argument("--summary", action="store_true", help="in bang Markdown ra stdout")
    ap.add_argument("--giu-kiem-thu", action="store_true",
                    help="KHONG loai tru kiem-thu-rule (chi dung khi kiem thu chinh cong cu nay)")
    a = ap.parse_args()

    vao = Path(a.vao)
    try:
        du_lieu = json.loads(vao.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"::error::retire.js khong tao ra {vao} - tang thu vien JS nhung san CHUA quet duoc.", file=sys.stderr)
        if a.summary:
            print("### Tầng 1b · Thư viện JS nhúng sẵn (retire.js)\n\n"
                  "> ⚠ retire.js không chạy được nên tầng này **chưa có kết quả** — "
                  "không phải bằng chứng là thư viện sạch.\n")
        return 2
    except json.JSONDecodeError as e:
        print(f"::error::{vao} khong phai JSON hop le ({e}).", file=sys.stderr)
        return 2
    if du_lieu.get("errors"):
        for loi in du_lieu["errors"][:5]:
            print(f"::warning::retire.js bao loi: {str(loi)[:300]}", file=sys.stderr)

    bo = [b for b in BO_MAC_DINH if not (a.giu_kiem_thu and b == "kiem-thu-rule")] + a.bo
    sarif, phat_hien, nhan_ra = doi(du_lieu, Path(a.goc), bo)
    Path(a.ra).parent.mkdir(parents=True, exist_ok=True)
    Path(a.ra).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"retire.js: {len(phat_hien)} lo hong, {len(sarif['runs'][0]['tool']['driver']['rules'])} rule -> {a.ra}",
          file=sys.stderr)
    if a.summary:
        print(bang_tom_tat(phat_hien, nhan_ra))
    return 0


if __name__ == "__main__":
    sys.exit(main())
