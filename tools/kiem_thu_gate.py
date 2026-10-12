#!/usr/bin/env python3
"""
Kiem thu CONG XAC NHAN (backstop) cua gate.py - G6.

Cong xac nhan sinh ra de bit mot lo cu the: ruleset GitHub chi chan canh bao
MOI trong code PR DA DOI, nen mot lo hong da bi ZAP khai thac thanh cong nhung
neo vao tep PR khong dong vao thi duoc cho merge (PR #18 cua VulnShop-App).
Bo kiem nay tai hien dung ca do va khang dinh cong chan duoc.

Kiem ca HAI chieu, vi mot cong chi biet chan thi vo dung nhu cong khong biet chan:
  - lo hong DA XAC NHAN o tep khong doi            -> PHAI chan
  - ngoai le co ly_do/nguoi_duyet/het_han con hieu luc -> cho qua
  - ngoai le HET HAN                                -> van chan
  - baseline (no ky thuat da biet tren main)        -> cho qua
  - DAST sach, hoac High nhung confidence Low       -> cho qua
  - che do thuong (khong co --chan-xac-nhan)        -> luon ma 0 (GitHub moi la cong)
  - duong dan --out ra ngoai thu muc lam viec       -> ma 2 (loi cau hinh)

Ma tra ve: 0 neu dat het, 1 neu co ca hong.
Chay: python tools/kiem_thu_gate.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "gate.py"


def main() -> int:
    work = Path(tempfile.mkdtemp())

    def ghi(ten: str, obj) -> str:
        q = work / ten
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_text(json.dumps(obj), encoding="utf-8")
        return ten                      # tra ve duong dan TUONG DOI so voi work

    def chay(*args: str) -> subprocess.CompletedProcess:
        # cwd = work: gate.py chay nhu trong CI, duong dan tuong doi so voi goc repo
        return subprocess.run([sys.executable, str(GATE), *args],
                              cwd=work, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")

    # Ca PR #18: ZAP khai thac duoc SQLi + IDOR, ca hai tren endpoint ma PR khong sua tep
    zap = {
        "alerts": [
            {"plugin": "40018", "risk": "High", "confidence": "High",
             "url": "http://localhost:5000/Report/Lookup?sku=a", "param": "sku",
             "alert": "SQL Injection", "attack": "a' OR '1'='1", "cweid": "89"},
            {"plugin": "10021", "risk": "Low", "confidence": "Medium",
             "url": "http://localhost:5000/x", "param": "", "alert": "Header thieu",
             "cweid": "693"},
        ],
        "rule_runtime": [],
        "idor": [{"url": "http://localhost:5000/Report/Invoice?id=2",
                  "alert": "Doc hoa don cua tai khoan khac",
                  "attack": "alice doc id=2 cua bob"}],
    }
    zp = ghi("reports/zap-alerts.json", zap)
    zap_sach = ghi("reports/zap-sach.json", {
        "alerts": [{"plugin": "1", "risk": "Medium", "confidence": "High",
                    "url": "http://x/y", "param": "q", "alert": "m", "cweid": "200"}],
        "idor": []})
    zap_low = ghi("reports/zap-low.json", {
        "alerts": [{"plugin": "40018", "risk": "High", "confidence": "Low",
                    "url": "http://x/y?q=1", "param": "q", "alert": "SQLi?",
                    "cweid": "89"}],
        "idor": []})

    nl_con = ghi(".devsecops/ngoai-le.json", [
        {"loai": "dast-xac-nhan", "url": "/Report/Lookup", "ly_do": "demo",
         "nguoi_duyet": "huy", "het_han": "2099-01-01"},
        {"loai": "idor", "url": "/Report/Invoice", "ly_do": "demo",
         "nguoi_duyet": "huy", "het_han": "2099-01-01"}])
    nl_het = ghi(".devsecops/ngoai-le-het.json", [
        {"loai": "dast-xac-nhan", "url": "/Report/Lookup", "ly_do": "cu",
         "nguoi_duyet": "huy", "het_han": "2000-01-01"},
        {"loai": "idor", "url": "/Report/Invoice", "ly_do": "cu",
         "nguoi_duyet": "huy", "het_han": "2000-01-01"}])
    bl = ghi(".devsecops/baseline.json",
             ["zap|89|/Report/Lookup|sku", "idor|/Report/Invoice"])
    khong_co = "reports/khong-co.json"

    hong: list[str] = []
    ket: list[tuple[str, int, int]] = []

    def kiem(ten: str, kq: subprocess.CompletedProcess, muon: int) -> None:
        ket.append((ten, kq.returncode, muon))
        if kq.returncode != muon:
            hong.append(f"{ten}: ma {kq.returncode}, muon {muon}\n{kq.stdout[-500:]}{kq.stderr[-300:]}")

    def xn(baseline: str, ngoaile: str, zapfile: str = zp, out: str = "reports/cong.json"):
        return chay("--chan-xac-nhan", "--zap", zapfile, "--out", out,
                    "--baseline-xac-nhan", baseline, "--ngoai-le", ngoaile, "--summary", "")

    kiem("lo hong xac nhan o tep khong doi -> CHAN", xn(khong_co, khong_co), 1)
    kiem("ngoai le con hieu luc -> QUA", xn(khong_co, nl_con), 0)
    kiem("ngoai le HET HAN -> CHAN", xn(khong_co, nl_het), 1)
    kiem("baseline phu -> QUA", xn(bl, khong_co), 0)
    kiem("DAST sach -> QUA", xn(khong_co, khong_co, zapfile=zap_sach), 0)
    kiem("High nhung confidence Low -> QUA", xn(khong_co, khong_co, zapfile=zap_low), 0)

    # Guard duong dan: --out ra ngoai thu muc lam viec la LOI CAU HINH (ma 2),
    # khong duoc lan thanh ket luan bao mat (0 qua / 1 chan).
    kiem("--out tuyet doi ngoai cwd -> ma 2",
         xn(khong_co, khong_co, out="/tmp/ngoai-vung-gate.json"), 2)
    kiem("--out vuot thu muc bang .. -> ma 2",
         xn(khong_co, khong_co, out="../ngoai-vung-gate.json"), 2)
    # Baseline ngoai cwd -> bo qua baseline (fail-closed) nen van CHAN
    kiem("baseline ngoai cwd -> bo qua, van CHAN",
         xn("/tmp/baseline-ngoai.json", khong_co), 1)

    # Che do thuong phai GIU NGUYEN: luon ma 0, GitHub moi la cong chan
    sarif = ghi("reports/semgrep.sarif",
                {"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": []}}, "results": []}]})
    kiem("che do thuong -> luon ma 0",
         chay("--sast", sarif, "--zap", zp, "--out", "reports/thuong.json", "--summary", ""), 0)

    print("### Phong do cong xac nhan (G6)\n")
    print("| Phep kiem | Ma thoat | Ky vong | Ket qua |")
    print("|---|---|---|---|")
    for ten, duoc, muon in ket:
        print(f"| {ten} | {duoc} | {muon} | {'✅' if duoc == muon else '❌'} |")
    print()

    if hong:
        print("KIEM THU THAT BAI:")
        for h in hong:
            print("  -", h)
        return 1
    print(f"KIEM THU DAT ({len(ket)} phep kiem)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
