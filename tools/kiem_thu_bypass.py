#!/usr/bin/env python3
"""
Kiem thu cho kiem_bypass.py - PHA tung chot roi doi hoi no phai bao.

VI SAO CAN TEP NAY
Mot bo kiem chi biet noi "dat" thi khong kiem gi ca. kiem_bypass.py chay tren
pipeline that va ra 16/16 dat - nhung ket qua do khong phan biet duoc hai kha
nang: chot con nguyen, hay phep kiem hong. Tep nay phan biet: no sao mot ban
cau hinh, pha DUNG MOT chot, va doi hoi kiem_bypass.py phai bao dung chot do.

Khong pha duoc chot nao thi phep kiem tuong ung la trang tri.

CHAY
    python tools/kiem_thu_bypass.py
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GOC = Path(__file__).resolve().parent.parent

# (ten phep kiem phai bao hong, tep bi pha, ham pha)
# Moi dong la mot duong lach that: pha chot roi doi hoi bo kiem bat duoc.
PHA = [
    ("khong the thoa cong bang cach bi skip", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("needs.scan.result != 'skipped'", "true")),
    ("--disable-nosem", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("--disable-nosem", "")),
    ("nosem bi vo hieu hoa truoc khi quet", ".github/workflows/devsecops-reusable.yml",
     lambda t: re.sub(r"no_sem", "XOA_CHOT", t)),
    ("continue-on-error", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("    steps:", "    steps:\n      # them chot xau\n", 1)
                .replace("      - uses: actions/checkout@v7",
                         "      - uses: actions/checkout@v7\n        continue-on-error: true", 1)),
    ("paths / paths-ignore o trigger", ".github/workflows/devsecops.yml",
     lambda t: t.replace("  pull_request:", "  pull_request:\n    paths:\n      - 'src/**'", 1)),
    ("push duoc quet tren MOI nhanh", ".github/workflows/devsecops.yml",
     lambda t: t.replace("  push:", "  push:\n    branches: [main]", 1)),
    ("day len Code Scanning", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("          sarif_file: reports/idor.sarif",
                         "          sarif_file: reports/DA_XOA.sarif", 1)),
    # Phai nham vao mot BUOC that, khong phai chu thich. Ban dau phep pha nay
    # dung .replace(..., 1) va no sua trung dong CHU THICH
    # "# persist-credentials: false" o dau tep - doi mot chu thich thi khong co
    # chot nao mat, nen bo kiem dung khi noi "van du chot". Phep pha sai, khong
    # phai phep kiem sai. Gio nham vao dong thut 10 space (trong khoi `with:`).
    ("persist-credentials: false", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("          persist-credentials: false",
                         "          persist-credentials: true", 1)),
    ("gate.py co che do --chan-xac-nhan", "tools/gate.py",
     lambda t: t.replace("--chan-xac-nhan", "--da-bo-chot")),
    ("thuc su truyen --chan-xac-nhan", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("--chan-xac-nhan", "")),
    ("ly_do / nguoi_duyet / het_han", "tools/gate.py",
     lambda t: t.replace("het_han", "khong_con")),
    ("khong ra ket qua thi CHAN", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("exit 1", "exit 0")),
    ("chan duong dan ra ngoai thu muc lam viec", "tools/gate.py",
     lambda t: t.replace("relative_to", "KHONG_CHAN")),
    ("Ben goi ghim toolkit-ref", ".github/workflows/devsecops.yml",
     lambda t: re.sub(r"toolkit-ref:\s*\$\{\{\s*github\.sha[^\n]*", "toolkit-ref: main", t)),
    ("deu duoc nap vao buoc quet", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("sast-detect-java.yaml", "DA_QUEN_NAP.yaml")),
    ("fixture bi loai khoi lan quet", ".github/workflows/devsecops-reusable.yml",
     lambda t: t.replace("kiem-thu-rule", "mot-cai-gi-khac")),
]

CAN = [".github/workflows/devsecops-reusable.yml", ".github/workflows/devsecops.yml",
       "tools/gate.py", "tools/kiem_bypass.py"]


def dung_cay(tmp: Path) -> None:
    for t in CAN:
        d = tmp / t
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(GOC / t, d)
    # Thu muc semgrep-rules: kiem_bypass liet ke sast-detect*.yaml trong do
    (tmp / "semgrep-rules").mkdir(parents=True, exist_ok=True)
    for p in (GOC / "semgrep-rules").glob("sast-detect*.yaml"):
        (tmp / "semgrep-rules" / p.name).write_text("rules: []\n", encoding="utf-8")


def chay(tmp: Path) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-I", str(tmp / "tools" / "kiem_bypass.py")],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout + r.stderr


def main() -> int:
    print("### Kiểm thử bộ kiểm bypass — phá từng chốt\n")

    # Chieu 1: ban nguyen phai DAT
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        dung_cay(tmp)
        rc, out = chay(tmp)
    if rc != 0:
        print(f"HỎNG: bản chưa phá mà đã báo mất chốt (mã {rc})")
        print(out[-2500:])
        return 1
    print("Bản chưa phá: **đạt** (đúng kỳ vọng)\n")

    # Chieu 2: pha tung chot, doi hoi bo kiem bao dung chot do
    print("| Chốt bị phá | Bộ kiểm có bắt được |")
    print("|---|---|")
    hong = []
    for ten, tep, f in PHA:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dung_cay(tmp)
            p = tmp / tep
            goc_txt = p.read_text(encoding="utf-8")
            p.write_text(f(goc_txt), encoding="utf-8")
            if p.read_text(encoding="utf-8") == goc_txt:
                hong.append((ten, "phép phá không đổi được gì — phép kiểm thử sai, không phải bộ kiểm sai"))
                print(f"| {ten[:52]} | ⚠ phép phá vô hiệu |")
                continue
            rc, out = chay(tmp)
        # tim dong bao hong co chua ten chot
        bat = rc != 0 and any(ten in l for l in out.splitlines() if "MẤT CHỐT" in l or "**" in l)
        if bat:
            print(f"| {ten[:52]} | ✅ |")
        else:
            hong.append((ten, f"mã thoát {rc}, không thấy chốt này trong danh sách mất chốt"))
            print(f"| {ten[:52]} | ❌ KHÔNG bắt được |")

    print()
    if hong:
        print(f"**{len(hong)} phép kiểm là trang trí:**\n")
        for ten, ly in hong:
            print(f"- {ten}: {ly}")
        return 1
    print(f"Cả **{len(PHA)}** chốt đều bị bắt khi phá. Bộ kiểm không phải trang trí.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
