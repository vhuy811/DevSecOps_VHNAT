#!/usr/bin/env python3
"""Canh giu cau hinh CI: cac loi DA TUNG LAM HONG CI, moi loi mot phep kiem.

VI SAO CAN TEP NAY
Chu thich trong tep YAML khong phai la mot phep kiem. Bang chung cu the trong
chinh du an nay:

  CI #1  phong-do-java.yml viet `git sparse-checkout init --cone -q`.
         git 2.43 cua runner khong co co -q cho `init` -> "unknown switch 'q'"
         -> job chet o giay thu 23.
  e9c58a7 sua dung: go -q VA them mot dong chu thich giai thich vi sao.
  5a7881a vo tinh dua -q TRO LAI va xoa luon dong chu thich do.
  CI #3  hong lai y het CI #1, mat them mot vong CI 15 phut.

Tuc la: mot lan sua + mot dong chu thich KHONG ngan duoc tai pham. Tep nay
bien tung lan hong thanh mot phep kiem chay tu dong, re (khong can docker,
khong can mang) va chay truoc moi thu khac.

NGUYEN TAC THEM MUC MOI: chi them khi mot cau hinh DA THUC SU lam hong mot
lan chay CI, va ghi ro lan chay nao. Day khong phai cho de doan truoc moi loi
co the xay ra - danh sach doan mo thi khong ai giu noi.
"""
import re
import sys
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows"

# (ten, bieu thuc tim loi, giai thich + lan CI da hong)
LUAT: list[tuple[str, re.Pattern, str]] = [
    (
        "sparse-checkout init -q",
        re.compile(r"git\s+sparse-checkout\s+init\b[^\n]*\s-q\b"),
        "git 2.43 tren runner ubuntu-24.04 KHONG co co -q cho "
        "`sparse-checkout init` (chi co --cone / --sparse-index) nen bao "
        "'unknown switch' va job chet ngay. Da lam hong CI #1 va CI #3 cua "
        "Phong do Java. Bo han -q di.",
    ),
    (
        "checkout khong tat persist-credentials",
        re.compile(r"uses:\s*actions/checkout@[^\n]*\n(?:(?![ \t]*-\s)[^\n]*\n)*?"
                   r"[ \t]*with:\s*\n(?:(?![ \t]*-\s)[^\n]*\n)*?"
                   r"[ \t]*persist-credentials:\s*true"),
        "actions/checkout ghi GITHUB_TOKEN vao .git/config va de o do het job. "
        "Pipeline nay mount workspace vao nhieu image :latest, nen mot image bi "
        "chiem chi can doc .git/config la co token ghi duoc vao repo. Phai de "
        "persist-credentials: false.",
    ),
]


# ---------------------------------------------------------------------------
# PHEP KIEM CAU TRUC: HOP DONG QUYEN GIUA WORKFLOW DUNG CHUNG VA BEN GOI
#
# Workflow dung chung chay NESTED trong workflow cua repo goi. GitHub khong
# cong quyen lai: mot job ben trong xin `pull-requests: read` ma ben goi khong
# cap thi CA LAN CHAY chet ngay o buoc khoi dong, voi loi
#   "The nested job 'X' is requesting 'pull-requests: read',
#    but is only allowed 'pull-requests: none'."
# Khong job nao chay, khong SARIF nao duoc day len, va - dang so nhat - khong
# canh bao bao mat nao xuat hien.
#
# DA XAY RA THAT: commit a42d7b9 them `pull-requests: read` cho job nhan-dien
# nhung khong sua mau vi-du-repo-khac.yml lan khoi permissions trong README.
# Ngay sau khi nhanh do vao main, pipeline cua VulnShop-App chet voi
# "Startup failure" o lan chay #52. Moi repo lam theo tai lieu deu se hong y
# het, va hong theo kieu im lang - CI do nhung khong ai doc ra la do quyen.
#
# Phep kiem nay doi chieu quyen MA WORKFLOW DUNG CHUNG DOI voi quyen MA TAI
# LIEU BAO BEN GOI CAP. Lech mot dong la bao.
MUC = {"none": 0, "read": 1, "write": 2}
GOC_REPO = Path(__file__).resolve().parent.parent


def kiem_quyen_ben_goi() -> list[str]:
    dung_chung = WF / "devsecops-reusable.yml"
    mau_goi = GOC_REPO / "vi-du-repo-khac.yml"
    if not dung_chung.is_file() or not mau_goi.is_file():
        print("[BO QUA] khong thay devsecops-reusable.yml hoac vi-du-repo-khac.yml")
        return []

    cay = yaml.safe_load(dung_chung.read_text(encoding="utf-8")) or {}
    can: dict[str, str] = {}
    for ten_job, job in (cay.get("jobs") or {}).items():
        q = (job or {}).get("permissions") or {}
        if not isinstance(q, dict):
            continue
        for pham_vi, muc in q.items():
            if MUC.get(str(muc), 0) > MUC.get(can.get(pham_vi, "none"), 0):
                can[pham_vi] = str(muc)

    cap = (yaml.safe_load(mau_goi.read_text(encoding="utf-8")) or {}).get("permissions") or {}
    if not isinstance(cap, dict):
        cap = {}

    thieu = []
    for pham_vi, muc in sorted(can.items()):
        co = str(cap.get(pham_vi, "none"))
        if MUC.get(co, 0) < MUC.get(muc, 0):
            thieu.append(f"{pham_vi}: can '{muc}', mau chi cap '{co}'")

    ten = "Mau cho ben goi cap du quyen workflow dung chung doi"
    if thieu:
        print(f"[HONG] {ten}")
        for t in thieu:
            print(f"       {t}")
        print("       Thieu quyen thi CA LAN CHAY chet o buoc khoi dong "
              "(Startup failure) va khong co canh bao bao mat nao.")
        print("       Sua vi-du-repo-khac.yml VA khoi permissions trong README.")
        return [f"{ten} -> {'; '.join(thieu)}"]
    print(f"[DAT ] {ten} ({', '.join(f'{k}: {v}' for k, v in sorted(can.items()))})")
    return []


def main() -> int:
    if not WF.is_dir():
        print(f"Khong thay thu muc {WF}")
        return 2
    tep = sorted(WF.glob("*.yml")) + sorted(WF.glob("*.yaml"))
    if not tep:
        print(f"Khong co workflow nao trong {WF} - phep kiem nay se luon DAT ma "
              f"khong kiem gi")
        return 2

    loi: list[str] = []
    for ten_luat, rx, vi_sao in LUAT:
        thay = []
        for p in tep:
            noi_dung = p.read_text(encoding="utf-8")
            for m in rx.finditer(noi_dung):
                dong = noi_dung[: m.start()].count("\n") + 1
                thay.append(f"{p.name}:{dong}")
        if thay:
            loi.append(f"{ten_luat} -> {', '.join(thay)}\n     {vi_sao}")
            print(f"[HONG] {ten_luat}")
            for x in thay:
                print(f"       {x}")
            print(f"       {vi_sao}")
        else:
            print(f"[DAT ] {ten_luat}")

    loi += kiem_quyen_ben_goi()

    print()
    tong = len(LUAT) + 1
    if loi:
        print(f"HONG {len(loi)}/{tong} luat tren {len(tep)} workflow.")
        return 1
    print(f"DAT het {tong}/{tong} luat tren {len(tep)} workflow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
