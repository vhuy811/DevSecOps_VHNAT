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

    print()
    if loi:
        print(f"HONG {len(loi)}/{len(LUAT)} luat tren {len(tep)} workflow.")
        return 1
    print(f"DAT het {len(LUAT)}/{len(LUAT)} luat tren {len(tep)} workflow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
