#!/usr/bin/env python3
"""Phong do logic doi chieu ruleset cua kiem_ruleset.py.

VI SAO KHONG DO BANG API THAT
kiem_ruleset.py chay trong CI va can quyen doc repo. Phep do nay phai chay
duoc o may lap trinh vien, khong mang, khong token. Nen no do HAM doi_chieu()
- phan quyet dinh dat/lech - bang cac phan hoi API GHI SAN.

Cac phan hoi do duoc dung theo dung hinh dang ma GitHub tra ve cho
GET /repos/{owner}/{repo}/rules/branches/{branch}.

MOI CA DO LA MOT CACH RULESET CO THE BI LAM YEU TRONG THUC TE: go mot cong cu
khoi danh sach, ha nguong canh bao, tat luat, bo mot required check. Tung ca
deu phai bi bat.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kiem_ruleset import doi_chieu  # noqa: E402

GOC = Path(__file__).resolve().parent.parent
DAC_TA = json.loads((GOC / "ruleset_mong_doi.json").read_text(encoding="utf-8"))

CONG_CU = DAC_TA["cong_cu_bat_buoc"]
KIEM_TRA = DAC_TA["kiem_tra_bat_buoc"]


def luat_day_du(cong_cu=None, nguong="high_or_higher", kiem_tra=None,
                bo_luat=()) -> list[dict]:
    """Dung phan hoi API cho mot ruleset lanh manh, roi cho phep lam yeu."""
    cc = CONG_CU if cong_cu is None else cong_cu
    kt = KIEM_TRA if kiem_tra is None else kiem_tra
    ra: list[dict] = []
    if "code_scanning" not in bo_luat:
        ra.append({
            "type": "code_scanning",
            "ruleset_source_type": "Repository",
            "parameters": {"code_scanning_tools": [
                {"tool": t, "security_alerts_threshold": nguong,
                 "alerts_threshold": "errors"} for t in cc
            ]},
        })
    if "required_status_checks" not in bo_luat:
        ra.append({
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [
                {"context": c} for c in kt
            ]},
        })
    for t in ("pull_request", "deletion", "non_fast_forward"):
        if t not in bo_luat:
            ra.append({"type": t, "parameters": {}})
    return ra


# (ten ca do, luat that, cho co loi khong, tu khoa phai xuat hien trong loi)
CA_DO = [
    ("ruleset lanh manh -> dat", luat_day_du(), False, ""),

    ("go Trivy khoi danh sach cong cu",
     luat_day_du(cong_cu=[c for c in CONG_CU if c != "Trivy"]), True, "Trivy"),
    ("go gitleaks khoi danh sach cong cu",
     luat_day_du(cong_cu=[c for c in CONG_CU if c != "gitleaks"]), True, "gitleaks"),
    ("go CodeQL khoi danh sach cong cu",
     luat_day_du(cong_cu=[c for c in CONG_CU if c != "CodeQL"]), True, "CodeQL"),
    ("go Semgrep-du-an - cong cu chinh cua tang SAST",
     luat_day_du(cong_cu=[c for c in CONG_CU if c != "Semgrep-du-an"]),
     True, "Semgrep-du-an"),
    ("go ca 3 cong cu DAST",
     luat_day_du(cong_cu=[c for c in CONG_CU
                          if c not in ("OWASP-ZAP", "DAST-runtime", "DAST-idor")]),
     True, "OWASP-ZAP"),

    # Nguong = "chan tu muc do nay tro len". critical = CHI chan Critical,
    # tuc la de lot High -> YEU hon high_or_higher. Day la cho de hieu nguoc
    # nhat cua API, va la cho phep do nay da bat duoc mot loi that.
    ("nguong critical-only: de lot moi lo hong High -> phai bao",
     luat_day_du(nguong="critical"), True, "nguong"),
    ("nguong none: tat han viec chan -> phai bao",
     luat_day_du(nguong="none"), True, "nguong"),
    ("nguong medium_or_higher: chan NHIEU hon dac ta -> khong phai loi",
     luat_day_du(nguong="medium_or_higher"), False, ""),
    ("nguong all: chan moi muc -> khong phai loi",
     luat_day_du(nguong="all"), False, ""),

    ("tat han luat code_scanning",
     luat_day_du(bo_luat=("code_scanning",)), True, "code_scanning"),
    ("tat luat pull_request (day thang vao main)",
     luat_day_du(bo_luat=("pull_request",)), True, "pull_request"),
    ("tat luat non_fast_forward (day ep viet lai main)",
     luat_day_du(bo_luat=("non_fast_forward",)), True, "non_fast_forward"),
    ("tat luat deletion (xoa duoc main)",
     luat_day_du(bo_luat=("deletion",)), True, "deletion"),

    ("go check 'Cong xac nhan' khoi required status checks",
     luat_day_du(kiem_tra=[c for c in KIEM_TRA if "Cong xac nhan" not in c]),
     True, "Cong xac nhan"),
    ("go check dependency-review",
     luat_day_du(kiem_tra=[c for c in KIEM_TRA if "dependency-review" not in c]),
     True, "dependency-review"),
    ("tat han luat required_status_checks",
     luat_day_du(bo_luat=("required_status_checks",)), True,
     "required_status_checks"),

    ("ruleset bi tat hoan toan (API tra danh sach rong)", [], True, "code_scanning"),

    ("them cong cu ngoai dac ta -> chi nhac, khong hong",
     luat_day_du(cong_cu=CONG_CU + ["Semgrep-cong-dong"]), False, ""),
]


# Moi dot bien la mot cach ham doi_chieu() co the mat rang. No la thu DUY NHAT
# phat hien ruleset bi lam yeu, ma ruleset lai la thu DUY NHAT chan merge - nen
# no hong la hong lang le o dung mat xich cuoi.
DOT_BIEN = [
    ("doi_chieu() luon bao khong co loi",
     lambda s: s.replace("    return loi, nhac", "    return [], nhac")),
    ("bo kiem danh sach cong cu bat buoc",
     lambda s: s.replace('loi.append("cong cu bat buoc bi go khoi ruleset: "',
                         'nhac.append("cong cu bat buoc bi go khoi ruleset: "')),
    ("bo kiem nguong canh bao",
     lambda s: s.replace("elif NGUONG_BAO_MAT.index(tt) < NGUONG_BAO_MAT.index(mong_nguong):",
                         "elif False:")),
    ("bo kiem cac luat khac (pull_request, deletion, non_fast_forward)",
     lambda s: s.replace('loi.append(f"mat luat \'{ten_luat}\' ({nhan})")',
                         'nhac.append(f"mat luat \'{ten_luat}\' ({nhan})")')),
]


def _dot_bien() -> int:
    """Nap mot ban kiem_ruleset.py DA BI PHA roi doi hoi cac ca do phai bao hong."""
    import importlib.util
    import tempfile

    goc = Path(__file__).resolve().parent / "kiem_ruleset.py"
    nguon = goc.read_text(encoding="utf-8")
    sot: list[str] = []
    print("\n=== DOT BIEN: phep do nay co thuc su do khong? ===")
    with tempfile.TemporaryDirectory() as td:
        for ten, sua in DOT_BIEN:
            hong_nguon = sua(nguon)
            if hong_nguon == nguon:
                sot.append(f"{ten}: khong ap duoc vao ma nguon")
                print(f"[SOT ] {ten} - khong ap duoc")
                continue
            tam = Path(td) / "kiem_ruleset_hong.py"
            tam.write_text(hong_nguon, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("kr_hong", tam)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            bat = 0
            for _ten, luat, cho_loi, tu_khoa in CA_DO:
                loi, _ = mod.doi_chieu(DAC_TA, luat)
                if bool(loi) != cho_loi:
                    bat += 1
            if bat:
                print(f"[DAT ] {ten} -> phep do bao hong ({bat} ca)")
            else:
                sot.append(f"{ten}: pha roi ma phep do van bao DAT")
                print(f"[SOT ] {ten} -> pha roi ma phep do VAN bao dat")
    print()
    if sot:
        print(f"PHEP DO KHONG DANG TIN - {len(sot)}/{len(DOT_BIEN)} dot bien "
              f"khong bi bat:")
        for x in sot:
            print(f"  - {x}")
        return 1
    print(f"DAT - {len(DOT_BIEN)}/{len(DOT_BIEN)} dot bien deu bi bat.")
    return 0


def main() -> int:
    print("=== PHONG DO LOGIC DOI CHIEU RULESET ===")
    print(f"Dac ta: {len(CONG_CU)} cong cu bat buoc, nguong "
          f"{DAC_TA['nguong_bao_mat']}, {len(KIEM_TRA)} required check\n")
    hong = 0
    for ten, luat, cho_loi, tu_khoa in CA_DO:
        loi, nhac = doi_chieu(DAC_TA, luat)
        co_loi = bool(loi)
        dat = co_loi == cho_loi
        if dat and cho_loi and tu_khoa:
            dat = any(tu_khoa in x for x in loi)
        if dat:
            them = ""
            if loi:
                them = f" -> bat: {loi[0][:66]}"
            elif nhac:
                them = f" -> nhac: {nhac[0][:66]}"
            print(f"[DAT ] {ten}{them}")
        else:
            hong += 1
            print(f"[HONG] {ten}")
            print(f"       cho {'co loi' if cho_loi else 'khong loi'}"
                  f"{f' chua {tu_khoa!r}' if tu_khoa else ''}, "
                  f"nhan loi={loi} nhac={nhac}")

    print()
    if hong:
        print(f"HONG {hong}/{len(CA_DO)} ca do.")
        return 1
    print(f"DAT het {len(CA_DO)}/{len(CA_DO)} ca do.")
    print("Nghia la: moi cach lam yeu ruleset da liet ke deu bi kiem_ruleset.py bat.")
    return _dot_bien()


if __name__ == "__main__":
    raise SystemExit(main())
