#!/usr/bin/env python3
"""
Kiem thu bo rule Semgrep cua du an (C# + Python + Java).

VI SAO CAN TEP NAY
Mot rule chua chay thu thi chua phai la rule - no chi la mot y dinh viet bang
YAML. Rule co the sai cu phap, sai ten API, hoac dung mot dang pattern ma
Semgrep im lang khong khop. Ca ba truong hop deu ra cung mot ket qua: quet
xong, khong bao gi, va nguoi doc tuong la ma nguon sach.

Tep nay bien dieu do thanh mot cau hoi tra loi duoc.

BA DIEU KIEN DUOC KIEM TRA
  1. Moi rule PHAT HIEN phai bat duoc it nhat mot case trong Co_Loi.*
     -> that bai nghia la rule do mu, khong bao ve gi ca
  2. KHONG rule phat hien nao duoc bat trong Da_Khu_Doc.*
     -> that bai nghia la rule bao nham ma nguon da khu doc (duong tinh gia)
  3. Moi rule SANITIZER phai bat duoc bang chung trong Da_Khu_Doc.*
     -> that bai nghia la khong co nhan FILTERED nao sinh ra duoc

DA NGON NGU: moi ngon ngu co mot cap fixture Co_Loi.<duoi> / Da_Khu_Doc.<duoi>.
Rule cua ngon ngu nao chi khop fixture cua ngon ngu do, nen dieu kien 1 van
dung cho tung rule rieng le.

CACH CHAY
    python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py

Can semgrep cai san trong PATH (pip install semgrep), hoac Docker dang chay.
Ma tra ve 0 neu dat ca ba dieu kien, 1 neu khong.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

THU_MUC = Path(__file__).resolve().parent
RULES = THU_MUC.parent

# Moi tep rule PHAT HIEN. Tep khong ton tai thi bo qua, de ban bo cong cu cu
# (chua co rule Python/Java) van chay kiem thu duoc.
TEN_TEP_PHAT_HIEN = [
    "sast-detect.yaml",          # C# / Razor
    "sast-detect-python.yaml",   # Python
    "sast-detect-java.yaml",     # Java
]
TEN_TEP_SANITIZER = "sanitizer-check.yaml"

# Fixture "da khu doc" cua moi ngon ngu: Da_Khu_Doc.cs / .py / .java
TIEN_TO_AN_TOAN = "Da_Khu_Doc"

ID_RE = re.compile(r"^\s*-\s*id:\s*(\S+)\s*$", re.M)


def tep_phat_hien() -> list[Path]:
    return [RULES / t for t in TEN_TEP_PHAT_HIEN if (RULES / t).is_file()]


def doc_id_rule(tep: Path) -> list[str]:
    """Lay danh sach id rule tu mot tep YAML, khong can thu vien ngoai."""
    if not tep.is_file():
        raise SystemExit(f"Khong tim thay {tep}")
    return ID_RE.findall(tep.read_text(encoding="utf-8"))


def la_an_toan(ten_tep: str) -> bool:
    """Tep fixture 'da khu doc' cua bat ky ngon ngu nao."""
    return Path(ten_tep).stem == TIEN_TO_AN_TOAN


def chay_semgrep(out: Path) -> None:
    """Chay Semgrep tren thu muc fixture, xuat JSON ra `out`.

    Uu tien semgrep cai san; khong co thi dung Docker giong phan con lai cua
    bo cong cu. Khong co ca hai thi bao ro rang - KHONG duoc im lang bo qua
    roi bao "dat", vi khong chay duoc khac hoan toan voi chay xong khong loi.
    """
    ds_phat_hien = tep_phat_hien()
    if not ds_phat_hien:
        raise SystemExit(f"Khong tim thay tep rule phat hien nao trong {RULES}")

    if shutil.which("semgrep"):
        cau_hinh = [f"--config={p}" for p in ds_phat_hien]
        cau_hinh.append(f"--config={RULES / TEN_TEP_SANITIZER}")
        lenh = ["semgrep", "scan", *cau_hinh, str(THU_MUC),
                "--json", "--output", str(out), "--metrics=off", "--quiet"]
        subprocess.run(lenh, check=False, encoding="utf-8", errors="replace")
        return

    if not shutil.which("docker"):
        raise SystemExit(
            "Khong tim thay semgrep lan docker.\n"
            "  - pip install semgrep, hoac\n"
            "  - bat Docker Desktop len"
        )

    cau_hinh = [f"--config=/rules/{p.name}" for p in ds_phat_hien]
    cau_hinh.append(f"--config=/rules/{TEN_TEP_SANITIZER}")
    lenh = [
        "docker", "run", "--rm",
        "-v", f"{THU_MUC}:/fixture:ro",
        "-v", f"{RULES}:/rules:ro",
        "-v", f"{out.parent}:/out",
        "-w", "/fixture", "semgrep/semgrep", "semgrep", "scan",
        *cau_hinh,
        ".", "--json", "--output", f"/out/{out.name}",
        "--metrics=off", "--quiet",
    ]
    kq = subprocess.run(lenh, capture_output=True, text=True,
                        encoding="utf-8", errors="replace")
    if not out.is_file():
        chi_tiet = (kq.stderr or kq.stdout or "").strip()
        goi_y = ""
        if "docker.sock" in chi_tiet or "daemon" in chi_tiet.lower():
            goi_y = "\nDocker Desktop chua chay. Mo no len roi chay lai."
        raise SystemExit(
            f"Semgrep khong xuat duoc ket qua (docker tra ve {kq.returncode}).\n"
            f"{chi_tiet[:800]}{goi_y}"
        )


def main() -> int:
    ds_phat_hien = tep_phat_hien()
    id_phat_hien: list[str] = []
    nguon_rule: dict[str, str] = {}
    for p in ds_phat_hien:
        for rid in doc_id_rule(p):
            id_phat_hien.append(rid)
            nguon_rule[rid] = p.name
    id_sanitizer = doc_id_rule(RULES / TEN_TEP_SANITIZER)

    print(f"[*] {len(ds_phat_hien)} tep rule phat hien: "
          f"{', '.join(p.name for p in ds_phat_hien)}")
    print(f"[*] {len(id_phat_hien)} rule phat hien, "
          f"{len(id_sanitizer)} rule sanitizer")
    trung_lap = {r for r in id_phat_hien if id_phat_hien.count(r) > 1}
    if trung_lap:
        # id trung nhau giua cac tep rule se lam sarif_tools.id_ngan() gop
        # nham hai rule khac nhau thanh mot.
        print(f"  HONG    id rule bi trung giua cac tep: {', '.join(sorted(trung_lap))}")
        return 1
    print("[*] Dang chay Semgrep tren fixture ...\n")

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "kq.json"
        chay_semgrep(out)
        data = json.loads(out.read_text(encoding="utf-8"))

    # Gom ket qua theo (id rule -> tap tep da bat), kem so dong.
    # So dong la bat buoc: mot bao nham chi ghi "bat nham Da_Khu_Doc.cs" thi
    # nguoi sua phai do tay ca tep de tim cho. Da mat mot vong CI vi thieu no.
    trung: dict[str, set[str]] = {}
    dong_bat: dict[tuple[str, str], set[int]] = {}
    for r in data.get("results", []):
        rid = r.get("check_id", "").split(".")[-1]
        ten = Path(r.get("path", "")).name
        trung.setdefault(rid, set()).add(ten)
        ln = (r.get("start") or {}).get("line")
        if isinstance(ln, int):
            dong_bat.setdefault((rid, ten), set()).add(ln)

    def vi_tri(rid: str, ten: str) -> str:
        ds = sorted(dong_bat.get((rid, ten), ()))
        return f"{ten}:{','.join(str(x) for x in ds)}" if ds else ten

    hong: list[str] = []

    # --- Dieu kien 1: moi rule phat hien phai bat duoc case cua no ----------
    print("DIEU KIEN 1 - rule phat hien co bat duoc case co loi khong")
    print("-" * 68)
    for rid in id_phat_hien:
        tep = trung.get(rid, set())
        co_loi = {t for t in tep if not la_an_toan(t)}
        if co_loi:
            print(f"  DAT     {rid:<45} {', '.join(sorted(co_loi))}")
        else:
            print(f"  HONG    {rid:<45} khong bat duoc gi  [{nguon_rule[rid]}]")
            hong.append(f"rule phat hien mu: {rid} ({nguon_rule[rid]})")

    # --- Dieu kien 2: khong duoc bat nham ma nguon da khu doc ---------------
    print("\nDIEU KIEN 2 - co bao nham ma nguon da khu doc khong")
    print("-" * 68)
    bao_nham = [(rid, sorted(t for t in trung.get(rid, set()) if la_an_toan(t)))
                for rid in id_phat_hien]
    bao_nham = [(rid, tep) for rid, tep in bao_nham if tep]
    if bao_nham:
        for rid, tep in bao_nham:
            cho = ", ".join(vi_tri(rid, t_) for t_ in tep)
            print(f"  HONG    {rid:<45} bat nham {cho}")
            hong.append(f"duong tinh gia: {rid} tren {cho}")
    else:
        print(f"  DAT     khong rule nao bat nham {TIEN_TO_AN_TOAN}.*")

    # --- Dieu kien 3: sanitizer phai tim duoc bang chung --------------------
    print("\nDIEU KIEN 3 - rule sanitizer co tim duoc bang chung khu doc khong")
    print("-" * 68)
    for rid in id_sanitizer:
        if any(la_an_toan(t) for t in trung.get(rid, set())):
            print(f"  DAT     {rid}")
        else:
            print(f"  HONG    {rid:<45} khong tim thay bang chung")
            hong.append(f"sanitizer mu: {rid}")

    print("\n" + "=" * 68)
    if hong:
        print(f"KIEM THU THAT BAI - {len(hong)} van de:")
        for h in hong:
            print(f"  - {h}")
        print("\nRule hong thi lo hong tuong ung di qua pipeline ma khong ai biet.")
        return 1

    print(f"KIEM THU DAT - {len(id_phat_hien)} rule phat hien va "
          f"{len(id_sanitizer)} rule sanitizer deu hoat dong dung.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
