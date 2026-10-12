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
# Thu muc con PHAI loai khoi lan quet fixture. logic-nghiep-vu/ la corpus "ma
# DUNG ma trong nhu loi" - no co bo cham rieng (tools/kiem_thu_logic_nghiepvu.py)
# va dap an rieng (0 canh bao muc chan). De lan vao day thi hong hai chieu:
#   - DIEU KIEN 1 nhan canh bao tren corpus lam "bang chung rule bat duoc loi",
#     trong khi corpus do dang le phai SACH. Lan chay CI #6 cho thay dung the:
#     dso-weak-hash va dso-weak-random "DAT" mot phan nho ban vao
#     LogicNghiepVu.cs. Mot rule chi bat duoc corpus se qua dieu kien 1 bang
#     chinh bao nham cua no.
#   - va corpus khong duoc kiem o dieu kien 2 (chi xet tep ten Da_Khu_Doc.*),
#     nen bao nham o do khong bi bat.
LOAI_KHOI_FIXTURE = ("logic-nghiep-vu", "thu-vien-js")
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


KHOI_RULE_RE = re.compile(r"^  - id: (\S+)$", re.M)
PATTERN_RE = re.compile(r"^\s*- pattern:\s*(.+?)\s*$", re.M)


def pattern_khong_phai_chuoi(tep: Path) -> list[str]:
    """Tim gia tri cua `pattern:` (va ho hang) KHONG duoc boc nhay.

    VI SAO CAN CHOT NAY - mot cai bay da lam hong mot vong CI:
        - pattern: {..., "$where": $X}
    `{` va `[` la cu phap DICT/LIST cua YAML, nen dong tren bi doc thanh
    mapping {'...': None, '$where': '$X'}. Semgrep tu choi vi "null values are
    prohibited", va no tu choi CA TEP RULE - tuc 10 rule Python mat sach, roi
    lan quet tra ve 0 ket qua cho MOI rule cua MOI tep.

    Cai bay o cho: yaml.safe_load chay HOAN TOAN tron tru. Kiem "YAML co hop le
    khong" o may KHONG bat duoc loi nay - vi no hop le, chi khong phai thu minh
    dinh viet. Chot nay kiem dung cai can kiem: gia tri co duoc boc nhay khong.

    Dung regex chu khong dung PyYAML: cac job phong do khong cai PyYAML, va mot
    chot an toan thi khong duoc them phu thuoc moi.
    """
    KHOA = (r"pattern|pattern-not|pattern-inside|pattern-not-inside"
            r"|pattern-regex|pattern-not-regex|focus-metavariable")
    rx = re.compile(rf"^\s*-?\s*({KHOA}):\s*([\{{\[].*)$")
    van_de: list[str] = []
    for i, dong in enumerate(tep.read_text(encoding="utf-8").splitlines(), 1):
        m = rx.match(dong)
        if m:
            van_de.append(
                f"{tep.name}:{i}: `{m.group(1)}:` bat dau bang "
                f"{m.group(2)[0]!r} nen YAML doc thanh dict/list, khong phai "
                f"chuoi -> Semgrep tu choi CA TEP. Boc nhay: "
                f"{m.group(1)}: '{m.group(2)[:40]}...'")
    return van_de


def nguon_sink_trung(tep: Path) -> list[str]:
    """Tim rule taint co mot pattern vua la NGUON vua la SINK.

    Day la mot cai bay im lang. Vi du that (CI #20): rule
    dso-taint-path-traversal khai File.ReadAllText(...) la nguon, trong khi
    sink cua no la File.$F($X, ...) voi $F la metavariable - nen
    File.ReadAllText khop ca hai dau va rule tu bao chinh no, ke ca khi doi so
    la hang chuoi. Hau qua neu lot luoi: moi loi goi File.ReadAllText trong
    ung dung thanh canh bao muc ERROR, tuc la chan merge moi lan doc tep.

    Kiem o day vi no khong can chay Semgrep, va vi bao nham dang nay rat kho
    doc khi nhin qua ket qua quet - no giong mot canh bao that.
    """
    van_de: list[str] = []
    noi_dung = tep.read_text(encoding="utf-8")
    moc = [(m.group(1), m.start()) for m in KHOI_RULE_RE.finditer(noi_dung)]
    for k, (rid, bd) in enumerate(moc):
        kt = moc[k + 1][1] if k + 1 < len(moc) else len(noi_dung)
        khoi = noi_dung[bd:kt]
        if "mode: taint" not in khoi:
            continue

        def lay(ten: str) -> set[str]:
            if f"    {ten}:" not in khoi:
                return set()
            sau = khoi.split(f"    {ten}:", 1)[1]
            # dung o muc thuoc dau tien cua rule (4 space + chu)
            for d in ("\n    pattern-", "\n    metadata:", "\n    message:",
                      "\n    severity:", "\n    languages:", "\n    mode:"):
                i = sau.find(d)
                if i > 0:
                    sau = sau[:i]
            return set(PATTERN_RE.findall(sau))

        nguon, sink = lay("pattern-sources"), lay("pattern-sinks")
        trung = nguon & sink
        for s in sink:                      # sink dung metavariable cho ten ham
            if ".$F(" in s:
                tien = s.split(".$F(")[0] + "."
                trung |= {n for n in nguon if n.startswith(tien)}
        if trung:
            van_de.append(f"{rid} ({tep.name}): pattern vua la nguon vua la sink "
                          f"-> {', '.join(sorted(trung))}")
    return van_de


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
        loai = [f"--exclude={x}" for x in LOAI_KHOI_FIXTURE]
        lenh = ["semgrep", "scan", *cau_hinh, *loai, str(THU_MUC),
                "--json", "--output", str(out), "--metrics=off", "--quiet"]
        kq = subprocess.run(lenh, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
        if kq.returncode >= 2 or not out.is_file():
            raise SystemExit(
                f"Semgrep khong chay duoc (ma thoat {kq.returncode}).\n"
                f"{(kq.stderr or kq.stdout or '').strip()[:1200]}")
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
        *[f"--exclude={x}" for x in LOAI_KHOI_FIXTURE],
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
    # Tien kiem khong can Semgrep: gia tri pattern phai la CHUOI.
    sai_kieu = [x for pth in list(ds_phat_hien) + [RULES / TEN_TEP_SANITIZER]
                for x in pattern_khong_phai_chuoi(pth)]
    if sai_kieu:
        print(f"  HONG    {len(sai_kieu)} pattern khong phai chuoi "
              f"(Semgrep se tu choi CA TEP RULE):")
        for x in sai_kieu:
            print(f"            - {x}")
        return 1

    # Tien kiem khong can Semgrep: bay nguon/sink trung nhau.
    bay = [x for pth in ds_phat_hien for x in nguon_sink_trung(pth)]
    if bay:
        print(f"  HONG    {len(bay)} rule taint co pattern vua la nguon vua la sink:")
        for x in bay:
            print(f"            {x}")
        print("    Rule nhu vay tu bao chinh no o moi loi goi, khong lien quan")
        print("    luong du lieu. Bo pattern do khoi nguon cua dung rule do.")
        return 1

    print("[*] Dang chay Semgrep tren fixture ...\n")

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "kq.json"
        chay_semgrep(out)
        data = json.loads(out.read_text(encoding="utf-8"))

    # ---------------------------------------------------------------- CHOT
    # "Khong co ket qua" KHAC HOAN TOAN "da quet va sach". Du an da ap nguyen
    # tac nay cho Gitleaks trong devsecops-reusable.yml, nhung o day thi quen -
    # va cai gia phai tra la mot vong CI:
    #
    #   Lan chay "Phong do logic nghiep vu" #2: Semgrep tu choi mot tep rule,
    #   van ghi ra JSON hop le voi "errors" day va "results": [], roi bo kiem
    #   nay doc thay 0 ket qua va bao CA 64 rule phat hien + 9 rule sanitizer
    #   deu "mu". Nghiem trong hon: DIEU KIEN 2 (khong duoc bao nham ma da khu
    #   doc) bao **DAT** - vi khong co canh bao nao thi dung la khong bao nham.
    #   Tuc mot rule sai cu phap lam MU TOAN BO cong chan, ma bo kiem van co
    #   mot dong mau xanh.
    #
    # Hai chot duoi day bien ca hai truong hop do thanh loi dung ten cua no.
    loi_semgrep = data.get("errors") or []
    if loi_semgrep:
        print("  HONG    Semgrep bao loi khi nap/chay rule - KHONG phai rule mu:")
        for e in loi_semgrep[:8]:
            if isinstance(e, dict):
                mo_ta = (e.get("long_msg") or e.get("message")
                         or e.get("short_msg") or str(e))
                cho = ((e.get("path") or "")
                       or ((e.get("spans") or [{}])[0].get("file", "")))
                print(f"            - {cho}: {str(mo_ta)[:300]}")
            else:
                print(f"            - {str(e)[:300]}")
        if len(loi_semgrep) > 8:
            print(f"            ... con {len(loi_semgrep) - 8} loi nua")
        print("\n  Mot tep rule hong lam Semgrep tra ve 0 ket qua cho MOI rule,")
        print("  ke ca cac rule van dung. Sua loi tren truoc, dung doc tiep bang.")
        return 2
    if not data.get("results"):
        print("  HONG    Semgrep chay xong nhung khong co MOT ket qua nao tren")
        print("          fixture - trong khi Co_Loi.* co y chua lo hong cho moi")
        print("          rule. Day la dau hieu quet HONG, khong phai rule mu.")
        return 2

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
