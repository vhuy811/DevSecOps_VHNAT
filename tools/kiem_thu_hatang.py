#!/usr/bin/env python3
"""
Phong do TANG HA TANG (Trivy config tren Dockerfile).

VI SAO CAN TEP NAY
Tang ha tang la tang CUOI CUNG chua co bo do nao. Bao cao chi noi "N loi cau
hinh", va N=0 co the nghia la Dockerfile viet dung, cung co the nghia la Trivy
khong doc duoc tep, hoac buoc quet bi bo qua. Ba truong hop do khac han nhau
va deu hien ra man hinh giong het nhau.

Them mot ly do nua, rieng cho tang nay: no VUA MOI bi phat hien la khong co
dong nao trong bang tom tat ket qua. Tang chay that, day SARIF that, nhung
nguoi doc bao cao khong thay gi. Mot tang da tung "im lang" nhu vay thi cang
can mot phep do noi ro no con song.

CACH LAM
Sinh hai Dockerfile fixture trong thu muc tam:

  Dockerfile.co_loi    - co y vi pham cac luat Trivy biet truoc
  Dockerfile.da_sua    - ban da sua cua chinh nhung vi pham do

roi doi hoi:
  1. Ban co loi phai bi bat, va bat dung nhung luat da khai.
  2. Ban da sua KHONG duoc bao gi o muc co quyen chan.

Dieu kien 2 quan trong ngang dieu kien 1: mot cau hinh bat moi thu deu dat
dieu kien 1 va truot dieu kien 2.

DAP AN co hai muc, giong phong do secret:
  chac_chan - khang dinh; bo sot hay bao nham o day la sai that
  can_do    - chua biet Trivy ban hien tai xu ly the nao, chi in ra de doc

CHAY
    python tools/kiem_thu_hatang.py --sinh <thu-muc>
    python tools/kiem_thu_hatang.py --sarif <tep.sarif> [--md <tep.md>]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# LUAT DUOC GAI. Phep do cham theo DUNG ma luat nay, khong cham theo "co phat
# hien nao khong".
#
# VI SAO: lan chay #44 da HONG vi dieu do. Ban da_sua sua dung DS-0002 (thieu
# USER) nhung van thieu HEALTHCHECK, nen Trivy bao DS-0026 - va phep do, von
# chi hoi "co phat hien nao khong", ket luan la bao nham. Trivy dung, dap an
# sai. Neu cham theo "co phat hien nao khong" thi moi lan Trivy them mot luat
# Dockerfile moi (anh :latest nen dieu nay se xay ra) la bo do hong oan.
#
# Cham theo ma luat thi phep do tra loi dung cau no dinh hoi: "tang ha tang co
# bat duoc KHUYET DIEM DA GAI, va co im lang khi khuyet diem do da duoc sua
# khong". Cac phat hien khac van duoc in ra de doc, nhung khong lam hong phep do.
LUAT_GAI = "DS-0002"          # container chay bang root

# (ten tep, noi dung, phai_bat, muc, mo ta)
FIXTURE = [
    ("Dockerfile.co_loi", """FROM mcr.microsoft.com/dotnet/aspnet:9.0
# Khong khai USER -> container chay bang root
COPY app/ /app/
EXPOSE 80
HEALTHCHECK CMD wget -q --spider http://localhost:80/ || exit 1
ENTRYPOINT ["dotnet", "/app/VulnShop.dll"]
""", True, "chac_chan",
     "khong khai USER nen container chay bang root (DS-0002)"),

    ("Dockerfile.da_sua", """FROM mcr.microsoft.com/dotnet/aspnet:9.0
COPY app/ /app/
RUN adduser --disabled-password --gecos "" ungdung
USER ungdung
EXPOSE 8080
HEALTHCHECK CMD wget -q --spider http://localhost:8080/ || exit 1
ENTRYPOINT ["dotnet", "/app/VulnShop.dll"]
""", False, "chac_chan",
     "da tao user rieng va khai USER - ban doi chung, KHONG duoc bao DS-0002"),
]


def sinh(thu_muc: Path) -> int:
    thu_muc.mkdir(parents=True, exist_ok=True)
    for ten, noi_dung, phai_bat, muc, mo_ta in FIXTURE:
        (thu_muc / ten).write_text(noi_dung, encoding="utf-8")
    print(f"Da sinh {len(FIXTURE)} Dockerfile fixture vao {thu_muc}")
    for ten, _, phai_bat, muc, mo_ta in FIXTURE:
        nhan = "PHAI BAT " if phai_bat else "KHONG BAT"
        print(f"  {nhan} [{muc:9}] {ten:22} {mo_ta}")
    return 0


def doc_sarif(p: Path) -> list[tuple[str, str, str]]:
    """-> [(ten_tep, rule_id, muc)]"""
    if not p.is_file():
        return []
    d = json.loads(p.read_text(encoding="utf-8"))
    ra = []
    for run in d.get("runs", []):
        muc_rule = {}
        for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            lv = (r.get("defaultConfiguration") or {}).get("level", "warning")
            muc_rule[r.get("id")] = lv
        for res in run.get("results", []):
            rid = res.get("ruleId", "?")
            lv = res.get("level") or muc_rule.get(rid, "warning")
            for loc in res.get("locations", []):
                uri = (((loc.get("physicalLocation") or {}).get("artifactLocation")
                        or {}).get("uri") or "")
                ra.append((Path(uri).name, rid, lv))
    return ra


def cham(sarif: Path, md: Path | None) -> int:
    kq = doc_sarif(sarif)
    theo_tep: dict[str, list[tuple[str, str]]] = {}
    for ten, rid, lv in kq:
        theo_tep.setdefault(ten, []).append((rid, lv))

    dong = ["### Phong do tang ha tang - Trivy config", "",
            f"Fixture sinh luc chay, khong commit - {len(FIXTURE)} Dockerfile.", "",
            "| Tep | Dap an (DS-0002) | Trivy | Luat khac | Ket qua |",
            "|---|---|---|---|---|"]
    hong: list[str] = []

    khac_tong: dict[str, set[str]] = {}
    for ten, _, phai_bat, muc, mo_ta in FIXTURE:
        thay = theo_tep.get(ten, [])
        ma = {r for r, _ in thay}
        # Cham theo DUNG luat duoc gai, khong theo "co phat hien nao khong".
        bat = LUAT_GAI in ma
        dat = (bat == phai_bat) if muc == "chac_chan" else True
        khac = sorted(ma - {LUAT_GAI})
        khac_tong[ten] = set(khac)
        dong.append(f"| `{ten}` | {'bat' if phai_bat else 'im lang'} | "
                    f"{'bat' if bat else 'im lang'} | "
                    f"{', '.join(khac) or '-'} | "
                    f"{'DAT' if dat else 'HONG'} |")
        if muc == "chac_chan" and not dat:
            hong.append(f"{ten}: {LUAT_GAI} dap an "
                        f"'{'bat' if phai_bat else 'im lang'}' nhung Trivy "
                        f"'{'bat' if bat else 'im lang'}'")
        # Bao nham o muc CHAN thi van phai bao, ke ca luat khac.
        co_chan = [r for r, lv in thay if lv == "error"]
        if not phai_bat and co_chan:
            hong.append(f"{ten}: BAO NHAM o muc co quyen chan ({', '.join(co_chan)})")

    tong = len(kq)
    dong += ["", f"Tong {tong} phat hien tren {len(FIXTURE)} tep fixture.", ""]
    if hong:
        dong.append("**HONG** - " + "; ".join(hong))
    else:
        dong.append(f"**DAT** - tang ha tang bat dung {LUAT_GAI} o ban co loi va "
                    f"im lang o ban da sua.")
        dong.append("")
        dong.append("Cot *Luat khac* chi de doc: Trivy co the them luat "
                    "Dockerfile moi bat ky luc nao (anh ghim `:latest`), va "
                    "phep do nay cham theo luat duoc gai nen khong hong oan "
                    "vi chuyen do.")

    ra = "\n".join(dong)
    print(ra)
    if md:
        md.write_text(ra + "\n", encoding="utf-8")
    return 1 if hong else 0


# ---------------------------------------------------------------------------
# TU KIEM: chinh ham cham() co cham dung khong?
# ---------------------------------------------------------------------------
# Lan chay #44 hong vi ham cham() hoi sai cau: no hoi "co phat hien nao khong"
# thay vi "co DS-0002 khong". Sua xong thi phai chung minh ban sua vua dung o
# ca do da lam hong, vua KHONG lam phep do mat rang o cac ca hong that.
# Khong can Trivy, khong can mang - dung SARIF dung san.
TU_KIEM = [
    ("dung canh lan #44 (da_sua con DS-0026)",
     {"Dockerfile.co_loi": [("DS-0002", "warning"), ("DS-0026", "note")],
      "Dockerfile.da_sua": [("DS-0026", "note")]}, 0),
    ("ban da_sua sach hoan toan",
     {"Dockerfile.co_loi": [("DS-0002", "warning")],
      "Dockerfile.da_sua": []}, 0),
    ("HONG THAT: da_sua van chay bang root",
     {"Dockerfile.co_loi": [("DS-0002", "warning")],
      "Dockerfile.da_sua": [("DS-0002", "warning")]}, 1),
    ("HONG THAT: co_loi khong bi bat - tang ha tang mu",
     {"Dockerfile.co_loi": [("DS-0026", "note")],
      "Dockerfile.da_sua": []}, 1),
    ("HONG THAT: da_sua bi bao o muc CHAN boi luat khac",
     {"Dockerfile.co_loi": [("DS-0002", "warning")],
      "Dockerfile.da_sua": [("DS-0013", "error")]}, 1),
]


def _sarif_gia(cap: dict) -> dict:
    res = []
    for ten, ds in cap.items():
        for rid, lv in ds:
            res.append({"ruleId": rid, "level": lv,
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": ten}}}]})
    return {"version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}},
                      "results": res}]}


def tu_kiem() -> int:
    import io
    import tempfile
    from contextlib import redirect_stdout

    print("### Tu kiem ham cham() cua phong do ha tang\n")
    print("| Ca | Ma mong doi | Ma that | Ket qua |")
    print("|---|---|---|---|")
    hong = 0
    for ten, cap, cho in TU_KIEM:
        with tempfile.NamedTemporaryFile("w", suffix=".sarif", delete=False,
                                         encoding="utf-8") as f:
            json.dump(_sarif_gia(cap), f)
            t = Path(f.name)
        with redirect_stdout(io.StringIO()):
            ma = cham(t, None)
        t.unlink(missing_ok=True)
        dat = ma == cho
        hong += 0 if dat else 1
        print(f"| {ten} | {cho} | {ma} | {'DAT' if dat else 'HONG'} |")
    print()
    if hong:
        print(f"**HONG** - {hong}/{len(TU_KIEM)} ca tu kiem sai.")
        return 1
    print(f"**DAT** - {len(TU_KIEM)}/{len(TU_KIEM)} ca. Ham cham() cham theo ma "
          f"luat {LUAT_GAI}, khong cham theo 'co phat hien nao khong'.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sinh", type=Path)
    ap.add_argument("--tu-kiem", action="store_true",
                    help="do chinh ham cham() bang SARIF dung san (khong can Trivy)")
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--md", type=Path)
    a = ap.parse_args()
    if a.tu_kiem:
        return tu_kiem()
    if a.sinh:
        return sinh(a.sinh)
    if a.sarif:
        return cham(a.sarif, a.md)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
