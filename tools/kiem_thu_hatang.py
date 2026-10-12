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

# (ten tep, noi dung, phai_bat, muc, mo ta)
FIXTURE = [
    ("Dockerfile.co_loi", """FROM mcr.microsoft.com/dotnet/aspnet:9.0
# Khong khai USER -> container chay bang root
COPY app/ /app/
EXPOSE 80
ENTRYPOINT ["dotnet", "/app/VulnShop.dll"]
""", True, "chac_chan",
     "khong khai USER nen container chay bang root (DS002)"),

    ("Dockerfile.da_sua", """FROM mcr.microsoft.com/dotnet/aspnet:9.0
COPY app/ /app/
RUN adduser --disabled-password --gecos "" ungdung
USER ungdung
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/VulnShop.dll"]
""", False, "chac_chan",
     "da tao user rieng va khai USER - ban doi chung, KHONG duoc bao"),
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
            "| Tep | Dap an | Trivy | Rule | Ket qua |", "|---|---|---|---|---|"]
    hong: list[str] = []

    for ten, _, phai_bat, muc, mo_ta in FIXTURE:
        thay = theo_tep.get(ten, [])
        co_chan = [r for r, lv in thay if lv == "error"]
        bat = bool(thay)
        dat = (bat == phai_bat) if muc == "chac_chan" else True
        rules = ", ".join(sorted({r for r, _ in thay})) or "-"
        dong.append(f"| `{ten}` | {'bat' if phai_bat else 'im lang'} | "
                    f"{'bat' if bat else 'im lang'} | {rules} | "
                    f"{'DAT' if dat else 'HONG'} |")
        if muc == "chac_chan" and not dat:
            hong.append(f"{ten}: dap an '{'bat' if phai_bat else 'im lang'}' "
                        f"nhung Trivy '{'bat' if bat else 'im lang'}'")
        if not phai_bat and co_chan:
            hong.append(f"{ten}: BAO NHAM o muc co quyen chan ({', '.join(co_chan)})")

    tong = len(kq)
    dong += ["", f"Tong {tong} phat hien tren {len(FIXTURE)} tep fixture.", ""]
    if hong:
        dong.append("**HONG** - " + "; ".join(hong))
    else:
        dong.append("**DAT** - tang ha tang bat dung ban co loi va im lang tren "
                    "ban da sua.")

    ra = "\n".join(dong)
    print(ra)
    if md:
        md.write_text(ra + "\n", encoding="utf-8")
    return 1 if hong else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sinh", type=Path)
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--md", type=Path)
    a = ap.parse_args()
    if a.sinh:
        return sinh(a.sinh)
    if a.sarif:
        return cham(a.sarif, a.md)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
