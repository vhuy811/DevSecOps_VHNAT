#!/usr/bin/env python3
"""Doi chieu ruleset THAT tren GitHub voi ban dac ta trong repo.

VI SAO PHAI CO TEP NAY
Toan bo suc manh chan merge cua do an nay KHONG nam trong ma nguon. No nam
trong mot ruleset cau hinh bang tay tren giao dien GitHub:

    Require code scanning results: 8 cong cu, nguong High or higher
    Bypass list: RONG
    Enforcement: Active

Khong mot dong ma nguon nao trong repo ep duoc cau hinh do ton tai. Mot nguoi
co quyen admin bo mot cong cu khoi danh sach, hoac them chinh minh vao bypass
list, thi:
  - pipeline VAN xanh,
  - canh bao VAN hien trong tab Code scanning,
  - va merge VAN duoc du dang co lo hong High.
Khong co dau hieu nao trong CI. Day la diem mu nguy hiem nhat cua ca do an:
cai quyet dinh chan hay khong chan la cai duy nhat khong duoc kiem soat phien
ban.

Tep nay bien ruleset thanh mot thu CO THE DO DUOC: repo khai bao ruleset nao
MINH MONG DOI trong ruleset_mong_doi.json, CI doc ruleset THAT qua REST API va
bao neu lech.

MA THOAT
  0  khop dac ta
  1  LECH - ruleset that khong con bao ve nhu da khai bao
  2  khong kiem duoc (thieu dac ta / thieu token / API tu choi) -> CI bo qua,
     KHONG coi la dat. Khac biet 0 va 2 la co y: "khong kiem duoc" khong bao
     gio duoc im lang bien thanh "dat".
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")

# Nguong cua GitHub, xep tu CHAN IT NHAT den CHAN NHIEU NHAT.
#
# CAN THAN - DE HIEU NGUOC: gia tri nay la "chan tu muc do nao tro len", nen
# `critical` nghia la CHI canh bao Critical moi chan, con High van cho merge.
# Tuc la `critical` YEU HON `high_or_higher`, khong phai manh hon. Nguoc lai
# `all` chan moi muc nen la manh nhat.
#
# Phep do kiem_thu_ruleset.py da bat dung loi nay: ban dau danh sach bi viet
# nguoc (`critical` dat o cuoi nhu thu manh nhat). Hau qua neu khong bat:
# ruleset bi ha xuong critical-only - de LOT moi lo hong High, dung muc do ma
# ca do an nay nham chan - thi phep kiem van bao DAT.
NGUONG_BAO_MAT = ["none", "critical", "high_or_higher", "medium_or_higher", "all"]


def goi(duong_dan: str, token: str) -> tuple[int, object]:
    req = urllib.request.Request(
        f"{API}{duong_dan}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "devsecops-kiem-ruleset",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {}
    except Exception as e:                      # mang, DNS, timeout
        return 0, {"message": str(e)}


def doi_chieu(dac_ta: dict, luat: list[dict]) -> tuple[list[str], list[str]]:
    """Tra (loi, nhac). Thuan logic - khong goi mang, nen do duoc bang fixture."""
    loi: list[str] = []
    nhac: list[str] = []

    co = {str(r.get("type")) for r in luat}

    # --- 1. Cong cu bat buoc phai bao ket qua ---------------------------
    mong_cc = dac_ta.get("cong_cu_bat_buoc") or []
    if mong_cc:
        quet = [r for r in luat if r.get("type") == "code_scanning"]
        that: dict[str, dict] = {}
        for r in quet:
            for t in (r.get("parameters") or {}).get("code_scanning_tools") or []:
                if t.get("tool"):
                    that[str(t["tool"])] = t
        if not quet:
            loi.append("KHONG co luat 'code_scanning' nao tren nhanh nay - "
                       "khong cong cu nao chan duoc merge")
        thieu = [c for c in mong_cc if c not in that]
        if thieu:
            loi.append("cong cu bat buoc bi go khoi ruleset: " + ", ".join(thieu))
        them = sorted(set(that) - set(mong_cc))
        if them:
            nhac.append("ruleset co thu nhieu hon dac ta: " + ", ".join(them))

        mong_nguong = dac_ta.get("nguong_bao_mat")
        if mong_nguong:
            for c in mong_cc:
                if c not in that:
                    continue
                tt = str(that[c].get("security_alerts_threshold") or "none")
                if tt not in NGUONG_BAO_MAT:
                    nhac.append(f"{c}: nguong la '{tt}', phep do chua biet gia tri nay")
                elif NGUONG_BAO_MAT.index(tt) < NGUONG_BAO_MAT.index(mong_nguong):
                    loi.append(f"{c}: nguong canh bao chan it hon dac ta - "
                               f"dac ta '{mong_nguong}', that '{tt}'")

    # --- 2. Cac luat khac phai con ---------------------------------------
    for ten_luat, nhan in (dac_ta.get("luat_bat_buoc") or {}).items():
        if ten_luat not in co:
            loi.append(f"mat luat '{ten_luat}' ({nhan})")

    # --- 3. Trang thai kiem tra bat buoc ---------------------------------
    mong_kt = dac_ta.get("kiem_tra_bat_buoc") or []
    if mong_kt:
        that_kt: set[str] = set()
        for r in luat:
            if r.get("type") != "required_status_checks":
                continue
            for c in (r.get("parameters") or {}).get("required_status_checks") or []:
                if c.get("context"):
                    that_kt.add(str(c["context"]))
        thieu = [c for c in mong_kt if c not in that_kt]
        if thieu:
            loi.append("kiem tra bat buoc bi go: " + ", ".join(thieu))

    # --- 4. Ruleset phai dang Active --------------------------------------
    # /rules/branches/<nhanh> CHI tra ve luat dang co hieu luc. Mot ruleset
    # chuyen sang Disabled/Evaluate thi luat cua no bien khoi phan hoi nay -
    # tuc la muc 1-3 o tren da bat duoc truong hop do roi.
    return loi, nhac


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    nhanh = os.environ.get("NHANH_CAN_KIEM") or "main"
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    tep = Path(os.environ.get("DAC_TA_RULESET") or "ruleset_mong_doi.json")

    if not tep.is_file():
        print(f"[BO QUA] khong co {tep} - repo nay khong khai bao ruleset mong doi.")
        print("         Them tep do neu muon CI canh giu ruleset.")
        return 2
    try:
        dac_ta = json.loads(tep.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[HONG] {tep} khong phai JSON hop le: {e}")
        return 1

    nhanh = dac_ta.get("nhanh") or nhanh
    if not repo or not token:
        print("[BO QUA] thieu GITHUB_REPOSITORY hoac GITHUB_TOKEN - "
              "khong doc duoc ruleset.")
        return 2

    ma, du_lieu = goi(f"/repos/{repo}/rules/branches/{nhanh}", token)
    if ma != 200 or not isinstance(du_lieu, list):
        tin = du_lieu.get("message") if isinstance(du_lieu, dict) else ""
        print(f"[BO QUA] API tra {ma or 'loi mang'} khi doc ruleset nhanh "
              f"'{nhanh}': {tin}")
        print("         Can quyen doc repo. KHONG coi la dat - ruleset chua duoc kiem.")
        return 2

    loi, nhac = doi_chieu(dac_ta, du_lieu)

    print(f"Ruleset co hieu luc tren '{repo}' nhanh '{nhanh}': "
          f"{len(du_lieu)} luat")
    for r in du_lieu:
        print(f"    - {r.get('type')}")
    print()
    for n in nhac:
        print(f"[NHAC] {n}")
    if loi:
        print(f"[LECH] ruleset that khong khop {tep}:")
        for x in loi:
            print(f"       {x}")
        print()
        print("       Ruleset la thu DUY NHAT chan merge khi co lo hong. Lech o day")
        print("       nghia la pipeline van xanh, canh bao van hien, ma merge van")
        print("       duoc - khong co dau hieu nao khac trong CI.")
        return 1
    print(f"[DAT ] ruleset khop {tep}: "
          f"{len(dac_ta.get('cong_cu_bat_buoc') or [])} cong cu bat buoc, "
          f"nguong {dac_ta.get('nguong_bao_mat') or '(khong doi)'}, "
          f"{len(dac_ta.get('luat_bat_buoc') or {})} luat khac.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
