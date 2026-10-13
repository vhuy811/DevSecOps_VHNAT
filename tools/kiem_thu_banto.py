#!/usr/bin/env python3
"""
Phong do TANG T3 - ban do route (gen_routes_map.py).

VI SAO CAN TEP NAY
Ban do route khong tim lo hong, nhung no quyet dinh DAST quet cho nao. Mot
endpoint bi xep nham se khong duoc quet, va bao cao van ghi "khong tim thay
lo hong" - dung cai ket qua ma mot lan quet sach cung cho ra. Chinh docstring
cua gen_routes_map.py viet: "Mot ban do sai nguy hiem hon khong co ban do".

Vay ma day la tang DUY NHAT trong nam tang khong co phep do nao. Phat hien ra
dieu do khi ra soat lai do phu cua bo tu kiem.

CA KIEM THU. Fixture la mot controller co cac truong hop phan loai da biet
dap an, dat canh nhau de bat ca hai chieu: xep dung loai VA khong xep nham.

Ca [Authorize] + [AllowAnonymous] duoc dua vao co chu dich. Trong ASP.NET Core
[AllowAnonymous] GHI DE [Authorize], nen endpoint do van an danh truy cap
duoc. Nguoi doc ma (ke ca nguoi viet tep nay) rat de thay [Authorize] roi ket
luan ngay la "can dang nhap" ma khong doc het khoi thuoc tinh - da xay ra that
trong mot lan ra soat. Co ca nay thi lan sau khong ai ket luan voi nua.

CHAY
    python tools/kiem_thu_banto.py
Ma tra ve 0 neu moi ca dung dap an, 1 neu co ca sai.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

GOC = Path(__file__).resolve().parent.parent

NGUON = '''using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace PhongDo.Controllers;

public class MauController : Controller
{
    public IActionResult TimKiem(string q)
    {
        return View();
    }

    public IActionResult ChiTiet(int id)
    {
        return View();
    }

    [HttpPost]
    public IActionResult Gui(string noiDung)
    {
        return Ok();
    }

    [Authorize]
    public IActionResult RiengTu(string k)
    {
        return View();
    }

    [Authorize]
    [AllowAnonymous]
    public IActionResult AnDanh(string t)
    {
        return View();
    }

    public IActionResult TrangChu()
    {
        return View();
    }
}
'''

# url_path -> (status mong doi, needs_auth mong doi, vi sao)
DAP_AN = {
    "/Mau/TimKiem": ("testable", False,
                     "GET, tham so chuoi don gian - ZAP ban payload duoc"),
    "/Mau/ChiTiet": ("testable", False,
                     "GET, tham so so - van quet duoc"),
    "/Mau/Gui": ("post_param", False,
                 "[HttpPost] CO tham so - lop POST (G6.8) thu thap form va do duoc"),
    "/Mau/RiengTu": ("needs_auth", True,
                     "[Authorize] o cap PHUONG THUC, lop khong co [Authorize]"),
    "/Mau/AnDanh": ("testable", False,
                    "[AllowAnonymous] GHI DE [Authorize] - van quet duoc"),
    "/Mau/TrangChu": ("no_param", False,
                      "khong co tham so de tan cong"),
}


def _chay_ban_do(tool: Path) -> dict:
    """Chay gen_routes_map.py (hoac mot ban da bi pha) tren fixture -> ban do."""
    with tempfile.TemporaryDirectory() as td:
        goc = Path(td)
        (goc / "Controllers").mkdir()
        (goc / "Controllers" / "MauController.cs").write_text(NGUON, encoding="utf-8")
        ra = goc / "routes.json"
        r = subprocess.run(
            [sys.executable, str(tool), "--root", str(goc), "--out", str(ra)],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-800:])
        return json.loads(ra.read_text(encoding="utf-8"))


def _cham(d: dict) -> list[str]:
    """Doi chieu ban do voi dap an -> danh sach loi (rong = dat). Khong in gi."""
    thuc_te = {x["url_path"]: x for x in d.get("routes", [])}
    hong: list[str] = []
    for url, (st_mong, auth_mong, vi_sao) in DAP_AN.items():
        r_ = thuc_te.get(url)
        if r_ is None:
            hong.append(f"{url}: khong co trong ban do")
            continue
        if r_.get("status") != st_mong or bool(r_.get("needs_auth")) != auth_mong:
            hong.append(f"{url}: mong ({st_mong}, auth={auth_mong}) nhung duoc "
                        f"({r_.get('status')}, auth={bool(r_.get('needs_auth'))})")
    thua = sorted(set(thuc_te) - set(DAP_AN))
    if thua:
        hong.append(f"ban do sinh them endpoint ngoai dap an: {thua}")
    return hong


# Moi dot bien la mot cach gen_routes_map.py co the hong ma KHONG AI HAY: ban do
# sai thi DAST quet nham cho roi bao "khong tim thay lo hong" - dung cai ket qua
# ma mot lan quet sach cung cho ra. Dot bien thu hai la LOI DA XAY RA THAT
# (phat hien khi chay tren eShopOnWeb).
DOT_BIEN = [
    ("bo xu ly [AllowAnonymous] - thuoc tinh ghi de bi lam ngo",
     lambda s: s.replace("and not ATTR_ANONYMOUS.search(blob)", "")),
    ("bo [Authorize] cap phuong thuc - DUNG LOI DA TUNG XAY RA THAT",
     lambda s: s.replace("(class_auth or bool(ATTR_AUTHORIZE.search(blob)))",
                         "class_auth")),
    ("coi POST co tham so la testable - DAST se ban payload sai phuong thuc",
     lambda s: s.replace('return "post_param" if r["params"] else "non_get"',
                         'return "testable" if r["params"] else "non_get"')),
]


def _dot_bien() -> list[str]:
    goc_tool = GOC / "tools" / "gen_routes_map.py"
    nguon = goc_tool.read_text(encoding="utf-8")
    sot: list[str] = []
    print("\n### Dot bien - phep do nay co thuc su do khong?\n")
    print("| Dot bien | Phep do bao |")
    print("|---|---|")
    with tempfile.TemporaryDirectory() as td:
        for ten, sua in DOT_BIEN:
            hong_nguon = sua(nguon)
            if hong_nguon == nguon:
                sot.append(f"{ten}: khong ap duoc vao ma nguon (ma da doi?)")
                print(f"| {ten} | KHONG AP DUOC |")
                continue
            tam = Path(td) / "gen_hong.py"
            tam.write_text(hong_nguon, encoding="utf-8")
            try:
                loi = _cham(_chay_ban_do(tam))
            except RuntimeError:
                loi = ["ban do pha lam tool chet"]
            if loi:
                print(f"| {ten} | HONG ({len(loi)} ca) - dung |")
            else:
                sot.append(f"{ten}: pha roi ma phep do van bao DAT")
                print(f"| {ten} | **DAT - SAI** |")
    return sot


def main() -> int:
    try:
        d = _chay_ban_do(GOC / "tools" / "gen_routes_map.py")
    except RuntimeError as e:
        print("gen_routes_map.py that bai:")
        print(e)
        return 1

    thuc_te = {x["url_path"]: x for x in d.get("routes", [])}

    print("### Phong do tang T3 - ban do route\n")
    print(f"Fixture sinh luc chay: {len(DAP_AN)} endpoint co dap an chot truoc.\n")
    print("| Endpoint | Dap an | Thuc te | needs_auth | Ket qua |")
    print("|---|---|---|---|---|")

    hong: list[str] = []
    for url, (st_mong, auth_mong, vi_sao) in DAP_AN.items():
        r_ = thuc_te.get(url)
        if r_ is None:
            print(f"| `{url}` | {st_mong} | KHONG THAY | - | HONG |")
            hong.append(f"{url}: khong co trong ban do")
            continue
        st, auth = r_.get("status"), bool(r_.get("needs_auth"))
        dat = (st == st_mong) and (auth == auth_mong)
        print(f"| `{url}` | {st_mong} | {st} | {auth} | {'DAT' if dat else 'HONG'} |")
        if not dat:
            hong.append(f"{url}: mong ({st_mong}, auth={auth_mong}) "
                        f"nhung duoc ({st}, auth={auth}) - {vi_sao}")

    thua = sorted(set(thuc_te) - set(DAP_AN))
    if thua:
        hong.append(f"ban do sinh them endpoint khong co trong dap an: {thua}")

    print()
    if hong:
        print(f"**HONG** - {len(hong)} ca sai:\n")
        for h in hong:
            print(f"- {h}")
        print("\nBan do sai thi DAST quet nham cho roi bao 'khong tim thay lo hong'.")
        return 1

    sot = _dot_bien()
    print()
    if sot:
        print(f"**PHEP DO KHONG DANG TIN** - {len(sot)}/{len(DOT_BIEN)} dot bien "
              f"khong bi bat:\n")
        for x in sot:
            print(f"- {x}")
        return 1
    print(f"**DAT** - {len(DAP_AN)}/{len(DAP_AN)} endpoint phan loai dung, "
          f"{len(DOT_BIEN)}/{len(DOT_BIEN)} dot bien deu bi bat.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
