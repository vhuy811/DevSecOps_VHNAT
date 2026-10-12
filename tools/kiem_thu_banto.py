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
    "/Mau/Gui": ("non_get", False,
                 "[HttpPost] nen lop quet chinh khong voi toi"),
    "/Mau/RiengTu": ("needs_auth", True,
                     "[Authorize] o cap PHUONG THUC, lop khong co [Authorize]"),
    "/Mau/AnDanh": ("testable", False,
                    "[AllowAnonymous] GHI DE [Authorize] - van quet duoc"),
    "/Mau/TrangChu": ("no_param", False,
                      "khong co tham so de tan cong"),
}


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        goc = Path(td)
        (goc / "Controllers").mkdir()
        (goc / "Controllers" / "MauController.cs").write_text(NGUON, encoding="utf-8")
        ra = goc / "routes.json"
        r = subprocess.run(
            [sys.executable, str(GOC / "tools" / "gen_routes_map.py"),
             "--root", str(goc), "--out", str(ra)],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("gen_routes_map.py that bai:")
            print(r.stderr[-800:])
            return 1
        d = json.loads(ra.read_text(encoding="utf-8"))

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
    print(f"**DAT** - {len(DAP_AN)}/{len(DAP_AN)} endpoint phan loai dung.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
