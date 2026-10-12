#!/usr/bin/env python3
"""
Dap an cho tang SCA - do tang thu vien tren nhieu he sinh thai.

VI SAO CAN TEP NAY
Tang SCA la tang DUY NHAT trong pipeline chua co bo do nao, nen cau "bo sot bao
nhieu" khong tra loi duoc. Va khi di tim bo do thi phat hien mot lo lon hon:

  sca.py              -> CHI NuGet (dotnet list package --vulnerable)
  retire.js           -> CHI thu vien JS nhung san, KHONG doc package.json
  dependency-review   -> CHI thu vien MOI trong PR, khong xet thu vien da co
  Trivy fs            -> da chay nhung CHI de sinh SBOM, khong hoi lo hong

Nghia la voi mot repo Python hay Java, cac thu vien DA CO trong requirements.txt
hoac pom.xml khong tang nao quet. Chi thu vien moi them trong PR moi bi xet. Do
la lo hong cua chinh cau "dung duoc cho nhieu loai repo".

CACH DAP AN DUOC DUNG
Fixture duoc SINH RA LUC CHAY, trong thu muc tam, va khong bao gio duoc commit.
Hai ly do, ca hai deu that:
  1. Manifest ghim phien ban dinh lo hong ma commit vao repo thi Dependabot cua
     chinh repo nay se bao dong, va tang SCA cua chinh pipeline se chan moi PR.
  2. Khong co tep nao trong repo chua chuoi nhin giong thong tin dang nhap.

DAP AN la du lieu trong tep nay: moi dong la (he sinh thai, goi, phien ban, co
lo hong hay khong). Khong khang dinh ID cua CVE - chi khang dinh "phien ban nay
dinh lo hong da cong bo, phai co it nhat mot canh bao tren no". Khang dinh ID
thi de sai, va sai o dap an thi toan bo phep do vo nghia.

HAN CHE PHAI NOI RO
Ti le BAO NHAM cua SCA khong on dinh theo thoi gian nhu SAST: mot phien ban hom
nay sach, mai co advisory moi thi thanh "co lo hong" ma dap an o day van ghi la
sach. Nen con so bao nham cua tang nay phai doc kem ngay do, va cac dong "sach"
can duoc xem lai dinh ky. Ti le BAT thi on dinh: lo hong da cong bo khong bien
mat.

CHAY
    python tools/kiem_thu_sca.py --sinh /tmp/fixture     # chi sinh fixture
    python tools/kiem_thu_sca.py --sinh /tmp/fixture \\
        --trivy-sarif ket-qua/trivy-fs.sarif             # sinh + cham diem
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# (he_sinh_thai, goi, phien_ban, co_lo_hong)
# Cac phien ban "co lo hong" deu la lo hong da cong bo rong rai va co advisory
# trong GitHub Advisory Database. Cac phien ban "sach" la ban da va o thoi diem
# viet tep nay - xem HAN CHE o docstring.
# MOI GOI CHI DUOC XUAT HIEN MOT LAN TRONG MOT HE SINH THAI.
# Ban dau cac dong "sach" dung CUNG TEN GOI voi dong "co lo hong", chi khac
# phien ban - va manifest la map theo ten goi, nen phien ban sach GHI DE phien
# ban loi. Dap an se doi bat mot goi khong he co trong manifest, va phep do se
# bao "bo sot" oan. Ham sinh() co kiem rang buoc nay de loi do khong quay lai.
DAP_AN = [
    # --- npm -----------------------------------------------------------------
    ("npm", "lodash", "4.17.15", True),    # prototype pollution
    ("npm", "minimist", "1.2.0", True),    # prototype pollution
    ("npm", "axios", "0.21.0", True),      # SSRF
    ("npm", "ms", "2.1.3", False),
    ("npm", "escape-string-regexp", "4.0.0", False),
    # --- pip -----------------------------------------------------------------
    ("pip", "urllib3", "1.25.8", True),
    ("pip", "PyYAML", "5.1", True),        # arbitrary code execution qua full_load
    ("pip", "Flask", "0.12.2", True),
    ("pip", "six", "1.16.0", False),
    ("pip", "packaging", "24.1", False),
    # --- maven ---------------------------------------------------------------
    ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1", True),   # Log4Shell
    ("maven", "commons-collections:commons-collections", "3.2.1", True),  # deserialization RCE
    ("maven", "org.slf4j:slf4j-api", "2.0.13", False),
    # --- nuget ---------------------------------------------------------------
    ("nuget", "Newtonsoft.Json", "12.0.1", True),
    ("nuget", "Microsoft.Extensions.Primitives", "8.0.0", False),
]


def sinh(goc: Path) -> None:
    """Sinh cay manifest trong thu muc tam. Khong commit tep nao trong nay."""
    # Rang buoc: mot ten goi khong duoc xuat hien hai lan trong cung he sinh
    # thai, neu khong manifest se mat mot dong va dap an sai.
    for he in {h for h, _, _, _ in DAP_AN}:
        ten = [g for h, g, _, _ in DAP_AN if h == he]
        trung = {x for x in ten if ten.count(x) > 1}
        if trung:
            raise SystemExit(
                f"DAP_AN sai: {he} co goi xuat hien nhieu lan: {sorted(trung)}. "
                f"Manifest la map theo ten goi nen chi mot phien ban ton tai, va "
                f"phep do se bao bo sot oan.")
    goc.mkdir(parents=True, exist_ok=True)
    (goc / "GHI_CHU.txt").write_text(
        "Fixture SINH RA LUC CHAY cho tools/kiem_thu_sca.py.\n"
        "Cac manifest o day CO Y ghim phien ban dinh lo hong da cong bo.\n"
        "KHONG commit thu muc nay: Dependabot se bao dong va tang SCA cua chinh\n"
        "pipeline se chan moi PR.\n", encoding="utf-8")

    npm = [(g, v) for h, g, v, _ in DAP_AN if h == "npm"]
    (goc / "package.json").write_text(json.dumps({
        "name": "fixture-sca", "version": "1.0.0", "private": True,
        "dependencies": {g: v for g, v in npm},
    }, indent=2), encoding="utf-8")
    # Trivy uu tien lockfile. package-lock v3 toi thieu nhung du de Trivy doc.
    (goc / "package-lock.json").write_text(json.dumps({
        "name": "fixture-sca", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {"": {"name": "fixture-sca", "version": "1.0.0",
                          "dependencies": {g: v for g, v in npm}},
                     **{f"node_modules/{g}": {"version": v, "resolved":
                        f"https://registry.npmjs.org/{g}/-/{g}-{v}.tgz"}
                        for g, v in npm}},
    }, indent=2), encoding="utf-8")

    pip = [(g, v) for h, g, v, _ in DAP_AN if h == "pip"]
    (goc / "requirements.txt").write_text(
        "".join(f"{g}=={v}\n" for g, v in pip), encoding="utf-8")

    mvn = [(g, v) for h, g, v, _ in DAP_AN if h == "maven"]
    deps = "".join(
        f"    <dependency>\n      <groupId>{g.split(':')[0]}</groupId>\n"
        f"      <artifactId>{g.split(':')[1]}</artifactId>\n"
        f"      <version>{v}</version>\n    </dependency>\n" for g, v in mvn)
    (goc / "pom.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>fixture</groupId>\n  <artifactId>sca</artifactId>\n"
        "  <version>1.0.0</version>\n  <dependencies>\n" + deps +
        "  </dependencies>\n</project>\n", encoding="utf-8")

    ng = [(g, v) for h, g, v, _ in DAP_AN if h == "nuget"]
    (goc / "packages.lock.json").write_text(json.dumps({
        "version": 1,
        "dependencies": {"net8.0": {g: {"type": "Direct", "requested": f"[{v}, )",
                                        "resolved": v} for g, v in ng}},
    }, indent=2), encoding="utf-8")

    print(f"[*] Da sinh fixture o {goc}")
    for h in ("npm", "pip", "maven", "nuget"):
        co = sum(1 for e, _, _, x in DAP_AN if e == h and x)
        sach = sum(1 for e, _, _, x in DAP_AN if e == h and not x)
        print(f"      {h:6} {co} goi co lo hong, {sach} goi sach")


def doc_trivy(p: Path) -> list[tuple[str, str]]:
    """SARIF cua Trivy -> [(ten_goi, phien_ban)] bi bao.

    Trivy dat ten rule la CVE/GHSA va dua "pkgName@version" vao message hoac
    vao locations. Doc ca hai cho roi hop lai, de khong phu thuoc mot dinh dang.
    """
    d = json.loads(p.read_text(encoding="utf-8"))
    ra = set()
    for run in d.get("runs", []):
        for res in run.get("results", []):
            txt = json.dumps(res, ensure_ascii=False)
            # Trivy ghi dang "Package: lodash" / "Installed Version: 4.17.15"
            g = re.search(r"Package:\s*([^\\\"\n,]+)", txt)
            v = re.search(r"Installed Version:\s*([^\\\"\n,]+)", txt)
            if g and v:
                ra.add((g.group(1).strip(), v.group(1).strip()))
                continue
            # du phong: "goi@phienban" trong message
            for m in re.finditer(r"([A-Za-z0-9._:\-]+)@([0-9][0-9A-Za-z.\-]*)", txt):
                ra.add((m.group(1), m.group(2)))
    return sorted(ra)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sinh", required=True, help="thu muc tam de sinh fixture")
    ap.add_argument("--trivy-sarif", default="", help="SARIF cua trivy fs; co thi cham diem")
    ap.add_argument("--md", default="")
    a = ap.parse_args()

    goc = Path(a.sinh)
    sinh(goc)
    if not a.trivy_sarif:
        print("\nKhong co --trivy-sarif nen chi sinh fixture, khong cham diem.")
        return 0

    p = Path(a.trivy_sarif)
    if not p.is_file():
        print(f"HONG: khong thay {p}. Trivy khong ra SARIF nghia la KHONG QUET DUOC, "
              f"khong phai 'sach'.")
        return 1

    bao = doc_trivy(p)
    bao_chuan = {(g.lower(), v) for g, v in bao}

    def bi_bao(goi: str, pb: str) -> bool:
        # maven ghi groupId:artifactId; Trivy co the chi ghi artifactId
        ten = [goi.lower()]
        if ":" in goi:
            ten.append(goi.split(":")[-1].lower())
        return any((t, pb) in bao_chuan for t in ten)

    md = ["### Phòng đo tầng SCA — thư viện đã có trong repo", "",
          "| Hệ sinh thái | Gói | Phiên bản | Đáp án | Trivy fs |",
          "|---|---|---|---|---|"]
    tp = fp = fn = tn = 0
    for he, goi, pb, co_loi in DAP_AN:
        thay = bi_bao(goi, pb)
        if co_loi and thay: tp += 1; o = "✅ bắt được"
        elif co_loi and not thay: fn += 1; o = "❌ **bỏ sót**"
        elif not co_loi and thay: fp += 1; o = "❌ **báo nhầm**"
        else: tn += 1; o = "✅ không báo"
        md.append(f"| {he} | `{goi}` | {pb} | {'có lỗ hổng' if co_loi else 'sạch'} | {o} |")

    co = tp + fn
    sach = fp + tn
    md += ["",
           f"**Bắt {tp}/{co} gói có lỗ hổng ({tp/co:.0%}) · báo nhầm {fp}/{sach} gói sạch "
           f"({fp/sach:.0%})**", "",
           f"Trivy báo tổng {len(bao)} cặp gói@phiên-bản trên fixture.", "",
           "> Tỉ lệ **bắt** của tầng này ổn định theo thời gian: lỗ hổng đã công bố không "
           "biến mất. Tỉ lệ **báo nhầm** thì không — một phiên bản hôm nay sạch, mai có "
           "advisory mới thì thành có lỗ hổng, mà đáp án ở đây vẫn ghi là sạch. Nên con số "
           "báo nhầm phải đọc kèm ngày đo, và các dòng *sạch* cần xem lại định kỳ. Đây là "
           "khác biệt bản chất so với phòng đo SAST, nơi đáp án không đổi theo thời gian.", ""]

    text = "\n".join(md)
    if a.md:
        Path(a.md).write_text(text, encoding="utf-8")
    print()
    print(text)
    # Bo sot goi dinh lo hong da cong bo la that bai cua tang, khong phai canh bao.
    return 1 if fn else 0


if __name__ == "__main__":
    sys.exit(main())
