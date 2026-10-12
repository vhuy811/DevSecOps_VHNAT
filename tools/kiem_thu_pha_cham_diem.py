#!/usr/bin/env python3
"""Kiem thu NGUOC cho bo cham: pha cham_diem.py roi doi hoi phep kiem phai HONG.

VI SAO CAN TEP NAY NGOAI kiem_thu_cham_diem.py
Mot bo kiem thu dat het ngay lan chay dau khong chung minh dieu gi - no co the
dat vi khong kiem gi ca. Trong chinh phien lam viec nay, mot "chot" tu viet da
dat du no chi dem so lan xuat hien cua mot chuoi, va chi lo ra khi bi pha.
Nen moi phep kiem trong kiem_thu_cham_diem.py phai co mot cach PHA tuong ung o
day, kem cau tra loi cho: neu lap trinh vien lam sai dung cho nay thi con so
nao trong bao cao sai, va sai theo huong nao.

Hai muc trong danh sach duoi la LOI THAT da xay ra trong du an nay (nhanh
"throws" cua sig_re, va bo tien to nguon) - giu lai de khong tai pham.

CACH LAM: moi lan pha lam tren mot BAN COPY trong thu muc tam, khong bao gio
sua tep trong repo.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHAM = "tools/cham_diem.py"
KIEM = "tools/kiem_thu_cham_diem.py"

# (ten cach pha, chuoi trong cham_diem.py, chuoi thay the)
# Moc phai xuat hien DUNG MOT LAN - neu khong, cach pha nay khong con dung voi
# ma hien tai va phai duoc sua, chu khong phai bo qua.
PHA: list[tuple[str, str, str]] = [
    ("sig_re thieu nhanh 'throws' -> khong doc duoc ham nao trong tep Java",
     r'|throws\s+[\w.<>,\s]+)?$")',
     r')?$")'),
    ("vai_tro_tep luon tra None -> bien the 81 mat vai tro",
     'return "bad" if duoi == "bad" else "good"',
     'return None'),
    ("bo kiem ho CWE -> nhan moi canh bao la dung de",
     'if not (r["cwes"] and ho_cua(cases[cid]["cwe"]) & set().union(*(ho_cua(c) for c in r["cwes"]))):\n'
     '                continue',
     'if False:\n                continue'),
    ("khong dem canh bao ngoai corpus -> mat dau hieu doc sai ten tep",
     '        t = tep.get(r["file"])\n            if not t:\n'
     '                khong_gan += 1\n                continue',
     '        t = tep.get(r["file"])\n            if not t:\n                continue'),
    ("vai_tro_tai chi lay ham trong cung -> bao nham trong ham long bi bo",
     'for ten, _, _ in bao:\n        v = vai_tro(ten)\n        if v:\n'
     '            return v\n    return vt_tep',
     'for ten, _, _ in bao[:1]:\n        v = vai_tro(ten)\n        if v:\n'
     '            return v\n    return vt_tep'),
    ("dieu_kien_chan bi lam ngo -> rule muc warning cung tinh la chan duoc",
     'def dieu_kien_chan(spec: str):',
     'def dieu_kien_chan(spec: str):\n    return lambda r: True'),
    ("bat_rieng tinh ca chinh no -> luon ra 0, ket luan 'bo rule nao cung mien phi'",
     'khac = set().union(*[w["tp"] for q, w in theo.items() if q != r]) if len(theo) > 1 else set()',
     'khac = set().union(*[w["tp"] for q, w in theo.items()])'),
]


def main() -> int:
    lo: list[str] = []
    for ten, cu, moi in PHA:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "ban-copy"
            shutil.copytree(REPO / "tools", d / "tools")
            p = d / CHAM
            s = p.read_text(encoding="utf-8")
            n = s.count(cu)
            if n != 1:
                print(f"[HONG] {ten}\n       -> moc xuat hien {n} lan trong "
                      f"cham_diem.py, cach pha nay khong con dung voi ma hien tai")
                lo.append(ten)
                continue
            p.write_text(s.replace(cu, moi, 1), encoding="utf-8")
            r = subprocess.run([sys.executable, "-I", str(d / KIEM)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                bat = [l.strip() for l in r.stdout.splitlines() if "[HONG]" in l]
                print(f"[DAT ] {ten}")
                for l in bat[:2]:
                    print(f"       {l}")
            else:
                print(f"[LO  ] {ten}\n       -> da pha bo cham ma phep kiem VAN DAT: "
                      f"kiem_thu_cham_diem.py co lo o cho nay")
                lo.append(ten)
    print()
    if lo:
        print(f"HONG {len(lo)}/{len(PHA)} cach pha khong bi bat:")
        for x in lo:
            print(f"  - {x}")
        return 1
    print(f"DAT het {len(PHA)}/{len(PHA)}: moi cach pha bo cham deu bi phep kiem bat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
