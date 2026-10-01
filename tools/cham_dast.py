#!/usr/bin/env python3
"""
Cham ket qua ZAP voi dap an biet truoc - phong do cho tang DAST (G3.1).

VI SAO CAN
Pipeline quet toan bo VulnShop-App bang ZAP nhung hai lan bo sot SQL injection
that: /Product/Filter (PR #1) va /Product/TimNhanh (PR #4). Moi lan ZAP chi
bao loi header. Truoc khi sua, can DO: cung mot ban code co loi, ZAP voi cau
hinh nao bat duoc, cau hinh nao khong, ton them bao nhieu thoi gian.

Tep nay so alert ZAP (JSON cua dast_scan.py) voi danh sach lo hong da biet cua
tung ban code thu, in bang Markdown: lo hong nao bat duoc o cau hinh nao, bang
payload gi, va so alert High ngoai dap an (de thay cai gia bao nham).

    python tools/cham_dast.py --muc-tieu ground-truth \
        --ket-qua mac-dinh=A.json --ket-qua cao=B.json >> $GITHUB_STEP_SUMMARY
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Dap an: (duong dan, tham so, CWE) cua lo hong THAT trong tung ban code thu.
# Lay tu ground_truth.csv cua VulnShop-App va hai commit da bi bo sot.
DAP_AN: dict[str, list[tuple[str, str, str]]] = {
    # tag ground-truth: C1-C4 (C5, C6 da khu doc - KHONG duoc bat)
    "ground-truth": [
        ("/Product/Search", "q", "89"),
        ("/Product/Detail", "id", "89"),
        ("/Product/Echo", "msg", "79"),
        ("/Product/Greet", "name", "79"),
    ],
    # d017808 (PR #4): SQLi qua ham phu DocSanPham, ngu canh LIKE '%...%'
    "tim-nhanh": [("/Product/TimNhanh", "tu", "89")],
    # 217f476 (PR #1, truoc khi va): SQLi ngu canh Category = '...'
    "loc": [("/Product/Filter", "category", "89")],
}
# Cung CWE goc: ZAP gan XSS phan xa la 79, SQLi la 89.
HO_CWE = {"89": {"89"}, "79": {"79", "80"}}


def duong(url: str) -> str:
    p = url.split("?")[0]
    i = p.find("/", p.find("//") + 2) if "//" in p else 0
    return p[i:] if i > 0 else p


def doc(tep: str) -> dict:
    """Chi doc tep nam trong thu muc lam viec (workspace cua CI)."""
    goc = os.path.realpath(os.getcwd())
    thuc = os.path.realpath(tep)
    if not thuc.startswith(goc + os.sep):
        raise OSError(f"{tep} nam ngoai thu muc lam viec")
    with open(thuc, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--muc-tieu", required=True, choices=sorted(DAP_AN))
    ap.add_argument("--ket-qua", action="append", required=True,
                    help="ten=tep.json (lap lai cho tung cau hinh)")
    a = ap.parse_args()

    cau_hinh = []
    for kv in a.ket_qua:
        ten, _, tep = kv.partition("=")
        try:
            cau_hinh.append((ten, doc(tep)))
        except (OSError, json.JSONDecodeError) as e:
            print(f"> ⚠ `{ten}`: không đọc được {tep} ({e}) — cấu hình này chưa chạy xong.\n")
    if not cau_hinh:
        return 1

    dap_an = DAP_AN[a.muc_tieu]
    print(f"### Phòng đo DAST — `{a.muc_tieu}`\n")
    print("| Lỗ hổng thật | " + " | ".join(f"`{t}`" for t, _ in cau_hinh) + " |")
    print("|---|" + "---|" * len(cau_hinh))
    for path, ts, cwe in dap_an:
        o = []
        for _, d in cau_hinh:
            trung = [x for x in d.get("alerts", [])
                     if duong(x.get("url", "")) == path and x.get("param") == ts
                     and x.get("cweid") in HO_CWE[cwe]]
            if trung:
                x = max(trung, key=lambda x: {"High": 3, "Medium": 2, "Low": 1}.get(x["risk"], 0))
                tan_cong = (x.get("attack") or "").replace("|", "\\|")[:60]
                o.append(f"✅ {x['alert']} ({x['risk']}) `{tan_cong}`")
            else:
                o.append("❌ bỏ sót")
        print(f"| CWE-{cwe} `{path}?{ts}=` | " + " | ".join(o) + " |")

    def ngoai(d: dict) -> list[dict]:
        """Alert High khong ung voi lo hong nao trong dap an.

        Cung duong dan + cung ho CWE nhung khac tham so (vd. rule XSS DOM bao
        voi tham so rong tren chinh trang Echo) van tinh la TRUNG lo hong da
        biet, khong phai bao nham.
        """
        ra = []
        for x in d.get("alerts", []):
            if x.get("risk") != "High":
                continue
            p = duong(x.get("url", ""))
            if any(p == dp and x.get("cweid") in HO_CWE[dc] for dp, _, dc in dap_an):
                continue
            ra.append(x)
        return ra

    print("| High ngoài đáp án (báo nhầm) | " + " | ".join(str(len(ngoai(d))) for _, d in cau_hinh) + " |")
    print("| Thời gian quét (giây) | " + " | ".join(
        f"{d.get('giay', '?')}{' ⚠ quá giờ' if d.get('timed_out') else ''}" for _, d in cau_hinh) + " |")
    print("| Rule được chỉnh | " + " | ".join(str(len(d.get("rule_da_chinh", []))) for _, d in cau_hinh) + " |")
    print()
    for ten, d in cau_hinh:
        ds = ngoai(d)
        if not ds:
            continue
        print(f"<details><summary>`{ten}`: {len(ds)} alert High ngoài đáp án</summary>\n")
        print("| Alert | Đường dẫn | Tham số | Payload | Bằng chứng |")
        print("|---|---|---|---|---|")
        for x in ds:
            o = [x.get("alert", ""), duong(x.get("url", "")), x.get("param", ""),
                 (x.get("attack") or "")[:80], (x.get("evidence") or "")[:80]]
            print("| " + " | ".join("`" + str(v).replace("|", "\\|").replace("`", "'") + "`" if v else "" for v in o) + " |")
        print("\n</details>\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
