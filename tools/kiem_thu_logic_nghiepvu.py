#!/usr/bin/env python3
"""Cham corpus "logic nghiep vu": ma DUNG ma trong nhu loi.

VI SAO CAN TEP NAY
Hai bo do hien co (Juliet, BenchProctor) deu la ma SINH RA DE DO: moi case sach
la mot case loi duoc sua vua du. Ti le bao nham do tren do noi ve corpus do,
khong noi ve ma ung dung that. Hai cho trong do an dang bi chan lai vi thieu
dung con so nay:

  1. dso-weak-hash va dso-weak-random bat 100% voi 0% bao nham tren Juliet
     nhung van de muc WARNING nen KHONG chan duoc A02. Ly do da ghi trong
     PHU_OWASP.md: Juliet khong co lan nao dung MD5 HOP LE (checksum, cache
     key, ETag), nen 0% bao nham o do khong noi gi ve ma that.
  2. Cac rule vua mo rong nguon (os.environ, $RS.getString, $X.readLine) deu co
     mot dang dung hop le pho bien ma corpus sinh tu dong khong chua.

DAP AN: 0 canh bao o muc CO QUYEN CHAN. Moi canh bao muc chan trong thu muc
corpus la mot lan CHAN OAN - mot lan pipeline chan merge cua ma dung.

Dinh nghia "co quyen chan" lay tu dieu_kien_chan() cua cham_diem.py, DUNG mot
ham voi cac phong do khac - neu khong, hai cho se tra loi khac nhau cho cung
cau hoi "cai nay co chan khong".

Dau ra khong chi noi "co canh bao": no in kem lap luan "vi sao an toan" ma
chinh tep corpus ghi cho ham do, de nguoi doc quyet duoc ngay la rule sai hay
corpus sai.
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cham_diem import dieu_kien_chan, doc_sarif          # noqa: E402

DUOI = {".cs", ".py", ".java", ".js", ".ts"}
# Chu thich ngay tren ham: "// Vi sao an toan: ..." hoac "# Vi sao an toan: ..."
LY_LE_RE = re.compile(r"(?:#|//)\s*Vi sao an toan:\s*(.+)", re.I)
VIEC_RE = re.compile(r"(?:#|//)\s*Viec nghiep vu:\s*(.+)", re.I)


def doc_ly_le(p: Path) -> list[tuple[int, str, str]]:
    """[(dong_bat_dau_khoi, viec_nghiep_vu, ly_le_an_toan)] theo thu tu trong tep."""
    ra = []
    dong = p.read_text(encoding="utf-8", errors="replace").splitlines()
    viec = ly_le = None
    bd = 0
    for i, l in enumerate(dong, 1):
        mv = VIEC_RE.search(l)
        if mv:
            viec, ly_le, bd = mv.group(1).strip(), None, i
            continue
        ml = LY_LE_RE.search(l)
        if ml:
            ly_le = ml.group(1).strip()
            # gom cac dong tiep la phan noi dai cua ly le
            ra.append((bd, viec or "(khong ghi)", ly_le))
    return ra


def ly_le_gan_nhat(ds: list[tuple[int, str, str]], line: int) -> tuple[str, str]:
    truoc = [x for x in ds if x[0] <= line]
    if not truoc:
        return ("(khong tim duoc)", "(khong tim duoc)")
    x = max(truoc, key=lambda y: y[0])
    return (x[1], x[2])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--goc", required=True,
                    help="thu muc corpus logic nghiep vu")
    ap.add_argument("--sarif", action="append", default=[],
                    metavar="TEN=DUONG", help="ten_cong_cu=duong_dan.sarif")
    ap.add_argument("--chan", action="append", default=[],
                    metavar="TEN:DIEU_KIEN",
                    help='vd "semgrep-du-an:level=error" hoac "codeql:sev>=4"')
    ap.add_argument("--md", help="ghi bang ket qua dang Markdown")
    a = ap.parse_args()

    goc = Path(a.goc)
    if not goc.is_dir():
        print(f"Khong thay thu muc corpus: {goc}")
        return 2
    # Corpus PHAI nam duoi mot thu muc "kiem-thu-rule". Pipeline that loai tru
    # theo TEN THU MUC do o ca ba cho (semgrep --exclude, grep --exclude-dir,
    # paths-ignore cua CodeQL), nen dat o day la cach corpus thua huong bo loai
    # tru. Neu ai doi no sang cho khac thi chinh pipeline cua toolkit se quet
    # mot corpus "trong nhu loi" va chan merge cua chinh repo nay - mot cai bay
    # im lang, vi job nay van DAT trong khi PR that bat dau do.
    if "kiem-thu-rule" not in goc.resolve().parts:
        print(f"Corpus dat sai cho: {goc}\n"
              f"Phai nam duoi mot thu muc 'kiem-thu-rule' de thua huong bo loai "
              f"tru cua pipeline that (devsecops-reusable.yml loai tru theo ten "
              f"thu muc nay o ca Semgrep, grep nosem va CodeQL paths-ignore).")
        return 2
    tep = {p.name: p for p in goc.rglob("*") if p.suffix in DUOI}
    if not tep:
        print(f"Thu muc {goc} khong co tep ma nguon nao - corpus rong thi phep "
              f"kiem nay luon DAT ma khong kiem gi")
        return 2
    ly_le = {ten: doc_ly_le(p) for ten, p in tep.items()}

    # Ham nao khong ghi du "Viec nghiep vu" + "Vi sao an toan" thi khong thuoc
    # bo do nay - rat de tu lua bang cach them mot ham "an toan" ma chinh minh
    # cung khong chac.
    thieu = [ten for ten, ds in ly_le.items() if not ds]
    if thieu:
        print(f"Tep corpus khong ghi 'Viec nghiep vu' / 'Vi sao an toan': {thieu}")
        return 2

    dk = {}
    for spec in a.chan:
        ten, _, d = spec.partition(":")
        dk.setdefault(ten, []).append(dieu_kien_chan(d))

    chan, chi_bao, ngoai = [], [], 0
    for s in a.sarif:
        ten, duong = s.split("=", 1)
        if not Path(duong).is_file():
            print(f"::warning::Thieu SARIF cua {ten}: {duong} - bo qua cong cu nay")
            continue
        for r in doc_sarif(Path(duong)):
            if r["file"] not in tep:
                ngoai += 1
                continue
            co_chan = any(f(r) for f in dk.get(ten, []))
            (chan if co_chan else chi_bao).append((ten, r))

    md = [f"### Corpus logic nghiệp vụ — {len(tep)} tệp, {sum(len(v) for v in ly_le.values())} hàm",
          "",
          "Đáp án: **0 cảnh báo ở mức có quyền chặn**. Mỗi dòng trong bảng dưới là "
          "một lần pipeline sẽ **chặn oan** merge của mã đúng.", ""]

    if chan:
        md += ["#### Chặn oan", "",
               "| Công cụ | Rule | Tệp:dòng | Việc nghiệp vụ | Vì sao mã này an toàn |",
               "|---|---|---|---|---|"]
        for ten, r in chan:
            v, l = ly_le_gan_nhat(ly_le[r["file"]], r["line"])
            md.append(f"| {ten} | `{r['rule']}` | {r['file']}:{r['line']} | {v} | {l} |")
        md.append("")
    else:
        md += ["Không có cảnh báo nào ở mức chặn. ✅", ""]

    if chi_bao:
        md += [f"#### Mức chỉ báo (không chặn) — {len(chi_bao)} cảnh báo", "",
               "Không tính là sai: đây là lựa chọn có chủ đích — báo cho người "
               "review đọc, không chặn merge.", "",
               "| Công cụ | Rule | Tệp:dòng | Việc nghiệp vụ |", "|---|---|---|---|"]
        for ten, r in chi_bao:
            v, _ = ly_le_gan_nhat(ly_le[r["file"]], r["line"])
            md.append(f"| {ten} | `{r['rule']}` | {r['file']}:{r['line']} | {v} |")
        md.append("")

    md += [f"> Cảnh báo ngoài thư mục corpus (không tính): {ngoai}.", ""]
    text = "\n".join(md)
    if a.md:
        Path(a.md).parent.mkdir(parents=True, exist_ok=True)
        Path(a.md).write_text(text, encoding="utf-8")
    print(text)

    if chan:
        print(f"THAT BAI: {len(chan)} canh bao muc CHAN tren ma dung.")
        print("Moi dong tren la mot lan chan oan. Doc cot 'vi sao an toan' roi "
              "quyet: hoac rule can thu hep, hoac case trong corpus viet sai.")
        return 1
    print(f"DAT: 0 chan oan tren {len(tep)} tep "
          f"({sum(len(v) for v in ly_le.values())} ham), {len(chi_bao)} canh bao muc chi bao.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
