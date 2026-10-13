#!/usr/bin/env python3
"""Dap an cho tang T0 (Gitleaks): bat duoc secret nao, va bao nham cai gi.

VI SAO CAN TEP NAY
Tang secret la mot trong hai tang CHUA CO BO DO nao (xem KET_QUA_DO.md muc 5).
Pipeline chay Gitleaks voi cau hinh MAC DINH, va cho den gio khong ai biet no
bat duoc gi: bao cao chi noi "Gitleaks: N phat hien", ma N=0 co the nghia la
"ma nguon sach" hoac "khong rule nao khop" - hai dieu rat khac nhau.

FIXTURE SINH LUC CHAY, KHONG COMMIT. Day khong phai chon cho gon ma la bat
buoc, vi hai ly do:
  1. GitHub co push protection: commit mot chuoi CO HINH DANG secret that se
     lam GitHub CHAN ca lan push, keo theo moi commit khac trong nhanh. Mot bo
     do lam nguoi ta khong push duoc la mot bo do hong.
  2. Tep "secret mau" nam trong repo se bi chinh Gitleaks cua pipeline bat o
     moi lan chay, sinh canh bao vinh vien.
Cung ly do do voi tools/kiem_thu_sca.py - fixture SCA cung sinh luc chay.

GIA TRI DEU LA GIA. Chung dung HINH DANG that (tien to, do dai, bo ky tu) de
rule khop duoc, nhung phan ngau nhien sinh tu seed co dinh nen khong trung voi
bat ky khoa that nao. Khong chuoi nao trong tep nay la mot credential song.

HAI MUC TRONG DAP AN
  - chac_chan: toi biet ket qua dung phai la gi. Sai o day la sai THAT.
      * secret co hinh dang chuan ma KHONG bat duoc  -> bo sot
      * placeholder kieu "<dien-khoa-cua-ban>" ma BI bat -> bao nham
  - can_do: toi KHONG biet Gitleaks mac dinh xu ly the nao (vi du chuoi
    entropy cao nhung khong co tien to). In ra de doc, KHONG khang dinh.
    Lan chay dau se cho biet, va luc do moi chuyen chung sang chac_chan kem
    ghi chu - doan truoc roi khang dinh la cach tu lua.
"""
import argparse
import json
import random
import string
import sys
from pathlib import Path

# Seed co dinh: cung mot fixture moi lan chay, de so do so sanh duoc giua cac
# lan. Khong dung secrets/urandom o day - bo do phai tai lap duoc.
NN = random.Random(20261009)


# Tien to cua tung loai khoa duoc GHEP tu hai manh, KHONG viet lien mot khoi.
#
# VI SAO: GitHub push protection quet chinh TEP NAY. Ban dau viet lien khoi va
# no CHAN ca lan push, bat o dong moi:
#       STRIPE_KEY=<tien to sk-live><24 chu x>
# tuc 24 chu "x" lien tiep - mot placeholder ma nguoi doc nao cung nhan ra.
# Day chinh la cai MOI viet ra de do BAO NHAM cua Gitleaks, va no lai bi mot bo
# quet khac bao nham. Mot phat hien dang ghi: hai bo quet khong dong y nhau tren
# cung mot chuoi, va o day GitHub la ben sai.
#
# Ghep tu hai manh thi trong tep khong con chuoi nao khop mau cua bo quet, trong
# khi gia tri SINH RA LUC CHAY van nguyen ven nen Gitleaks van phai bat duoc.
# Day khong phai cach "lach" bo quet: tep nay khong chua secret that nao ca.
TIEN_TO = {
    "aws":    "AK" + "IA",
    "github": "gh" + "p_",
    "slack":  "xox" + "b-",
    "stripe": "sk_" + "live_",
    "google": "AI" + "za",
    "npm":    "np" + "m_",
}


def ngau(n: int, bo: str = string.ascii_letters + string.digits) -> str:
    return "".join(NN.choice(bo) for _ in range(n))


def khoi_khoa_rieng() -> str:
    than = "\n".join(ngau(64, string.ascii_letters + string.digits + "+/") for _ in range(6))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{than}\n-----END RSA PRIVATE KEY-----"


# (ten_tep, noi_dung, phai_bat, muc, mo_ta)
#   phai_bat True  = day la secret, Gitleaks PHAI bat
#   phai_bat False = day KHONG phai secret, Gitleaks KHONG duoc bat
#   muc "chac_chan" = khang dinh | "can_do" = chi do, khong khang dinh
def dap_an() -> list[tuple[str, str, bool, str, str]]:
    aws_id = TIEN_TO["aws"] + ngau(16, string.ascii_uppercase + string.digits)
    return [
        # ---------------- PHAI BAT, chac chan ----------------
        ("aws_config.txt",
         f'aws_access_key_id = {aws_id}\n'
         f'aws_secret_access_key = {ngau(40, string.ascii_letters + string.digits + "+/")}\n',
         True, "chac_chan", "cap khoa AWS dang chuan (tien to AK-IA + secret 40 ky tu)"),
        ("ci_token.sh",
         f'export GITHUB_TOKEN={TIEN_TO["github"]}{ngau(36)}\n',
         True, "chac_chan", "GitHub personal access token (tien to gh-p)"),
        ("slack_hook.py",
         f'BOT_TOKEN = "{TIEN_TO["slack"]}{NN.randrange(10**11, 10**12)}-'
         f'{NN.randrange(10**11, 10**12)}-{ngau(24)}"\n',
         True, "chac_chan", "Slack bot token (tien to xox-b)"),
        ("thanh_toan.cs",
         f'const string StripeKey = "{TIEN_TO["stripe"]}{ngau(24)}";\n',
         True, "chac_chan", "Stripe live secret key (tien to sk-live)"),
        ("deploy_key",
         khoi_khoa_rieng() + "\n",
         True, "chac_chan", "khoi khoa rieng RSA (BEGIN RSA PRIVATE KEY)"),
        ("maps.js",
         f'const key = "{TIEN_TO["google"]}{ngau(35)}";\n',
         True, "chac_chan", "Google API key (tien to AI-za)"),
        ("npmrc_mau.txt",
         f'//registry.npmjs.org/:_authToken={TIEN_TO["npm"]}{ngau(36)}\n',
         True, "chac_chan", "npm access token (tien to np-m)"),

        # ---------------- KHONG DUOC BAT, chac chan ----------------
        ("env_mau.txt",
         'AWS_SECRET_ACCESS_KEY=<dien-khoa-cua-ban-vao-day>\n'
         'DB_PASSWORD=<thay-bang-mat-khau-that>\n'
         f'STRIPE_KEY={TIEN_TO["stripe"]}{"x" * 24}\n',
         False, "chac_chan", "tep .env mau toan placeholder - dang pho bien nhat "
                             "trong repo that, bao nham o day la bao nham moi repo"),
        ("doc_huong_dan.md",
         'Dat bien moi truong truoc khi chay:\n\n'
         '```\nexport API_KEY=changeme\nexport DB_PASSWORD=changeme\n```\n\n'
         f'Khoa vi du cua AWS trong tai lieu chinh thuc: {TIEN_TO["aws"]}IOSFODNN7EXAMPLE\n',
         False, "chac_chan", "tai lieu huong dan: gia tri 'changeme' va khoa VI DU "
                             "da duoc cong bo cua AWS"),
        ("doc_cau_hinh.py",
         'import os\n\n'
         '# Doc tu moi truong, khong viet cung\n'
         'API_KEY = os.environ["API_KEY"]\n'
         'DB_PASSWORD = os.environ.get("DB_PASSWORD", "")\n',
         False, "chac_chan", "doc tu bien moi truong - dung cach, khong co gia tri nao"),
        ("khoa_cong_khai.pem",
         "-----BEGIN PUBLIC KEY-----\n"
         + "\n".join(ngau(64, string.ascii_letters + string.digits + "+/") for _ in range(4))
         + "\n-----END PUBLIC KEY-----\n",
         False, "chac_chan", "khoa CONG KHAI - entropy cao nhung cong khai la dung "
                             "ban chat cua no"),

        # ---------------- CAN DO, khong khang dinh ----------------
        ("phien_ban.json",
         json.dumps({"commit": ngau(40, "0123456789abcdef"),
                     "build_id": "550e8400-e29b-41d4-a716-446655440000",
                     "released": "2026-10-09"}, indent=2) + "\n",
         False, "can_do", "SHA commit 40 ky tu hex va UUID - entropy cao nhung "
                          "khong phai secret. Chua ro Gitleaks mac dinh co bat khong"),
        ("anh_nhung.html",
         '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB'
         + ngau(180, string.ascii_letters + string.digits + "+/") + '">\n',
         False, "can_do", "anh PNG nhung dang data URI - khoi base64 dai, "
                          "chua ro rule entropy co bat khong"),
        ("khoa_chung.conf",
         f'secret_key = {ngau(48)}\n',
         True, "can_do", "gan 'secret_key' voi chuoi entropy cao NHUNG khong co "
                         "tien to nha cung cap nao. Day la dang secret tu quan ly "
                         "pho bien nhat; chua ro rule generic co bat khong"),
    ]


def sinh(d: Path) -> dict:
    d.mkdir(parents=True, exist_ok=True)
    ra = {}
    for ten, noi_dung, phai_bat, muc, mo_ta in dap_an():
        (d / ten).write_text(noi_dung, encoding="utf-8")
        ra[ten] = (phai_bat, muc, mo_ta)
    return ra


def doc_phat_hien(sarif: Path) -> dict[str, list[str]]:
    """ten_tep -> danh sach rule da bao."""
    if not sarif.is_file():
        return {}
    d = json.loads(sarif.read_text(encoding="utf-8"))
    ra: dict[str, list[str]] = {}
    for run in d.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            ten = Path(loc.get("artifactLocation", {}).get("uri", "")).name
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id", "?")
            ra.setdefault(ten, []).append(rid)
    return ra


# ---------------------------------------------------------------------------
# TU KIEM: chinh ham cham diem co cham dung khong?
# ---------------------------------------------------------------------------
# Tang T0 bao "0 phat hien" tren ung dung that - va do la ket qua DUNG, vi kho
# ma khong co secret nao. Nhung "0 phat hien" cung la ket qua cua mot tang MU
# HOAN TOAN. Hai truong hop do khong phan biet duoc neu khong co fixture, va
# ham cham diem hong thi ca fixture cung khong cuu duoc. --tu-kiem do rieng ham
# do bang SARIF dung san: khong Gitleaks, khong mang.
def _sarif_gia(tep: list[str]) -> dict:
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "gitleaks", "rules": []}},
        "results": [{"ruleId": "generic-api-key",
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": t}}}]} for t in tep]}]}


def _tu_kiem() -> int:
    import io
    import tempfile
    from contextlib import redirect_stdout

    ds = [(ten, pb, muc) for ten, _, pb, muc, _mo in dap_an()]
    phai_bat = [t for t, pb, muc in ds if pb and muc != "can_do"]
    khong_bat = [t for t, pb, muc in ds if not pb and muc != "can_do"]

    ca = [
        ("bat dung het secret, im tren tep moi", phai_bat, 0),
        ("bo sot MOT secret", phai_bat[1:], 1),
        ("bao nham MOT tep moi (vi du .env mau)", phai_bat + khong_bat[:1], 1),
        ("khong bao gi - tang secret mu hoan toan", [], 1),
        ("bao moi tep - cong cu bao bua", phai_bat + khong_bat, 1),
    ]
    print("### Tu kiem ham cham diem cua phong do secret\n")
    print("| Ca | Ma mong doi | Ma that | Ket qua |")
    print("|---|---|---|---|")
    hong = 0
    with tempfile.TemporaryDirectory() as td:
        for ten, tep, cho in ca:
            f = Path(td) / "gia.sarif"
            f.write_text(json.dumps(_sarif_gia(tep)), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                ma = _cham(f, None)
            dat = ma == cho
            hong += 0 if dat else 1
            print(f"| {ten} | {cho} | {ma} | {'DAT' if dat else 'HONG'} |")
    print()
    if hong:
        print(f"**HONG** - {hong}/{len(ca)} ca tu kiem sai.")
        return 1
    print(f"**DAT** - {len(ca)}/{len(ca)} ca. Ham cham diem phan biet duoc bo sot, "
          f"bao nham va mu hoan toan.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sinh", metavar="THU_MUC",
                    help="sinh fixture vao thu muc nay roi thoat")
    ap.add_argument("--sarif", help="SARIF cua Gitleaks sau khi quet fixture")
    ap.add_argument("--md", help="ghi bang ket qua dang Markdown")
    ap.add_argument("--tu-kiem", action="store_true",
                    help="do rieng ham cham diem bang SARIF dung san (khong can Gitleaks)")
    a = ap.parse_args()

    if a.tu_kiem:
        return _tu_kiem()

    if a.sinh:
        ds = sinh(Path(a.sinh))
        print(f"Da sinh {len(ds)} tep fixture vao {a.sinh}")
        for ten, (pb, muc, mo_ta) in ds.items():
            print(f"  {'PHAI BAT ' if pb else 'KHONG BAT'} [{muc:9}] {ten:22} {mo_ta[:60]}")
        return 0

    if not a.sarif:
        print("Can --sinh THU_MUC hoac --sarif TEP")
        return 2

    return _cham(Path(a.sarif), Path(a.md) if a.md else None)


def _cham(sarif: Path, md_ra: Path | None) -> int:
    """Doi chieu SARIF cua Gitleaks voi dap an. Tra ve ma thoat."""
    ds = {ten: (pb, muc, mo) for ten, _, pb, muc, mo in dap_an()}
    thay = doc_phat_hien(sarif)

    bat, sot, nham, sach, do_them = [], [], [], [], []
    for ten, (phai_bat, muc, mo_ta) in ds.items():
        co = ten in thay
        rule = ", ".join(sorted(set(thay.get(ten, [])))) or "-"
        if muc == "can_do":
            do_them.append((ten, phai_bat, co, rule, mo_ta))
        elif phai_bat and co:
            bat.append((ten, rule, mo_ta))
        elif phai_bat and not co:
            sot.append((ten, mo_ta))
        elif not phai_bat and co:
            nham.append((ten, rule, mo_ta))
        else:
            sach.append((ten, mo_ta))

    n_pb = len(bat) + len(sot)
    n_kb = len(nham) + len(sach)
    md = ["### Phòng đo tầng secret — Gitleaks (cấu hình mặc định)", "",
          f"Fixture sinh lúc chạy, **không commit** — {len(ds)} tệp. Giá trị đều là giả, "
          "dùng hình dạng thật (tiền tố, độ dài) để rule khớp được.", "",
          "| | số case | kết quả |", "|---|---|---|",
          f"| Secret phải bắt (chắc chắn) | {n_pb} | bắt **{len(bat)}**, "
          f"**bỏ sót {len(sot)}** |",
          f"| Không phải secret (chắc chắn) | {n_kb} | im lặng **{len(sach)}**, "
          f"**báo nhầm {len(nham)}** |",
          f"| Chưa biết, chỉ đo | {len(do_them)} | xem bảng dưới |", ""]
    if n_pb:
        md.append(f"Tỉ lệ bắt trên phần chắc chắn: **{len(bat)}/{n_pb} = "
                  f"{len(bat)*100//n_pb}%**.\n")

    if sot:
        md += ["#### Bỏ sót — secret thật mà không báo", "",
               "| Tệp | Đây là gì |", "|---|---|"]
        md += [f"| `{t}` | {m} |" for t, m in sot] + [""]
    if nham:
        md += ["#### Báo nhầm — không phải secret mà vẫn báo", "",
               "| Tệp | Rule | Đây là gì |", "|---|---|---|"]
        md += [f"| `{t}` | `{r}` | {m} |" for t, r, m in nham] + [""]
    if do_them:
        md += ["#### Chưa biết trước, chỉ đo", "",
               "Những case này tôi **không** đoán trước kết quả. Lần chạy đầu cho "
               "biết hành vi thật, và chỉ sau đó mới chuyển chúng sang mức khẳng "
               "định — đoán trước rồi khẳng định là cách tự lừa.", "",
               "| Tệp | Tôi nghĩ nên | Gitleaks | Rule | Đây là gì |",
               "|---|---|---|---|---|"]
        for t, pb, co, r, m in do_them:
            md.append(f"| `{t}` | {'bắt' if pb else 'im lặng'} | "
                      f"{'**bắt**' if co else 'im lặng'} | `{r}` | {m} |")
        md.append("")
    md += ["> Hạn chế: 14 tệp là một phép kiểm chức năng, không phải một tỉ lệ có "
           "mẫu số đáng tin. Nó trả lời \"Gitleaks có bắt được các dạng secret phổ "
           "biến và có im lặng với tệp .env mẫu hay không\", chứ không phải "
           "\"bao nhiêu phần trăm secret ngoài thực tế bị bắt\".", ""]

    text = "\n".join(md)
    if md_ra:
        md_ra.parent.mkdir(parents=True, exist_ok=True)
        md_ra.write_text(text, encoding="utf-8")
    print(text)

    if sot or nham:
        print(f"THAT BAI: bo sot {len(sot)}, bao nham {len(nham)} tren phan chac chan.")
        return 1
    print(f"DAT: bat {len(bat)}/{n_pb} secret, 0 bao nham tren {n_kb} tep khong phai secret.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
