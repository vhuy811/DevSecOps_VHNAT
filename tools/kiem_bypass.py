#!/usr/bin/env python3
"""
Kiem cac duong LACH CONG - moi duong la mot phep kiem phai DAT.

VI SAO CAN TEP NAY
Lo hong lach cong o PR #18 tim duoc bang tay, sau khi no da lot. Lo hong
`// nosemgrep` o PR #1 cung vay. Hai lan deu la: ai do thu, thay qua duoc, roi
moi bit. Cai dat ra khong phai mot ban sua - la mot phep kiem, de lan sau ai sua
workflow ma bo mat chot thi biet ngay chu khong phai doi mot PR thu nghiem.

NGUYEN TAC
Moi phep kiem o day ung voi mot duong lach CU THE, va phai ghi ro:
  - lach bang cach nao
  - vi sao lach duoc (co che nao cua GitHub / cong cu cho phep)
  - chot nao dang giu, va phep kiem tim chot do o dau
Khong co phep kiem nao chi de "cho co". Phep kiem khong noi duoc ba dieu tren
thi khong thuoc tep nay.

PHAM VI. Tep nay kiem TINH tren cau hinh pipeline: no bat duoc viec chot bi xoa
hoac bi lam yeu. No KHONG thay duoc mot PR doi khang that - co nhung dieu chi
biet duoc khi mo PR len (vi du: GitHub co coi mot required check chua bao gio
bao cao la "pending" hay khong). Nhung dieu do duoc ghi la GIOI HAN o cuoi tep,
chu khong duoc gia vo la da kiem.

CHAY
    python tools/kiem_bypass.py
Ma tra ve 0 neu moi chot con nguyen, 1 neu co chot mat.
"""
from __future__ import annotations

import re
import sys

import yaml
from pathlib import Path

GOC = Path(__file__).resolve().parent.parent
WF = GOC / ".github" / "workflows"

# Workflow la CONG THAT (chan merge). Workflow phong do khong phai cong - chung
# duoc phep continue-on-error vi chung do, khong chan.
WF_CONG = ["devsecops.yml", "devsecops-reusable.yml"]

ket_qua: list[tuple[bool, str, str]] = []


def kiem(ten: str, dat: bool, vi_sao: str) -> None:
    ket_qua.append((dat, ten, vi_sao))


def doc(ten: str) -> str:
    p = WF / ten
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def main() -> int:
    reuse = doc("devsecops-reusable.yml")
    goi = doc("devsecops.yml")
    gate = (GOC / "tools" / "gate.py").read_text(encoding="utf-8")

    # ---- 1. Job bi SKIP van thoa required check -----------------------------
    # GitHub coi mot job bi skip la DA THOA required status check. Nen chi can
    # lam cho job cong khong chay (dieu kien if sai, hoac mot needs bi skip) la
    # cong chuyen xanh ma khong he kiem gi.
    kiem("Job 'Cong xac nhan' khong the thoa cong bang cach bi skip",
         "needs.scan.result != 'skipped'" in reuse,
         "GitHub coi job bi skip la da thoa required check. Thieu chot nay thi "
         "chi can lam job khong chay la cong xanh ma khong kiem gi.")

    # ---- 2. nosem ------------------------------------------------------------
    # PR #1 (commit b5487dd): them `// nosemgrep` vao dong loi -> check
    # Semgrep-du-an chuyen xanh. --disable-nosem MOT MINH khong du, vi Semgrep
    # van doc chu thich o mot so duong. Chot: doi "nosem" -> "no_sem" trong ban
    # checkout TAM truoc khi quet.
    kiem("Semgrep chay voi --disable-nosem",
         reuse.count("--disable-nosem") >= 2,
         "Khong co co nay thi mot chu thich nosemgrep tat duoc rule ngay tai dong loi.")
    kiem("Chu thich nosem bi vo hieu hoa truoc khi quet (khong chi dua vao co)",
         "no_sem" in reuse and "nosem" in reuse,
         "PR #1 da chung minh --disable-nosem mot minh khong du: them // nosemgrep "
         "thi check chuyen xanh. Chot that la doi chu trong ban checkout tam.")

    # ---- 3. continue-on-error tren cong -------------------------------------
    # Mot buoc bao mat co continue-on-error thi that bai cua no khong lam job
    # that bai, va cong van xanh.
    co_coe = [f for f in WF_CONG if "continue-on-error" in doc(f)]
    kiem("Khong buoc nao cua pipeline cong dung continue-on-error",
         not co_coe,
         f"continue-on-error lam that bai cua buoc bao mat khong keo job that bai. "
         f"Tep co: {co_coe}")

    # ---- 4. paths filter tren workflow cong ---------------------------------
    # Co paths filter thi doi ten tep hoac dat ma vao duong dan khong khop la
    # workflow khong chay -> khong co SARIF -> khong co canh bao.
    kiem("Workflow cong khong co paths / paths-ignore o trigger",
         not re.search(r"^\s{2,4}paths(-ignore)?:", goi, re.M),
         "Co paths filter thi chi can dat ma vao duong dan khong khop la workflow "
         "khong chay va khong canh bao gi.")

    # ---- 5. nhanh moi phai duoc quet ----------------------------------------
    # push: branches: [main] thi nhanh moi khong bi quet, va nguoi ta co the
    # merge qua duong khac hoac bat cong sau.
    m = re.search(r"^on:(.*?)^\w", goi, re.S | re.M)
    khoi_on = m.group(1) if m else goi
    kiem("push duoc quet tren MOI nhanh (khong gioi han branches)",
         not re.search(r"push:\s*\n\s+branches:", khoi_on),
         "Gioi han push vao main thi nhanh moi khong qua tang nao, trai yeu cau "
         "'nhanh moi cung phai duyet du 5 tang'.")

    # ---- 6. moi SARIF sinh ra deu phai duoc day len Code Scanning -----------
    # Tang nao khong upload thi khong co check tuong ung, va cong khong biet
    # tang do ton tai.
    sinh = set(re.findall(r"reports/([\w.-]+)\.sarif", reuse))
    day = set(re.findall(r"sarif_file:\s*reports/([\w.-]+)\.sarif", reuse))
    thieu_day = sorted(s for s in sinh if s not in day and not s.endswith("-tho"))
    kiem("Moi SARIF cua tang deu co buoc day len Code Scanning",
         not thieu_day,
         f"Tang khong duoc upload thi khong co check tuong ung trong ruleset. "
         f"Thieu: {thieu_day}")

    # ---- 7. token khong duoc de lai trong .git/config -----------------------
    # Doc CAU TRUC chu khong dem so lan xuat hien. Ban dau phep kiem nay so
    # so luong "persist-credentials: false" voi so luong checkout - va kiem thu
    # am (kiem_thu_bypass.py) chung minh no la trang tri: tep co 9 dong
    # persist-credentials nhung chi 8 checkout, nen doi mot dong sang true van
    # thoa dieu kien >=. Dem khong phai cach kiem; phai di tung buoc.
    xau_checkout = []
    for ten_wf in WF_CONG:
        txt = doc(ten_wf)
        if not txt:
            continue
        d = yaml.safe_load(txt) or {}
        for ten_job, job in (d.get("jobs") or {}).items():
            for i, b in enumerate(job.get("steps") or []):
                if not isinstance(b, dict):
                    continue
                if not str(b.get("uses", "")).startswith("actions/checkout@"):
                    continue
                voi = b.get("with") or {}
                if voi.get("persist-credentials") is not False:
                    xau_checkout.append(f"{ten_wf}:{ten_job}:buoc{i}")
    kiem("Moi buoc checkout dat persist-credentials: false",
         not xau_checkout,
         f"GITHUB_TOKEN con trong .git/config thi mot buoc sau do (hoac mot action "
         f"phu thuoc) doc duoc va day duoc len repo. Buoc thieu: {xau_checkout}")

    # ---- 8. backstop canh bao da xac nhan -----------------------------------
    # PR #18: canh bao nam ngoai cac dong PR sua thi GitHub khong tinh la "moi",
    # nen lo hong that di qua cong. Chot: gate.py --chan-xac-nhan chan theo bang
    # chung khai thac duoc, khong phu thuoc diff.
    kiem("gate.py co che do --chan-xac-nhan (chan theo bang chung, khong theo diff)",
         "--chan-xac-nhan" in gate and "chan_xac_nhan" in gate.replace("-", "_"),
         "GitHub chi tinh canh bao MOI tren dong PR sua. Lo hong o tep khong doi "
         "di qua cong (PR #18). Backstop chan theo bang chung khai thac duoc.")
    kiem("Job cong thuc su truyen --chan-xac-nhan cho gate.py",
         "--chan-xac-nhan" in reuse,
         "Co che do ma khong goi thi backstop khong chay.")

    # ---- 9. tep ngoai le phai co du truong audit ----------------------------
    kiem("Ngoai le yeu cau du ly_do / nguoi_duyet / het_han",
         all(k in gate for k in ("ly_do", "nguoi_duyet", "het_han")),
         "Thieu rang buoc nay thi mot dong trong ngoai le tat duoc canh bao ma "
         "khong ai chiu trach nhiem va khong co han xem lai.")

    # ---- 10. DAST chet nhung van xanh ---------------------------------------
    # Tang DAST tung chet am tham (khong dang nhap duoc vi CSRF) ma van bao xanh.
    kiem("DAST duoc yeu cau nhung khong ra ket qua thi CHAN",
         "run-dast" in reuse and "exit 1" in reuse,
         "Tang DAST chet ma cong van xanh la truong hop xau nhat: bao cao noi da "
         "kiem dong trong khi khong kiem gi.")

    # ---- 11. duong dan baseline / out khong duoc ra ngoai thu muc lam viec --
    kiem("gate.py chan duong dan ra ngoai thu muc lam viec",
         "relative_to" in gate,
         "Khong chan thi mot PR tro --baseline-xac-nhan ra tep ngoai workspace "
         "(hoac tep do PR tu tao) de tat canh bao.")

    # ---- 12. toolkit-ref phai duoc ghim o ben GOI ---------------------------
    # Workflow reusable checkout bo cong cu theo inputs.toolkit-ref. Mot PR doi
    # ref do sang fork co bo rule da bi vo hieu thi cong van xanh.
    kiem("Ben goi ghim toolkit-ref (khong de PR tu chon bo rule)",
         re.search(r"toolkit-ref:\s*\$\{\{\s*github\.sha", goi) is not None,
         "Khong ghim thi mot PR tro toolkit-ref sang fork co bo rule rong va cong "
         "van xanh. Day la 2 canh bao CodeQL dang treo tren workflow.")

    # ---- 13. moi tep rule phai duoc nap vao lan quet ------------------------
    # Them mot tep rule moi ma quen nap thi rule do chet, va khong ai biet.
    tep_rule = sorted(p.name for p in (GOC / "semgrep-rules").glob("sast-detect*.yaml"))
    chua_nap = [t for t in tep_rule if t not in reuse]
    kiem("Moi tep sast-detect*.yaml deu duoc nap vao buoc quet",
         not chua_nap,
         f"Tep rule khong duoc nap thi toan bo rule trong do chet im lang. "
         f"Chua nap: {chua_nap}")

    # ---- 14. fixture phai bi loai khoi lan quet production ------------------
    # Co_Loi.* co y chua lo hong. Khong loai thi moi PR deu bi chan boi chinh
    # fixture; loai qua rong thi ma that cung bi che.
    kiem("Thu muc fixture bi loai khoi lan quet production",
         "kiem-thu-rule" in reuse,
         "Co_Loi.* co y chua lo hong; khong loai thi moi PR bi chan boi fixture.")

    # ---- in ket qua ---------------------------------------------------------
    hong = [x for x in ket_qua if not x[0]]
    print("### Kiểm các đường lách cổng\n")
    print(f"| Chốt | Kết quả |")
    print(f"|---|---|")
    for dat, ten, _ in ket_qua:
        print(f"| {ten} | {'✅' if dat else '❌ MẤT CHỐT'} |")
    print()
    if hong:
        print(f"**{len(hong)} chốt đã mất:**\n")
        for _, ten, vi_sao in hong:
            print(f"- **{ten}**")
            print(f"  {vi_sao}")
        print()
        print("> Mỗi chốt ở trên ứng với một đường lách đã từng có thật hoặc đã được "
              "xác định. Mất chốt nghĩa là đường lách đó mở lại.")
        return 1

    print(f"Đủ **{len(ket_qua)}** chốt.\n")
    print("> Phạm vi: đây là kiểm **tĩnh** trên cấu hình pipeline — nó bắt được việc "
          "chốt bị xoá hoặc bị làm yếu. Nó **không** thay được một PR đối kháng thật. "
          "Ba điều dưới đây chỉ biết được khi mở PR lên và chưa được kiểm ở đây:\n")
    print("> 1. GitHub có thực sự coi một required check *chưa bao giờ báo cáo* là "
          "chặn hay không (giả định của chốt số 6).")
    print("> 2. Ruleset trên repo có đúng các tool và ngưỡng như tài liệu nói hay "
          "không — cấu hình đó nằm ngoài repo, mã không đọc được.")
    print("> 3. Hành vi khi force-push sau khi đã có approval.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
