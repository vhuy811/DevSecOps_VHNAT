#!/usr/bin/env python3
"""Phong do buoc "Xac dinh pham vi thay doi" - buoc quyet dinh BO QUA tang nao.

VI SAO PHAI CO TEP NAY
Ruleset nhanh main danh dau 8 cong cu la "Require code scanning results":
CodeQL, Semgrep-du-an, OWASP-ZAP, DAST-runtime, DAST-idor, Trivy, gitleaks,
retire.js. GitHub treo PR o trang thai "Code scanning is waiting for results"
cho den khi DU CA 8 cong cu bao ket qua. Mot cong cu khong bao thi PR khong
bao gio merge duoc - va khong co thong bao nao noi ro vi sao.

Buoc `pham_vi` la cho duy nhat quyet dinh co bo qua cac tang hay khong. Neu
no tra `chi_tai_lieu=true` tren mot pull_request thi 7 trong 8 cong cu khong
chay (chi gitleaks chay vo dieu kien) -> PR treo vinh vien.

Hien tai buoc do co dung mot menh de chan chuyen do:

    if [ -n "$CHANGED" ] && [ -z "$KHAC" ] && [ "$EV" = "pull_request" ]; then
        echo "chi_tai_lieu=false"   # PR: LUON quet du

Menh de `&& [ "$EV" = "pull_request" ]` la thu duy nhat giu cho 8 cong cu
luon bao ket qua. Du an nay da hoc mot lan rang MOT DONG CHU THICH KHONG NGAN
DUOC TAI PHAM: commit e9c58a7 sua co -q cua sparse-checkout kem chu thich,
commit 5a7881a dua -q tro lai va xoa luon chu thich do, CI #3 hong y het CI #1.
Nen menh de nay duoc phong do bang mot phep kiem CHAY THAT, khong phai bang
mot dong chu thich.

CACH LAM
Tep nay KHONG viet lai logic de kiem tra. No doc dung doan `run` cua buoc
`pham_vi` trong devsecops-reusable.yml, thay cac bieu thuc ${{ }} bang bien
moi truong, roi chay doan shell DO THAT tren cac repo git dung that. Sua
workflow la sua doi tuong duoc do - khong co ban sao nao de lech.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

GOC = Path(__file__).resolve().parent.parent
WF = GOC / ".github" / "workflows" / "devsecops-reusable.yml"

# ${{ ... }} -> bien moi truong tuong ung. Bat buoc phai phu HET: con sot mot
# bieu thuc la bao hong, vi mot bieu thuc chua biet se bi bash doc thanh chuoi
# rong va phep do se do sai doi tuong ma khong ai hay.
THAY = {
    "github.event_name": "GHA_EVENT_NAME",
    "github.event.pull_request.base.sha": "GHA_PR_BASE",
    "github.event.before": "GHA_BEFORE",
}
RX_BIEU_THUC = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def lay_kich_ban() -> str:
    cay = yaml.safe_load(WF.read_text(encoding="utf-8"))
    for buoc in cay["jobs"]["scan"]["steps"]:
        if buoc.get("id") == "pham_vi":
            kb = buoc["run"]
            break
    else:
        raise SystemExit("[HONG] khong thay buoc id: pham_vi trong job scan")

    con_lai: list[str] = []

    def doi(m: re.Match) -> str:
        ten = m.group(1)
        if ten in THAY:
            return f'"${THAY[ten]}"'
        con_lai.append(ten)
        return m.group(0)

    kb = RX_BIEU_THUC.sub(doi, kb)
    if con_lai:
        raise SystemExit(
            "[HONG] buoc pham_vi dung bieu thuc ${{ }} ma phep do nay chua biet: "
            + ", ".join(sorted(set(con_lai)))
            + "\n       Them vao dict THAY roi chay lai. Khong duoc bo qua: "
            "bieu thuc chua biet se thanh chuoi rong va phep do se do sai."
        )
    return kb


def dung_repo(thu_muc: Path, tep_sua: list[str]) -> tuple[str, str]:
    """Tao repo git: mot commit goc, mot commit sua `tep_sua`. Tra (goc, dau)."""
    g = lambda *a: subprocess.run(["git", *a], cwd=thu_muc, check=True,
                                  capture_output=True, text=True)
    thu_muc.mkdir(parents=True, exist_ok=True)
    g("init", "-q", "-b", "main")
    g("config", "user.email", "do@vidu.test")
    g("config", "user.name", "Phong do")
    (thu_muc / "README.md").write_text("goc\n", encoding="utf-8")
    (thu_muc / "Program.cs").write_text("// goc\n", encoding="utf-8")
    (thu_muc / "docs").mkdir(exist_ok=True)
    (thu_muc / "docs" / "huong-dan.md").write_text("goc\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-q", "-m", "goc")
    goc = g("rev-parse", "HEAD").stdout.strip()

    for t in tep_sua:
        p = thu_muc / t
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("da sua\n", encoding="utf-8")
    g("add", "-A")
    g("commit", "-q", "-m", "sua")
    return goc, g("rev-parse", "HEAD").stdout.strip()


def chay(kich_ban: str, thu_muc: Path, moi_truong: dict[str, str]) -> dict[str, str]:
    ra = Path(tempfile.mkstemp(prefix="ghout-")[1])
    env = dict(os.environ, GITHUB_OUTPUT=str(ra), **moi_truong)
    kq = subprocess.run(["bash", "-s"], input=kich_ban, cwd=thu_muc, env=env,
                        capture_output=True, text=True)
    out: dict[str, str] = {}
    for dong in ra.read_text(encoding="utf-8").splitlines():
        if "=" in dong:
            k, v = dong.split("=", 1)
            out[k] = v
    ra.unlink(missing_ok=True)
    out["_ma"] = str(kq.returncode)
    return out


# (ten, tep bi sua, su kien, dap an chi_tai_lieu, moc co rong khong)
CA_DO = [
    ("PR chi sua tai lieu  -> VAN quet du", ["README.md"], "pull_request", "false", False),
    ("PR sua nhieu tai lieu -> VAN quet du",
     ["README.md", "docs/huong-dan.md"], "pull_request", "false", False),
    ("push chi sua tai lieu -> duoc bo tang", ["README.md"], "push", "true", False),
    ("PR sua ma nguon       -> quet du", ["Program.cs"], "pull_request", "false", False),
    ("push sua ma nguon     -> quet du", ["Program.cs"], "push", "false", False),
    ("PR sua ca ma lan tai lieu -> quet du",
     ["Program.cs", "README.md"], "pull_request", "false", False),
]


def do_mot_vong(kich_ban: str) -> list[str]:
    loi: list[str] = []
    tam = Path(tempfile.mkdtemp(prefix="phamvi-"))
    try:
        for i, (ten, tep, su_kien, dap_an, _) in enumerate(CA_DO):
            d = tam / f"r{i}"
            goc, _dau = dung_repo(d, tep)
            mt = {"GHA_EVENT_NAME": su_kien, "GHA_PR_BASE": "", "GHA_BEFORE": ""}
            if su_kien == "pull_request":
                mt["GHA_PR_BASE"] = goc
            else:
                mt["GHA_BEFORE"] = goc
            kq = chay(kich_ban, d, mt)
            thuc = kq.get("chi_tai_lieu", "(khong co)")
            if thuc != dap_an:
                loi.append(f"{ten}: cho '{dap_an}', nhan '{thuc}'")
                print(f"[HONG] {ten}  -> cho '{dap_an}', nhan '{thuc}'")
            else:
                print(f"[DAT ] {ten}  (chi_tai_lieu={thuc})")

        # Cac su kien khong co moc baseline.
        for su_kien in ("schedule", "workflow_dispatch"):
            d = tam / f"sk-{su_kien}"
            dung_repo(d, ["README.md"])
            kq = chay(kich_ban, d, {"GHA_EVENT_NAME": su_kien,
                                    "GHA_PR_BASE": "", "GHA_BEFORE": ""})
            ten = f"{su_kien} -> quet du, khong co moc"
            if kq.get("chi_tai_lieu") != "false" or kq.get("moc", "x") != "":
                loi.append(f"{ten}: nhan chi_tai_lieu={kq.get('chi_tai_lieu')} "
                           f"moc={kq.get('moc')!r}")
                print(f"[HONG] {ten}")
            else:
                print(f"[DAT ] {ten}")

        # Nhanh vua tao: github.event.before la toan so 0.
        d = tam / "nhanh-moi"
        dung_repo(d, ["README.md"])
        kq = chay(kich_ban, d, {"GHA_EVENT_NAME": "push", "GHA_PR_BASE": "",
                                "GHA_BEFORE": "0" * 40})
        ten = "push nhanh vua tao (before=000..) -> quet du"
        if kq.get("chi_tai_lieu") != "false":
            loi.append(f"{ten}: nhan {kq.get('chi_tai_lieu')}")
            print(f"[HONG] {ten}")
        else:
            print(f"[DAT ] {ten}")

        # Moc tro den commit khong ton tai trong repo (force-push, shallow).
        d = tam / "moc-la"
        dung_repo(d, ["README.md"])
        kq = chay(kich_ban, d, {"GHA_EVENT_NAME": "pull_request",
                                "GHA_PR_BASE": "f" * 40, "GHA_BEFORE": ""})
        ten = "PR voi moc khong co trong repo -> quet du"
        if kq.get("chi_tai_lieu") != "false":
            loi.append(f"{ten}: nhan {kq.get('chi_tai_lieu')}")
            print(f"[HONG] {ten}")
        else:
            print(f"[DAT ] {ten}")
    finally:
        shutil.rmtree(tam, ignore_errors=True)
    return loi


# Moi phep do phai tu chung minh la no CO DO THAT: sua hong kich ban dung
# cach ma commit 5a7881a da tung sua hong, roi doi phep do phai bao.
DOT_BIEN = [
    (
        "bo menh de && [ \"$EV\" = \"pull_request\" ]",
        lambda s: s.replace('&& [ "$EV" = "pull_request" ]', ""),
    ),
    (
        "doi nhanh PR thanh chi_tai_lieu=true",
        lambda s: s.replace(
            '  echo "chi_tai_lieu=false" >> "$GITHUB_OUTPUT"\n'
            '  echo "==> PR chi sua tai lieu nhung VAN quet day du',
            '  echo "chi_tai_lieu=true" >> "$GITHUB_OUTPUT"\n'
            '  echo "==> PR chi sua tai lieu nhung VAN quet day du',
        ),
    ),
    (
        "coi .cs la tai lieu (bo .cs khoi bo loc KHAC)",
        lambda s: s.replace(
            r"grep -vE '\.(md|txt|png|jpe?g|gif)$|^docs/|^LICENSE'",
            r"grep -vE '\.(md|txt|png|jpe?g|gif|cs)$|^docs/|^LICENSE'",
        ),
    ),
]


def main() -> int:
    kich_ban = lay_kich_ban()
    print("=== PHONG DO BUOC pham_vi (chay kich ban that tren repo git that) ===\n")
    loi = do_mot_vong(kich_ban)

    print("\n=== DOT BIEN: phep do nay co thuc su do khong? ===")
    sot: list[str] = []
    for ten, sua in DOT_BIEN:
        hong = sua(kich_ban)
        if hong == kich_ban:
            sot.append(f"{ten}: khong ap duoc vao kich ban (doan van ban da doi?)")
            print(f"[SOT ] {ten} - khong ap duoc, coi nhu phep do khong con do gi")
            continue
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()):
            bat = do_mot_vong(hong)
        if bat:
            print(f"[DAT ] {ten} -> phep do bao hong ({len(bat)} ca)")
        else:
            sot.append(f"{ten}: sua hong roi ma phep do van bao DAT")
            print(f"[SOT ] {ten} -> sua hong roi ma phep do VAN bao dat")

    print()
    if loi:
        print(f"HONG {len(loi)} ca do:")
        for x in loi:
            print(f"  - {x}")
        print("\nNeu chi_tai_lieu='true' tren pull_request: 7/8 cong cu bat buoc")
        print("khong chay -> PR treo mai o 'Code scanning is waiting for results'.")
        return 1
    if sot:
        print(f"PHEP DO KHONG DANG TIN - {len(sot)} dot bien khong bi bat:")
        for x in sot:
            print(f"  - {x}")
        return 1
    print(f"DAT het {len(CA_DO) + 4}/{len(CA_DO) + 4} ca do, "
          f"{len(DOT_BIEN)}/{len(DOT_BIEN)} dot bien deu bi bat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
