#!/usr/bin/env python3
"""
Tu khoi dong ung dung cua repo bat ky de DAST co cai ma ban - khong gan voi .NET.

Thu lan luot, dung cach dau tien ap dung duoc:

  1. start-command   repo tu khai (input cua workflow) - luon duoc uu tien
  2. docker compose  co docker-compose.yml / compose.yml o goc repo: cach nay
                     mang theo ca CSDL va dich vu phu ma app can
  3. dotnet          co .csproj cua ung dung web (Sdk.Web)
  4. Dockerfile      build image roi chay, cong lay tu dong EXPOSE
  5. node            package.json co script "start"

Khong cach nao ap dung duoc thi KHONG gia vo: ghi ro "DAST bo qua, ly do ..."
de trang tom tat noi that, chu khong im lang de nguoi doc tuong app da duoc quet.
Da chon mot cach ma app khong len duoc thi tra ma loi - app hong o PR la tin
hieu that, khong nuot di.

App coi la "da len" khi tra ve BAT KY phan hoi HTTP nao duoi 500 o health-path
(app chi co API thi "/" thuong tra 404 - van la dang chay).

Cach dung trong workflow:
    python tools/khoi_dong_app.py --root . --project-file "$PF" --start-command "$CMD" \\
        --app-url "$URL" --health-path / --github-output --summary
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

COMPOSE = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def cong_compose(tep: Path) -> int | None:
    """Cong dau tien duoc publish ra may chu trong tep compose ('8080:80' -> 8080)."""
    for dong in tep.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r'\s*-\s*["\']?(?:[\d.]+:)?(\d+):\d+', dong)
        if m:
            return int(m.group(1))
    return None


def cong_dockerfile(tep: Path) -> int | None:
    for dong in tep.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*EXPOSE\s+(\d+)", dong, re.I)
        if m:
            return int(m.group(1))
    return None


def chon_cach(root: Path, start_command: str, project_file: str, dockerfile: str, app_url: str) -> dict:
    """Quyet dinh cach khoi dong. Chua chay gi ca."""
    if start_command:
        return {"cach": "start-command", "lenh": start_command,
                "url": app_url or "http://localhost:8080",
                "ghi_chu": "" if app_url else "khong khai app-url, gia dinh http://localhost:8080"}
    for ten in COMPOSE:
        if (root / ten).is_file():
            cong = cong_compose(root / ten)
            return {"cach": "docker-compose", "lenh": f"docker compose -f {ten} up -d --build",
                    "url": app_url or (f"http://localhost:{cong}" if cong else "http://localhost:8080"),
                    "ghi_chu": "" if (app_url or cong) else "khong doc duoc cong publish, gia dinh 8080"}
    if project_file:
        return {"cach": "dotnet",
                "lenh": f'dotnet run --project "{project_file}" --urls http://0.0.0.0:5000',
                "url": app_url or "http://localhost:5000", "ghi_chu": ""}
    if dockerfile and (root / dockerfile).is_file():
        cong = cong_dockerfile(root / dockerfile) or 8080
        return {"cach": "dockerfile",
                "lenh": f'docker build -f "{dockerfile}" -t app-dast-ci . && '
                        f"docker run -d --name app-dast-ci --network host app-dast-ci",
                "url": app_url or f"http://localhost:{cong}", "ghi_chu": ""}
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            start = json.loads(pkg.read_text(encoding="utf-8")).get("scripts", {}).get("start")
        except (json.JSONDecodeError, OSError):
            start = None
        if start:
            return {"cach": "node", "lenh": "(npm ci || npm install) && PORT=3000 npm start",
                    "url": app_url or "http://localhost:3000", "ghi_chu": ""}
    return {"cach": "khong", "lenh": "", "url": "",
            "ly_do": "khong tim thay cach khoi dong app (khong co start-command, docker-compose, "
                     ".csproj web, Dockerfile hay package.json co script start)"}


def cho_len(url: str, cho_giay: int) -> tuple[bool, str]:
    het = time.time() + cho_giay
    loi = ""
    while time.time() < het:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return True, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return True, f"HTTP {e.code}"
            loi = f"HTTP {e.code}"
        except Exception as e:  # chua mo cong, bi tu choi ket noi...
            loi = type(e).__name__
        time.sleep(3)
    return False, loi


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--start-command", default="")
    ap.add_argument("--project-file", default="")
    ap.add_argument("--dockerfile", default="")
    ap.add_argument("--app-url", default="")
    ap.add_argument("--health-path", default="/")
    ap.add_argument("--cho", type=int, default=180, help="so giay toi da cho app len")
    ap.add_argument("--log", default="reports/app.log")
    ap.add_argument("--chi-chon", action="store_true", help="chi in cach se dung, khong chay")
    ap.add_argument("--github-output", action="store_true")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()

    root = Path(a.root).resolve()
    c = chon_cach(root, a.start_command.strip(), a.project_file.strip(), a.dockerfile.strip(), a.app_url.strip())
    ket = {"cach": c["cach"], "url": c.get("url", ""), "chay": False, "ly_do": c.get("ly_do", "")}

    def xuat() -> None:
        print(json.dumps(ket, ensure_ascii=False))
        if a.github_output and os.getenv("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                f.write(f"chay={'true' if ket['chay'] else 'false'}\n")
                f.write(f"cach={ket['cach']}\n")
                f.write(f"url={ket['url']}\n")
                f.write(f"ly_do={ket['ly_do']}\n")
        if a.summary and os.getenv("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
                if ket["chay"]:
                    f.write(f"> DAST: app khởi động bằng **{ket['cach']}** tại `{ket['url']}`.\n\n")
                else:
                    f.write(f"> ⚠ **DAST bỏ qua** — {ket['ly_do']}.\n\n")

    if c["cach"] == "khong" or a.chi_chon:
        if a.chi_chon:
            ket["lenh"] = c.get("lenh", "")
        xuat()
        return 0

    print(f"[*] Khoi dong app bang '{c['cach']}': {c['lenh']}")
    if c.get("ghi_chu"):
        print(f"    (!) {c['ghi_chu']}")
    Path(a.log).parent.mkdir(parents=True, exist_ok=True)
    log = open(a.log, "ab")
    if c["cach"] in ("docker-compose", "dockerfile"):
        # lenh docker tu chay nen (-d); cho no xong roi moi cho app len
        r = subprocess.run(c["lenh"], shell=True, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            ket["ly_do"] = f"lenh khoi dong ({c['cach']}) that bai, ma {r.returncode} - xem {a.log}"
            xuat()
            return 1
    else:
        # tien trinh chay nen, song qua cac buoc sau cua job
        subprocess.Popen(c["lenh"], shell=True, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                         start_new_session=True)

    ok, tt = cho_len(c["url"].rstrip("/") + a.health_path, a.cho)
    if not ok:
        ket["ly_do"] = f"app khong tra loi tai {c['url']}{a.health_path} sau {a.cho}s ({tt}) - xem {a.log}"
        xuat()
        try:
            print(Path(a.log).read_text(encoding="utf-8", errors="replace")[-3000:])
        except OSError:
            pass
        if c["cach"] in ("docker-compose", "dockerfile"):
            subprocess.run("docker ps -a; docker logs app-dast-ci 2>&1 | tail -50", shell=True)
        return 1
    ket["chay"] = True
    print(f"[+] App da len ({tt}) tai {c['url']}")
    xuat()
    return 0


if __name__ == "__main__":
    sys.exit(main())
