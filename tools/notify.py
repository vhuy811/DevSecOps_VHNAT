#!/usr/bin/env python3
"""
Gui ket qua pipeline len Telegram.

Doc reports/tom-tat.json (do tools/gate.py sinh) roi gui mot tin nhan ngan:
CHAN hay QUA, may van de, o dau. Bien moi truong can:
    TELEGRAM_BOT_TOKEN   token lay tu BotFather
    TELEGRAM_CHAT_ID     id cuoc tro chuyen nhan tin

Cac bien GitHub Actions duoi day la tuy chon, co thi tin nhan day du hon:
    GITHUB_SHA, GITHUB_REF_NAME, GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID

Cach dung:
    python tools/notify.py               # luon gui
    python tools/notify.py --only-on-block   # chi gui khi co muc CHAN
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests


def build_message(data: dict) -> str:
    chan = data.get("chan", [])
    ket_luan = data.get("ket_luan", "QUA")
    icon = "\U0001F534" if chan else "\U0001F7E2"
    ten = os.getenv("GITHUB_REPOSITORY", "").split("/")[-1] or "DevSecOps"
    lines = [f"{icon} <b>{ten} - {ket_luan}</b>"]

    repo = os.getenv("GITHUB_REPOSITORY")
    branch = os.getenv("GITHUB_REF_NAME")
    sha = (os.getenv("GITHUB_SHA") or "")[:7]
    if repo:
        lines.append(f"<code>{repo}</code> | nhanh <b>{branch}</b> | commit <code>{sha}</code>")

    if chan:
        lines.append("")
        lines.append(f"<b>{len(chan)} van de phai sua truoc khi merge:</b>")
        for c in chan[:10]:
            uu = " (DA KHAI THAC DUOC)" if c.get("da_khai_thac") else ""
            lines.append(f"- {c.get('nguon')} CWE-{c.get('cwe')} <code>{c.get('o_dau')}</code>{uu}")
    else:
        lines.append("")
        lines.append("Khong co van de nao phai sua.")

    for t in data.get("tham_khao", [])[:5]:
        lines.append(f"<i>{t}</i>")
    for g in data.get("ghi_chu", [])[:3]:
        lines.append(f"⚠ {g}")

    server = os.getenv("GITHUB_SERVER_URL")
    run_id = os.getenv("GITHUB_RUN_ID")
    if server and repo and run_id:
        lines.append("")
        lines.append(f'<a href="{server}/{repo}/actions/runs/{run_id}">Xem chi tiet lan chay</a>')
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", default="reports/tom-tat.json")
    ap.add_argument("--only-on-block", action="store_true",
                    help="Chi gui khi co muc CHAN, tranh lam phien")
    args = ap.parse_args()

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("Thieu TELEGRAM_BOT_TOKEN hoac TELEGRAM_CHAT_ID, bo qua buoc thong bao.")
        return 0  # khong lam hong pipeline chi vi khong gui duoc tin nhan

    path = Path(args.summary)
    if not path.exists():
        print(f"Khong tim thay {path}, bo qua buoc thong bao.")
        return 0

    data = json.loads(path.read_text(encoding="utf-8"))
    if args.only_on_block and not data.get("chan"):
        print("Khong co muc CHAN, khong gui thong bao.")
        return 0

    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": build_message(data),
              "parse_mode": "HTML", "disable_web_page_preview": True},
        timeout=20,
    )
    if resp.status_code != 200:
        print(f"Telegram tra ve {resp.status_code}: {resp.text[:300]}")
        return 0
    print("Da gui thong bao Telegram.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
