#!/usr/bin/env python3
"""
Tu nhan ngon ngu trong repo de bat dung cong cu quet - KHONG chon tay.

Mot repo web thuong co nhieu ngon ngu: C# + Razor + JavaScript + Dockerfile +
workflow YAML. Neu cong cu quet chi duoc bat theo mot o cau hinh chon tay,
ngon ngu nao bi quen la thanh vung mu ma khong ai biet. Tep nay:

  1. Duyet toan bo repo (bo .git, bin/, obj/, node_modules/, bo cong cu).
  2. Nhan ngon ngu theo phan mo rong tep va tep khai bao.
  3. Tach thu vien nhung san (wwwroot/lib, vendor/, *.min.js): khong dem la
     ma cua du an de khong quet SAST vao ma nguoi khac viet, nhung ghi lai
     de tang kiem thu vien xu ly.
  4. Suy ra: ngon ngu CodeQL, bo rule Semgrep, co can build .NET khong, va
     DANH SACH NGON NGU KHONG CO CONG CU NAO QUET - in ra Summary, khong im lang.

Cach dung:
    python tools/nhan_ngon_ngu.py --root . --out reports/ngon-ngu.json
    python tools/nhan_ngon_ngu.py --root . --github-output   # ghi vao $GITHUB_OUTPUT
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# thu muc khong bao gio la ma nguon cua du an
BO_QUA_THU_MUC = {".git", "bin", "obj", "node_modules", ".devsecops-toolkit", ".vs", ".idea",
                  "__pycache__", ".venv", "venv", "target", "coverage", "reports",
                  # ma mau co loi CO Y de kiem thu rule cua bo cong cu - khong phai ma du an
                  "kiem-thu-rule"}
# thu muc chua ban dong goi / sinh ra (dist/, build/): khong phai ma viet tay.
# KHONG bo qua han - thu vien nhung thuong nam o lib/jquery/dist/ - ma xep vao nhom nhung.
SINH_RA = {"dist", "build", "out"}
# thu muc chua thu vien nguoi khac viet, nhung san vao repo
THU_MUC_NHUNG = {"lib", "libs", "vendor", "vendors", "third_party", "thirdparty", "bower_components"}

# phan mo rong -> ngon ngu
DUOI = {
    ".cs": "csharp", ".cshtml": "csharp", ".razor": "csharp", ".csproj": "csharp",
    ".vb": "vbnet",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".vue": "javascript", ".svelte": "javascript",
    ".py": "python",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".swift": "swift",
    ".c": "c-cpp", ".cc": "c-cpp", ".cpp": "c-cpp", ".cxx": "c-cpp", ".h": "c-cpp", ".hpp": "c-cpp",
    ".sql": "sql",
    ".tf": "terraform",
}

# ngon ngu -> ten ngon ngu cua CodeQL (None = CodeQL khong ho tro hoac khong chay duoc tren runner Linux)
CODEQL = {
    "csharp": "csharp",
    "javascript": "javascript-typescript", "typescript": "javascript-typescript",
    "python": "python",
    "java": "java-kotlin", "kotlin": "java-kotlin",
    "go": "go",
    "ruby": "ruby",
    "c-cpp": "c-cpp",
    "actions": "actions",
}
# Cach CodeQL dung CSDL cho tung ngon ngu. "none" = doc ma nguon, khong can build
# (C#, Java/Kotlin va cac ngon ngu thong dich). Go va C/C++ phai build that.
CODEQL_BUILD = {"go": "autobuild", "c-cpp": "autobuild"}

# ngon ngu -> bo rule Semgrep cong dong
SEMGREP = {
    "csharp": ["p/csharp"],
    "javascript": ["p/javascript"], "typescript": ["p/typescript"],
    "python": ["p/python"],
    "java": ["p/java"], "kotlin": ["p/kotlin"],
    "go": ["p/golang"],
    "ruby": ["p/ruby"],
    "php": ["p/php"],
    "rust": ["p/rust"],
    "c-cpp": ["p/c"],
    "dockerfile": ["p/dockerfile"],
    "terraform": ["p/terraform"],
}
# ngon ngu tang ha tang (Trivy config)
HA_TANG = {"dockerfile", "terraform", "kubernetes"}
TEN = {
    "csharp": "C# / Razor", "vbnet": "VB.NET", "javascript": "JavaScript", "typescript": "TypeScript",
    "python": "Python", "java": "Java", "kotlin": "Kotlin", "go": "Go", "ruby": "Ruby", "php": "PHP",
    "rust": "Rust", "swift": "Swift", "c-cpp": "C/C++", "sql": "SQL", "terraform": "Terraform",
    "dockerfile": "Dockerfile", "actions": "GitHub Actions workflow", "kubernetes": "Kubernetes YAML",
}


def la_nhung(parts: tuple[str, ...], ten: str) -> bool:
    """Thu vien nhung san: nam duoi lib/, vendor/... hoac la tep .min.js/.min.css."""
    if any(p.lower() in THU_MUC_NHUNG or p.lower() in SINH_RA for p in parts[:-1]):
        return True
    return ten.endswith((".min.js", ".min.mjs", ".bundle.js"))


def ngon_ngu_cua(rel: Path) -> str | None:
    ten = rel.name
    low = ten.lower()
    parts = rel.parts
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return "dockerfile"
    if len(parts) >= 3 and parts[0] == ".github" and parts[1] == "workflows" and low.endswith((".yml", ".yaml")):
        return "actions"
    if low.endswith((".yml", ".yaml")) and any(p.lower() in ("k8s", "kubernetes", "manifests", "helm", "charts") for p in parts):
        return "kubernetes"
    return DUOI.get(rel.suffix.lower())


def nhan(root: Path) -> dict:
    ma = Counter()          # tep ma cua du an theo ngon ngu
    nhung = Counter()       # tep thu vien nhung san theo ngon ngu
    thu_muc_nhung = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in BO_QUA_THU_MUC]
        for f in filenames:
            rel = (Path(dirpath) / f).relative_to(root)
            nn = ngon_ngu_cua(rel)
            if not nn:
                continue
            if nn not in ("javascript", "typescript") and any(p.lower() in SINH_RA for p in rel.parts[:-1]):
                continue  # tep sinh ra cua ngon ngu khac: bo qua
            if nn in ("javascript", "typescript") and la_nhung(rel.parts, f.lower()):
                nhung[nn] += 1
                idx = next((i for i, p in enumerate(rel.parts[:-1])
                            if p.lower() in THU_MUC_NHUNG or p.lower() in SINH_RA), None)
                # nam trong lib/, vendor/... -> ghi thu muc; tep .min.js le -> ghi chinh tep
                thu_muc_nhung.add("/".join(rel.parts[: idx + 1]) if idx is not None else rel.as_posix())
                continue
            ma[nn] += 1

    codeql = sorted({CODEQL[n] for n in ma if n in CODEQL})
    semgrep = ["p/security-audit"] + sorted({p for n in ma for p in SEMGREP.get(n, [])})
    ha_tang = sorted(n for n in ma if n in HA_TANG)

    # ngon ngu co trong repo nhung khong cong cu SAST nao phu
    khong_phu = sorted(n for n in ma if n not in CODEQL and n not in SEMGREP and n not in HA_TANG)
    # CodeQL c-cpp can build that; swift can runner macOS - pipeline Linux khong chay
    ghi_chu = []
    if "c-cpp" in codeql:
        ghi_chu.append("C/C++: CodeQL can build du an; neu build that bai thi chi con Semgrep.")
    if "swift" in ma:
        ghi_chu.append("Swift: CodeQL can runner macOS, pipeline nay chay Linux - chi co Semgrep (neu co rule).")

    return {
        "ma_du_an": dict(sorted(ma.items(), key=lambda x: -x[1])),
        "thu_vien_nhung": dict(nhung),
        "thu_muc_nhung": sorted(thu_muc_nhung),
        "codeql_languages": codeql,
        "codeql_matrix": [{"language": l, "build-mode": CODEQL_BUILD.get(l, "none")} for l in codeql],
        "semgrep_packs": semgrep,
        "ha_tang": ha_tang,
        "co_dotnet": ma.get("csharp", 0) > 0 and any(root.rglob("*.csproj")),
        "khong_co_cong_cu": khong_phu,
        "ghi_chu": ghi_chu,
    }


def bang_markdown(kq: dict) -> str:
    dong = ["### Ngôn ngữ nhận ra trong repo (tự động)", "", "| Ngôn ngữ | Tệp của dự án | Công cụ quét |", "|---|---|---|"]
    for nn, so in kq["ma_du_an"].items():
        cc = []
        if nn in CODEQL:
            cc.append(f"CodeQL `{CODEQL[nn]}`")
        if nn in SEMGREP:
            cc.append("Semgrep " + " ".join(f"`{p}`" for p in SEMGREP[nn]))
        if nn in HA_TANG:
            cc.append("Trivy config")
        dong.append(f"| {TEN.get(nn, nn)} | {so} | {', '.join(cc) if cc else '**KHÔNG CÓ — chưa được quét**'} |")
    if kq["thu_vien_nhung"]:
        tong = sum(kq["thu_vien_nhung"].values())
        dong.append("")
        dong.append(f"Thư viện nhúng sẵn: {tong} tệp trong {', '.join(f'`{d}`' for d in kq['thu_muc_nhung'])} "
                    "— không quét SAST (mã người khác viết), chuyển cho tầng kiểm thư viện.")
    for g in kq["ghi_chu"]:
        dong.append(f"> {g}")
    return "\n".join(dong) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="")
    ap.add_argument("--github-output", action="store_true",
                    help="ghi codeql_languages, semgrep_packs, co_dotnet... vao $GITHUB_OUTPUT")
    ap.add_argument("--summary", action="store_true", help="ghi bang vao $GITHUB_STEP_SUMMARY")
    a = ap.parse_args()

    kq = nhan(Path(a.root).resolve())
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(kq, indent=1, ensure_ascii=False), encoding="utf-8")

    md = bang_markdown(kq)
    print(md)
    if a.summary and os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md + "\n")
    if a.github_output and os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"codeql_languages={json.dumps(kq['codeql_languages'])}\n")
            f.write(f"codeql_matrix={json.dumps(kq['codeql_matrix'])}\n")
            f.write(f"semgrep_packs={' '.join(kq['semgrep_packs'])}\n")
            f.write(f"co_dotnet={'true' if kq['co_dotnet'] else 'false'}\n")
            f.write(f"co_codeql={'true' if kq['codeql_languages'] else 'false'}\n")
            f.write(f"thu_muc_nhung={json.dumps(kq['thu_muc_nhung'])}\n")
    for n in kq["khong_co_cong_cu"]:
        print(f"::warning::Repo co ma {TEN.get(n, n)} nhung KHONG co cong cu SAST nao quet ngon ngu nay.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
