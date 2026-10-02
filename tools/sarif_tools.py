#!/usr/bin/env python3
"""
Chuan hoa SARIF de GitHub Code Scanning lam CONG - thay cho cong tu viet.

Theo mo hinh moi (So do 6): pipeline KHONG tu quyet chan/qua. No dua ket qua
cua tung scanner len Code Scanning duoi dang SARIF; GitHub tu tinh alert nao
la MOI trong PR, hien chu thich dung dong, va ruleset "Require code scanning
results" khoa merge theo nguong tung cong cu. Dismiss + ly do trong tab
Security la duong chap nhan rui ro chinh thuc, co audit.

Hai lenh:

  semgrep   Doc SARIF cua HAI luot quet Semgrep, chuan hoa muc do, ghi hai tep:
              --du-an      rule cua bo cong cu + rule rieng cua repo (.devsecops/rules)
                           -> semgrep-du-an.sarif: tin cay cao, co quyen chan
              --cong-dong  bo rule cong dong theo ngon ngu
                           -> semgrep-cong-dong.sarif: tham khao
            Nhom quyet dinh theo luot quet, khong theo ten rule.
            Neu co ket qua ZAP: rule du an nao cung CWE + cung endpoint voi mot
            alert ZAP thi ghi nhan "DA KHAI THAC DUOC" vao thong diep. Chi de
            xep uu tien - KHONG bao gio dung de bo qua canh bao.

  zap       Doc zap-alerts.json (tu dast_scan.py), xuat SARIF. Moi alert duoc
            ANH XA VE MA NGUON qua ban do route (endpoint -> Controller:dong)
            de GitHub hien chu thich ngay tren action tuong ung. Alert khong
            anh xa duoc (header, tep tinh) gan vao tep du an (.csproj).

Vi sao phai chuan hoa Semgrep truoc khi upload:
  - GitHub doc `security-severity` (so 0-10) o properties cua rule de xep
    critical/high/medium/low cho ruleset. Semgrep co phien ban ghi chu "Medium"
    -> GitHub tu choi ca tep (issue semgrep #10834). O day ep ve so.
  - Rule nao khong co thi suy tu level: error -> 8.0 (High), warning -> 5.0
    (Medium), note -> 2.0 (Low).
  - Them tag "security" de GitHub coi day la security alert.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from correlate import find_route  # noqa: E402

CWE_RE = re.compile(r"CWE-(\d+)", re.I)

LEVEL_SEV = {"error": "8.0", "warning": "5.0", "note": "2.0", "none": "0.0"}
CHU_SEV = {"critical": "9.5", "high": "8.0", "medium": "5.0", "moderate": "5.0",
           "low": "2.0", "info": "1.0", "informational": "1.0"}
ZAP_RISK_LEVEL = {"High": "error", "Medium": "warning", "Low": "note", "Informational": "note"}
ZAP_RISK_SEV = {"High": "8.0", "Medium": "5.0", "Low": "2.0", "Informational": "1.0"}


def doc(p: str) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


def ghi(p: str, d: dict) -> None:
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(json.dumps(d, indent=1, ensure_ascii=False), encoding="utf-8")


def sec_sev_hop_le(v) -> str | None:
    """Tra ve chuoi so '0.0'-'10.0' hoac None."""
    if v is None:
        return None
    s = str(v).strip()
    try:
        f = float(s)
        return f"{min(max(f, 0.0), 10.0):.1f}"
    except ValueError:
        return CHU_SEV.get(s.lower())


def cwe_cua_rule(rule: dict, res: dict) -> str:
    m = CWE_RE.search(res.get("message", {}).get("text", "")) or \
        CWE_RE.search(json.dumps(rule.get("properties", {}), ensure_ascii=False)) or \
        CWE_RE.search(json.dumps(rule.get("fullDescription", {}), ensure_ascii=False))
    return m.group(1) if m else ""


def id_ngan(rid: str) -> str:
    """Bo tien to duong dan ma Semgrep gan vao id rule.

    Semgrep nap rule tu tep cuc bo thi dat id = <thu muc chua tep, noi bang dau
    cham>.<id trong tep>. Chay trong CI voi --config devsecops-toolkit/semgrep-rules/
    sast-detect.yaml, rule `dso-sqli-commandtext-concat` thanh
    `devsecops-toolkit.semgrep-rules.dso-sqli-commandtext-concat`.
    Id rule trong tep khong chua dau cham, nen phan sau dau cham cuoi la id goc.
    Rule cong dong (csharp.lang.security...) giu nguyen id - do la id registry.
    """
    return rid.rsplit(".", 1)[-1]


def vi_tri(res: dict) -> tuple[str, int]:
    loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
    return (loc.get("artifactLocation", {}).get("uri", "").replace("\\", "/").lstrip("./"),
            int(loc.get("region", {}).get("startLine", 0) or 0))


# ---------------------------------------------------------------------------
def chuan_hoa_rule(rule: dict) -> dict:
    r = copy.deepcopy(rule)
    props = r.setdefault("properties", {})
    level = (r.get("defaultConfiguration") or {}).get("level", "warning")
    sev = sec_sev_hop_le(props.get("security-severity")) or LEVEL_SEV.get(level, "5.0")
    props["security-severity"] = sev
    tags = list(props.get("tags") or [])
    if "security" not in tags:
        tags.append("security")
    props["tags"] = tags
    r.setdefault("defaultConfiguration", {})["level"] = level
    return r


def xu_ly_semgrep(path: str, ten: str, rut_gon_id: bool, zap_alerts: list, routes: list) -> tuple[dict, dict]:
    """Chuan hoa mot tep SARIF Semgrep thanh mot 'cong cu' tren Code Scanning.

    rut_gon_id=True cho nhom du an: rule doc tu tep cuc bo bi Semgrep ghep duong
    dan vao id (a.b.dso-x) -> rut ve id goc de on dinh, khong phu thuoc thu muc.
    Rule registry (nhom cong dong) giu nguyen id.
    """
    sarif = doc(path)
    out = {"version": sarif.get("version", "2.1.0"), "$schema": sarif.get("$schema"), "runs": []}
    dem = {"kq": 0, "kt": 0, "supp": 0}
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {r.get("id"): chuan_hoa_rule(r) for r in driver.get("rules", [])}
        ket_qua, rule_dung = [], {}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid) or chuan_hoa_rule({"id": rid, "defaultConfiguration": {"level": res.get("level", "warning")}})
            res = copy.deepcopy(res)
            # level theo rule da chuan hoa, de ruleset "Alerts: Errors" dung
            res["level"] = rule["defaultConfiguration"]["level"]
            # "suppressions" (vd. tu chu thich nosemgrep) bi GitHub coi la DA DONG -> khong
            # chan. Chap nhan rui ro chi qua Dismiss + ly do tren GitHub, nen xoa het.
            if res.pop("suppressions", None):
                dem["supp"] += 1
            # danh sach rules duoc dung lai -> chi so cu mat nghia
            res.pop("ruleIndex", None)
            res.pop("rule", None)
            if rut_gon_id:
                rid_goc, rid = rid, id_ngan(rid)
                if rid != rid_goc:
                    # ten/mo ta rule cua Semgrep cung chua id dai ("Semgrep Finding: a.b.dso-x")
                    rule = json.loads(json.dumps(rule, ensure_ascii=False).replace(rid_goc, rid))
                    rule["id"] = rid
                    res["ruleId"] = rid
                # Doi chieu voi ZAP: cung CWE, cung endpoint -> DA KHAI THAC DUOC (chi de xep uu tien)
                cwe = cwe_cua_rule(rule, res)
                f, line = vi_tri(res)
                route = find_route(f, line, routes) if routes and f else None
                if route and cwe:
                    for z in zap_alerts:
                        if str(z.get("cweid")) == cwe and urlparse(z.get("url", "")).path == route["url_path"]:
                            msg = res.setdefault("message", {})
                            msg["text"] = (f"[DA KHAI THAC DUOC - ZAP: {z.get('alert')}, payload: "
                                           f"{(z.get('attack') or '')[:60]}] " + msg.get("text", ""))
                            res.setdefault("properties", {})["da_khai_thac"] = True
                            dem["kt"] += 1
                            break
            ket_qua.append(res)
            rule_dung[rid] = rule
            dem["kq"] += 1
        r2 = copy.deepcopy(run)
        r2["tool"]["driver"] = dict(driver, name=ten, rules=list(rule_dung.values()))
        r2["results"] = ket_qua
        r2.pop("automationDetails", None)
        out["runs"].append(r2)
    return out, dem


def lenh_semgrep(a: argparse.Namespace) -> int:
    """Hai luot quet rieng -> hai cong cu tren Code Scanning.

    Nhom duoc quyet dinh theo NGUON CAU HINH cua luot quet, khong theo ten rule:
      --du-an      luot quet rule cua bo cong cu + rule rieng cua repo (.devsecops/rules)
                   -> Semgrep-du-an: tin cay cao, co quyen chan
      --cong-dong  luot quet bo rule cong dong theo ngon ngu -> Semgrep-cong-dong: tham khao
    Repo nao cung them duoc rule rieng ma khong phai dat ten theo quy uoc nao.
    """
    zap_alerts = doc(a.zap).get("alerts", []) if a.zap and Path(a.zap).is_file() else []
    routes = doc(a.routes).get("routes", []) if a.routes and Path(a.routes).is_file() else []
    tong_supp = 0
    for nguon, dich, ten, rut_gon in ((a.du_an, a.out_du_an, "Semgrep-du-an", True),
                                     (a.cong_dong, a.out_cong_dong, "Semgrep-cong-dong", False)):
        if not nguon:
            continue
        if not Path(nguon).is_file():
            print(f"::warning::Khong co {nguon} - bo qua {ten}")
            continue
        out, dem = xu_ly_semgrep(nguon, ten, rut_gon, zap_alerts if rut_gon else [], routes)
        ghi(dich, out)
        tong_supp += dem["supp"]
        them = f", {dem['kt']} DA KHAI THAC DUOC theo ZAP" if rut_gon and zap_alerts else ""
        print(f"{ten}: {dem['kq']} canh bao -> {dich}{them}")
    if tong_supp:
        print(f"::warning::{tong_supp} ket qua Semgrep mang 'suppressions' (tat trong ma nguon) - "
              f"da BO dau tat, van dua len nhu canh bao binh thuong")
    return 0


# ---------------------------------------------------------------------------
def lenh_zap(a: argparse.Namespace) -> int:
    data = doc(a.inp)
    alerts = data.get("alerts", [])
    routes = doc(a.routes).get("routes", []) if a.routes and Path(a.routes).is_file() else []
    fallback = a.fallback_file or "README.md"

    rules: dict[str, dict] = {}
    results = []
    seen = set()
    n_map = 0
    for z in alerts:
        pid = str(z.get("plugin", ""))
        risk = z.get("risk", "Low")
        rid = f"zap-{pid}"
        cwe = str(z.get("cweid") or "")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": z.get("alert", rid),
                "shortDescription": {"text": z.get("alert", rid)},
                "fullDescription": {"text": f"OWASP ZAP active scan rule {pid}: {z.get('alert', '')}"},
                "defaultConfiguration": {"level": ZAP_RISK_LEVEL.get(risk, "note")},
                "properties": {
                    "security-severity": ZAP_RISK_SEV.get(risk, "2.0"),
                    "tags": ["security", "dast"] + ([f"external/cwe/cwe-{cwe}"] if cwe else []),
                    "precision": "high" if z.get("confidence") in ("High", "Confirmed") else "medium",
                },
            }
        path = urlparse(z.get("url", "")).path
        param = z.get("param", "")
        key = (pid, path, param)
        if key in seen:
            continue
        seen.add(key)

        route = next((r for r in routes if r.get("url_path") == path), None)
        if route:
            f, line = route["file"], int(route.get("line_start", 1) or 1)
            n_map += 1
        else:
            f, line = fallback, 1
        text = f"{z.get('alert')} tai {path}" + (f" (tham so/header: {param})" if param else "")
        if z.get("attack"):
            text += f" | payload: {z['attack'][:80]}"
        if z.get("evidence"):
            text += f" | bang chung: {z['evidence'][:80]}"
        if not route:
            text += " | (khong anh xa duoc ve action nao - gan vao tep du an)"
        results.append({
            "ruleId": rid,
            "level": ZAP_RISK_LEVEL.get(risk, "note"),
            "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f, "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": line}}}],
            "partialFingerprints": {"zapAlert/v1": f"{pid}|{path}|{param}"},
            "properties": {"risk": risk, "confidence": z.get("confidence"), "url": z.get("url"), "cwe": cwe},
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "OWASP-ZAP", "informationUri": "https://www.zaproxy.org/",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    ghi(a.out, sarif)
    dem = {}
    for r in results:
        dem[r["level"]] = dem.get(r["level"], 0) + 1
    print(f"ZAP: {len(results)} alert -> {a.out}  (error {dem.get('error',0)}, warning {dem.get('warning',0)}, "
          f"note {dem.get('note',0)}); {n_map} anh xa duoc ve ma nguon")
    return 0


# ---------------------------------------------------------------------------
def lenh_runtime(a: argparse.Namespace) -> int:
    """Rule runtime da chon lam khoa -> SARIF cho MOT cong cu RIENG tren Code Scanning.

    Chi dua phat hien co lam_khoa=True len (CSP, X-Frame-Options theo chinh sach);
    phan con lai van report-only o trang Summary. Cong cu rieng ten 'DAST-runtime'
    de ruleset dat nguong rieng (Medium) - KHONG dinh vao cong High cua OWASP-ZAP.
    Header la cau hinh muc ung dung, khong co dong code endpoint, nen moi phat hien
    gan vao fallback-file (tep du an). GitHub so baseline (main sach = 0) voi PR;
    PR nao lam mat header se tao alert MOI -> cong chan.
    LUON ghi SARIF (ket qua rong khi sach) de thiet lap baseline va check luon bao cao.
    """
    data = doc(a.inp)
    rt = [f for f in data.get("rule_runtime", []) if f.get("lam_khoa")]
    fallback = a.fallback_file or "README.md"
    rules: dict[str, dict] = {}
    results = []
    for f in rt:
        rid = f.get("rule_id") or ("rt-" + re.sub(r"[^a-z0-9]+", "-", f.get("alert", "").lower()).strip("-"))
        risk = f.get("risk", "Medium")
        cwe = str(f.get("cweid") or "")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.get("alert", rid),
                "shortDescription": {"text": f.get("alert", rid)},
                "fullDescription": {"text": f.get("cach_sua", "") or f.get("alert", "")},
                "defaultConfiguration": {"level": ZAP_RISK_LEVEL.get(risk, "warning")},
                "properties": {
                    "security-severity": ZAP_RISK_SEV.get(risk, "5.0"),
                    "tags": ["security", "dast", "runtime"] + ([f"external/cwe/cwe-{cwe}"] if cwe else []),
                    "precision": "very-high",
                },
            }
        text = f.get("alert", "")
        if f.get("evidence"):
            text += f" | bang chung: {f['evidence'][:80]}"
        if f.get("cach_sua"):
            text += f" | sua: {f['cach_sua'][:100]}"
        results.append({
            "ruleId": rid,
            "level": ZAP_RISK_LEVEL.get(risk, "warning"),
            "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": fallback, "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": 1}}}],
            "partialFingerprints": {"dastRuntime/v1": f"{rid}|{f.get('param', '')}"},
            "properties": {"risk": risk, "url": f.get("url"), "cwe": cwe},
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "DAST-runtime",
                                "informationUri": "https://owasp.org/www-project-secure-headers/",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    ghi(a.out, sarif)
    print(f"DAST-runtime: {len(results)} phat hien lam_khoa -> {a.out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("semgrep")
    s.add_argument("--du-an", default="", help="SARIF cua luot quet rule bo cong cu + rule rieng cua repo")
    s.add_argument("--cong-dong", default="", help="SARIF cua luot quet bo rule cong dong")
    s.add_argument("--out-du-an", default="reports/semgrep-du-an.sarif")
    s.add_argument("--out-cong-dong", default="reports/semgrep-cong-dong.sarif")
    s.add_argument("--zap", default="")
    s.add_argument("--routes", default="")
    z = sub.add_parser("zap")
    z.add_argument("--in", dest="inp", required=True)
    z.add_argument("--routes", default="")
    z.add_argument("--fallback-file", default="")
    z.add_argument("--out", default="reports/zap.sarif")
    rt = sub.add_parser("runtime")
    rt.add_argument("--in", dest="inp", required=True, help="zap-alerts.json (co khoa rule_runtime)")
    rt.add_argument("--fallback-file", default="")
    rt.add_argument("--out", default="reports/runtime.sarif")
    a = ap.parse_args()
    if a.cmd == "semgrep":
        return lenh_semgrep(a)
    if a.cmd == "runtime":
        return lenh_runtime(a)
    return lenh_zap(a)


if __name__ == "__main__":
    sys.exit(main())
