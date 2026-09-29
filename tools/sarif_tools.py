#!/usr/bin/env python3
"""
Chuan hoa SARIF de GitHub Code Scanning lam CONG - thay cho cong tu viet.

Theo mo hinh moi (So do 6): pipeline KHONG tu quyet chan/qua. No dua ket qua
cua tung scanner len Code Scanning duoi dang SARIF; GitHub tu tinh alert nao
la MOI trong PR, hien chu thich dung dong, va ruleset "Require code scanning
results" khoa merge theo nguong tung cong cu. Dismiss + ly do trong tab
Security la duong chap nhan rui ro chinh thuc, co audit.

Hai lenh:

  semgrep   Doc SARIF cua Semgrep, chuan hoa muc do, TACH lam hai tep:
              - semgrep-du-an.sarif     rule tu viet (vulnshop-*), tin cay cao -> chan
              - semgrep-cong-dong.sarif rule cong dong                          -> tham khao
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
TIEN_TO_DU_AN = "vulnshop-"

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
    sast-detect.yaml, rule `vulnshop-sqli-commandtext-concat` thanh
    `devsecops-toolkit.semgrep-rules.vulnshop-sqli-commandtext-concat`.
    Id rule trong tep khong chua dau cham, nen phan sau dau cham cuoi la id goc.
    Rule cong dong (csharp.lang.security...) giu nguyen id - do la id registry.
    """
    return rid.rsplit(".", 1)[-1]


def la_rule_du_an(rid: str) -> bool:
    return id_ngan(rid).startswith(TIEN_TO_DU_AN)


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


def lenh_semgrep(a: argparse.Namespace) -> int:
    sarif = doc(a.inp)
    zap_alerts = doc(a.zap).get("alerts", []) if a.zap and Path(a.zap).is_file() else []
    routes = doc(a.routes).get("routes", []) if a.routes and Path(a.routes).is_file() else []

    du_an = {"version": sarif.get("version", "2.1.0"), "$schema": sarif.get("$schema"), "runs": []}
    cong_dong = copy.deepcopy(du_an)
    n_da, n_cd, n_kt = 0, 0, 0

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {r.get("id"): chuan_hoa_rule(r) for r in driver.get("rules", [])}
        res_da, res_cd, rule_da, rule_cd = [], [], {}, {}

        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid) or chuan_hoa_rule({"id": rid, "defaultConfiguration": {"level": res.get("level", "warning")}})
            res = copy.deepcopy(res)
            # level cua ket qua theo rule da chuan hoa, de ruleset "Alerts: Errors" dung
            res["level"] = rule["defaultConfiguration"]["level"]

            if la_rule_du_an(rid):
                # Dung id ngan, on dinh: khong phu thuoc thu muc checkout bo cong cu.
                # Doi id thi bo ruleIndex/rule cu di, vi danh sach rules bi dung lai.
                rid = id_ngan(rid)
                rule = dict(rule, id=rid)
                res["ruleId"] = rid
                res.pop("ruleIndex", None)
                res.pop("rule", None)
                # Doi chieu voi ZAP: cung CWE, cung endpoint -> DA KHAI THAC DUOC
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
                            n_kt += 1
                            break
                res_da.append(res); rule_da[rid] = rule; n_da += 1
            else:
                res.pop("ruleIndex", None)
                res.pop("rule", None)
                res_cd.append(res); rule_cd[rid] = rule; n_cd += 1

        def run_moi(results, rules_dict, ten):
            r2 = copy.deepcopy(run)
            r2["tool"]["driver"] = dict(driver, name=ten, rules=list(rules_dict.values()))
            r2["results"] = results
            r2.pop("automationDetails", None)
            return r2

        du_an["runs"].append(run_moi(res_da, rule_da, "Semgrep-du-an"))
        cong_dong["runs"].append(run_moi(res_cd, rule_cd, "Semgrep-cong-dong"))

    ghi(a.out_du_an, du_an)
    ghi(a.out_cong_dong, cong_dong)
    print(f"Semgrep: {n_da} canh bao rule du an -> {a.out_du_an}")
    print(f"         {n_cd} canh bao rule cong dong -> {a.out_cong_dong}")
    if zap_alerts:
        print(f"         {n_kt} canh bao rule du an DA KHAI THAC DUOC theo ZAP")
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


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("semgrep")
    s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--out-du-an", default="reports/semgrep-du-an.sarif")
    s.add_argument("--out-cong-dong", default="reports/semgrep-cong-dong.sarif")
    s.add_argument("--zap", default="")
    s.add_argument("--routes", default="")
    z = sub.add_parser("zap")
    z.add_argument("--in", dest="inp", required=True)
    z.add_argument("--routes", default="")
    z.add_argument("--fallback-file", default="")
    z.add_argument("--out", default="reports/zap.sarif")
    a = ap.parse_args()
    return lenh_semgrep(a) if a.cmd == "semgrep" else lenh_zap(a)


if __name__ == "__main__":
    sys.exit(main())
