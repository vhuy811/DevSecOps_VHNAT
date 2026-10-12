#!/usr/bin/env python3
"""Kiem thu chinh BO CHAM (tools/cham_diem.py).

VI SAO CAN TEP NAY
Moi con so trong bao cao cua do an di qua cham_diem.py: ti le bat, ti le bao
nham, bang theo CWE, bang do nguong. Nhung bo cham chua he co phep kiem nao.
Mot loi gan vai tro trong do - canh bao cua ham bad bi tinh sang ham good -
khong lam chuong trinh chet, khong in canh bao, chi lam con so sai. Da gap dung
kieu sai im lang do hai lan trong du an nay:
  - sig_re thieu nhanh "throws": doc 0/5 ham trong tep Juliet Java, moi canh bao
    mat vai tro, bang ra 0% tron - nhin y nhu "rule khong bat duoc gi".
  - thieu bo tien to "Servlet_": 1332/5772 case khong phan loai duoc nguon.
Ca hai chi lo ra khi co nguoi ngoi doc bang. Tep nay bien viec doc do thanh mot
phep kiem tu dong.

CACH LAM: dung corpus do day sinh luc chay, mo phong DUNG cau truc Juliet (ke ca
"throws Throwable" va bien the 81 tach tep bad/good), kem mot SARIF co dap an
biet truoc. Moi phep kiem khang dinh mot tinh chat ma neu vo thi mot con so cu
the trong bao cao se sai, va noi ro con so nao.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

GOC = Path(__file__).resolve().parent
CHAM = GOC / "cham_diem.py"

sys.path.insert(0, str(GOC))
from cham_diem import TRUC_NGUONG, dieu_kien_chan        # noqa: E402

# ----------------------------------------------------------------- fixture
# Tep Juliet that: chu ky co "throws Throwable", ham good la private, va
# goodG2B GIU LAI sink doc (chi doi nguon thanh hang so). Giu dung dac diem
# nay moi quan trong: do la hinh dang sinh ra bao nham that tren corpus.
TEP_01 = '''package juliet.testcases.CWE89_SQL_Injection;
import juliet.support.*;

public class {TEN} extends AbstractTestCase
{{
    public void bad() throws Throwable
    {{
        String data = System.getenv("ADD");
        IO.getDBConnection().createStatement()
          .executeQuery("select * from users where name='"+data+"'");
    }}

    public void good() throws Throwable
    {{
        goodG2B();
        goodB2G();
    }}

    private void goodG2B() throws Throwable
    {{
        String data = "foo";
        IO.getDBConnection().createStatement()
          .executeQuery("select * from users where name='"+data+"'");
    }}

    private void goodB2G() throws Throwable
    {{
        String data = System.getenv("ADD");
        java.sql.PreparedStatement st =
            IO.getDBConnection().prepareStatement("select * from users where name=?");
        st.setString(1, data);
        st.executeQuery();
    }}
}}
'''

# Sink dat trong mot ham KHONG co vai tro (`run`) long trong ham CO vai tro
# (`goodB2G`). Day la hinh dang lam canh bao bi bo im lang neu bo cham chi lay
# ham trong cung de xet vai tro.
TEP_LONG = '''package juliet.testcases.CWE89_SQL_Injection;
import juliet.support.*;

public class {TEN} extends AbstractTestCase
{{
    public void bad() throws Throwable
    {{
        String data = System.getenv("ADD");
        IO.getDBConnection().createStatement()
          .executeQuery("select * from users where name='"+data+"'");
    }}

    private void goodB2G() throws Throwable
    {{
        final String data = "foo";
        new Thread(new Runnable()
        {{
            public void run()
            {{
                try
                {{
                    IO.getDBConnection().createStatement()
                      .executeQuery("select * from users where name='"+data+"'");
                }}
                catch (Throwable e) {{ }}
            }}
        }}).start();
    }}
}}
'''

# Bien the 81: bad va good nam o HAI TEP khac nhau, ten ham deu la "action".
# Vai tro phai lay tu DUOI TEN TEP, khong lay tu ten ham.
TEP_81_BASE = '''package juliet.testcases.CWE89_SQL_Injection;
public abstract class {TEN} extends AbstractTestCase
{{
    public abstract void action(String data) throws Throwable;
}}
'''
TEP_81_BAD = '''package juliet.testcases.CWE89_SQL_Injection;
public class {TEN} extends CWE89_SQL_Injection__Environment_executeQuery_81_base
{{
    public void action(String data) throws Throwable
    {{
        IO.getDBConnection().createStatement()
          .executeQuery("select * from users where name='"+data+"'");
    }}
}}
'''
TEP_81_GOOD = '''package juliet.testcases.CWE89_SQL_Injection;
public class {TEN} extends CWE89_SQL_Injection__Environment_executeQuery_81_base
{{
    public void action(String data) throws Throwable
    {{
        java.sql.PreparedStatement st =
            IO.getDBConnection().prepareStatement("select * from users where name=?");
        st.setString(1, data);
        st.executeQuery();
    }}
}}
'''


def dung_corpus(d: Path) -> dict:
    """Sinh corpus + tra ve so dong cua cac moc can nham canh bao vao."""
    d.mkdir(parents=True, exist_ok=True)
    moc = {}

    def ghi(ten: str, mau: str):
        p = d / ten
        p.write_text(mau.format(TEN=ten[:-5]), encoding="utf-8")
        dong = p.read_text(encoding="utf-8").splitlines()
        return {
            "tep": ten,
            "bad": next(i + 1 for i, l in enumerate(dong) if "executeQuery(\"select" in l
                        and _trong_ham(dong, i, "bad")),
        }

    # Hai case 01 (baseline) voi nguon khac nhau -> kiem ca loai_nguon
    for ten in ("CWE89_SQL_Injection__Environment_executeQuery_01.java",
                "CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01.java"):
        p = d / ten
        p.write_text(TEP_01.format(TEN=ten[:-5]), encoding="utf-8")
        dong = p.read_text(encoding="utf-8").splitlines()
        moc[ten] = {
            "bad": _dong_sink(dong, "bad"),
            "goodG2B": _dong_sink(dong, "goodG2B"),
            "goodB2G": _dong_sink(dong, "goodB2G"),
        }

    ten = "CWE89_SQL_Injection__Environment_executeQuery_45.java"
    p = d / ten
    p.write_text(TEP_LONG.format(TEN=ten[:-5]), encoding="utf-8")
    dong = p.read_text(encoding="utf-8").splitlines()
    moc[ten] = {"bad": _dong_sink(dong, "bad"),
                "trong_run": _dong_sink(dong, "run")}

    for ten, mau in (
        ("CWE89_SQL_Injection__Environment_executeQuery_81_base.java", TEP_81_BASE),
        ("CWE89_SQL_Injection__Environment_executeQuery_81_bad.java", TEP_81_BAD),
        ("CWE89_SQL_Injection__Environment_executeQuery_81_good.java", TEP_81_GOOD),
    ):
        p = d / ten
        p.write_text(mau.format(TEN=ten[:-5]), encoding="utf-8")
        dong = p.read_text(encoding="utf-8").splitlines()
        moc[ten] = {"action": next((i + 1 for i, l in enumerate(dong)
                                   if "executeQuery(" in l), 1)}
    return moc


def _dong_sink(dong: list[str], ham: str) -> int:
    """Dong goi sink NAM TRONG ham co ten cho truoc."""
    trong = False
    for i, l in enumerate(dong):
        if f" {ham}()" in l:
            trong = True
            continue
        if trong and "executeQuery(" in l:
            return i + 1
    raise AssertionError(f"fixture sai: khong thay sink trong ham {ham}")


def _trong_ham(*_a):      # giu de chu ky ghi() cu khong vo neu duoc dung lai
    return True


def sarif(canh: list[dict]) -> dict:
    """canh: [{rule, cwe, level, sev, file, line}] -> SARIF toi thieu nhung
    DUNG hinh dang CodeQL/Semgrep that: rule metadata o tool.driver.rules,
    CWE nam trong properties.tags."""
    ids = sorted({c["rule"] for c in canh})
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "thu", "rules": [
                {"id": r,
                 "properties": {"tags": [f"external/cwe/cwe-{c['cwe']:03d}"
                                         for c in canh if c["rule"] == r][:1],
                                "security-severity": str(
                                    next(c["sev"] for c in canh if c["rule"] == r))},
                 "defaultConfiguration": {"level": next(
                     c["level"] for c in canh if c["rule"] == r)}}
                for r in ids]}},
            "results": [{
                "ruleId": c["rule"],
                "message": {"text": "thu"},
                "level": c["level"],
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f"bench/src/testcases/{c['file']}"},
                    "region": {"startLine": c["line"]}}}],
            } for c in canh],
        }],
    }


def chay(goc: Path, sarif_duong: Path, chan: list[str], out: Path) -> dict:
    lenh = [sys.executable, str(CHAM), "juliet", "--goc", str(goc),
            "--sarif", f"thu={sarif_duong}", "--out", str(out)]
    for c in chan:
        lenh += ["--chan", c]
    r = subprocess.run(lenh, capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"cham_diem.py thoat {r.returncode}\n{r.stdout}\n{r.stderr}")
    return json.loads(out.read_text(encoding="utf-8"))


# ------------------------------------------------------------- phep kiem
LOI: list[str] = []


def kiem(dieu: bool, ten: str, hau_qua: str):
    if dieu:
        print(f"  [DAT ] {ten}")
    else:
        print(f"  [HONG] {ten}\n         -> {hau_qua}")
        LOI.append(ten)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        goc = t / "testcases"
        moc = dung_corpus(goc)
        f01 = "CWE89_SQL_Injection__Environment_executeQuery_01.java"
        f02 = "CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01.java"
        fbad = "CWE89_SQL_Injection__Environment_executeQuery_81_bad.java"
        fgood = "CWE89_SQL_Injection__Environment_executeQuery_81_good.java"

        print("1. Gan vai tro bad/good theo ham chua dong canh bao")
        canh = [
            # dung tren ham bad -> phai la TP
            {"rule": "taint-sqli", "cwe": 89, "level": "error", "sev": 9.8,
             "file": f01, "line": moc[f01]["bad"]},
            # dung tren goodG2B -> phai la FP (sink doc nhung nguon hang so)
            {"rule": "hinh-dang-concat", "cwe": 89, "level": "error", "sev": 6.1,
             "file": f01, "line": moc[f01]["goodG2B"]},
        ]
        s = t / "a.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["thu:level=error"], t / "a.json")
        tong = d["tong"]["thu"]
        kiem(tong["tp"] == 1, "canh bao tren ham bad duoc tinh la BAT",
             "ti le bat trong bao cao se thap hon thuc te")
        kiem(tong["fp"] == 1, "canh bao tren ham goodG2B duoc tinh la BAO NHAM",
             "ti le bao nham trong bao cao se thap gia tao - loi nguy hiem nhat")
        kiem(d["so_case"] == 4, f"dem dung so case (4), dang la {d['so_case']}",
             "mau so sai thi moi ti le sai theo")

        print("2. Bien the 81 - vai tro lay tu duoi ten tep, khong tu ten ham")
        canh = [
            {"rule": "taint-sqli", "cwe": 89, "level": "error", "sev": 9.8,
             "file": fbad, "line": moc[fbad]["action"]},
            {"rule": "taint-sqli", "cwe": 89, "level": "error", "sev": 9.8,
             "file": fgood, "line": moc[fgood]["action"]},
        ]
        s = t / "b.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["thu:level=error"], t / "b.json")
        kiem(d["tong"]["thu"]["tp"] == 1 and d["tong"]["thu"]["fp"] == 1,
             "81_bad -> BAT, 81_good -> BAO NHAM (ca hai ham deu ten 'action')",
             "bien the 81 chiem ~5% corpus; sai o day lam lech ca hai ti le")

        print("3. Canh bao khac ho CWE phai bi bo qua")
        canh = [{"rule": "lac-de", "cwe": 798, "level": "error", "sev": 9.8,
                 "file": f01, "line": moc[f01]["bad"]}]
        s = t / "c.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["thu:level=error"], t / "c.json")
        kiem(d["tong"]["thu"]["tp"] == 0,
             "canh bao CWE-798 tren case CWE-89 khong duoc tinh la bat",
             "neu tinh, mot cong cu bao bua moi noi se co ti le bat cao gia tao")

        print("4. Canh bao ngoai corpus phai duoc DEM, khong im lang bo")
        canh = [{"rule": "taint-sqli", "cwe": 89, "level": "error", "sev": 9.8,
                 "file": "juliet/support/IO.java", "line": 10}]
        s = t / "d.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["thu:level=error"], t / "d.json")
        kiem(d["tong"]["thu"]["canh_bao_ngoai_bo_do"] == 1,
             "canh bao o tep ho tro duoc dem vao 'canh bao ngoai bo do'",
             "con so nay la dau hieu duy nhat cho biet bo cham doc sai ten tep")

        print("5. --chan level=error phai loc bo canh bao muc warning")
        canh = [
            {"rule": "chi-bao", "cwe": 89, "level": "warning", "sev": 3.1,
             "file": f01, "line": moc[f01]["bad"]},
        ]
        s = t / "e.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["cong=thu:level=error"], t / "e.json")
        kiem(d["tong"]["cong"]["tp"] == 0,
             "rule muc warning khong duoc tinh vao nhom co quyen chan",
             "se bao cao la 'chan duoc' mot lo loi ma thuc te merge van qua")

        print("6. Sink trong ham khong vai tro, long trong ham good")
        flong = "CWE89_SQL_Injection__Environment_executeQuery_45.java"
        canh = [{"rule": "hinh-dang-concat", "cwe": 89, "level": "error", "sev": 6.1,
                 "file": flong, "line": moc[flong]["trong_run"]}]
        s = t / "g.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["thu:level=error"], t / "g.json")
        kiem(d["tong"]["thu"]["fp"] == 1,
             "canh bao trong `run()` long trong goodB2G duoc tinh la BAO NHAM",
             "canh bao bi BO im lang: ti le bao nham thap hon thuc te ma khong "
             "co dau hieu gi trong bao cao")

        print("7. Bang theo rule - cot 'bat rieng' va 'bo rule nay thi con'")
        canh = [
            {"rule": "taint-sqli", "cwe": 89, "level": "error", "sev": 9.8,
             "file": f01, "line": moc[f01]["bad"]},
            {"rule": "taint-sqli", "cwe": 89, "level": "error", "sev": 9.8,
             "file": f02, "line": moc[f02]["bad"]},
            # rule hinh dang: bao dung ca bad (trung voi taint) va ca goodG2B
            {"rule": "hinh-dang-concat", "cwe": 89, "level": "error", "sev": 6.1,
             "file": f01, "line": moc[f01]["bad"]},
            {"rule": "hinh-dang-concat", "cwe": 89, "level": "error", "sev": 6.1,
             "file": f01, "line": moc[f01]["goodG2B"]},
            {"rule": "hinh-dang-concat", "cwe": 89, "level": "error", "sev": 6.1,
             "file": f02, "line": moc[f02]["goodG2B"]},
        ]
        s = t / "f.sarif"
        s.write_text(json.dumps(sarif(canh)), encoding="utf-8")
        d = chay(goc, s, ["cong=thu:level=error"], t / "f.json")
        r = d.get("theo_rule", {}).get("cong", {})
        kiem(bool(r), "JSON co muc theo_rule",
             "khong tach duoc bao nham theo rule thi chi con lua chon giu/bo ca cong cu")
        kiem(r.get("hinh-dang-concat", {}).get("nham") == 2,
             "rule hinh dang bi tinh 2 case bao nham",
             "khong khoanh duoc rule nao gay bao nham")
        kiem(r.get("hinh-dang-concat", {}).get("bat_rieng") == 0,
             "rule hinh dang co 'bat rieng' = 0 (taint da bat het phan no bat)",
             "day la cot quyet dinh co bo duoc rule do mien phi hay khong")
        kiem(r.get("taint-sqli", {}).get("bat_rieng") == 1,
             "taint-sqli co 'bat rieng' = 1 (case 02 chi no bat)",
             "neu ra 0 thi se ket luan sai rang bo taint-sqli khong mat gi")

        print("8. Bo do dang bench: bang chinh va bang do nguong phai KHOP mau so")
        bench = t / "bench"
        for khung in ("flask",):
            td = bench / khung / "testcode"
            td.mkdir(parents=True, exist_ok=True)
            dong_csv = ["# test name,category,real vulnerability,CWE"]
            for i in range(1, 9):
                co_loi = i <= 4
                (td / f"benchmark_test_{i:05d}.py").write_text(
                    "import sqlite3\n"
                    + ("q = 'SELECT * FROM t WHERE a=' + x\n" if co_loi
                       else "q = 'SELECT * FROM t WHERE a=?'\n"),
                    encoding="utf-8")
                dong_csv.append(f"BenchmarkTest{i:05d},sqli,"
                                f"{'true' if co_loi else 'false'},89")
            (bench / khung / "expectedresults-2026.01.01.csv").write_text(
                "\n".join(dong_csv) + "\n", encoding="utf-8")

        # Canh bao: dung tren 2/4 case co loi va 1/4 case sach
        # -> bang chinh phai ra bat 50%, nham 25% (mau so 4 va 4)
        # -> neu dung mau so kieu Juliet (8) se ra 25% va 12%, tuc MOT NUA.
        canh = []
        for i in (1, 2, 5):
            canh.append({"rule": "taint-sqli", "cwe": 89, "level": "error",
                         "sev": 9.8, "file": f"benchmark_test_{i:05d}.py",
                         "line": 2})
        sb = sarif(canh)
        for r in sb["runs"][0]["results"]:
            ten = Path(r["locations"][0]["physicalLocation"]
                       ["artifactLocation"]["uri"]).name
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = \
                f"bench/flask/testcode/{ten}"
        s8 = t / "h.sarif"
        s8.write_text(json.dumps(sb), encoding="utf-8")
        md8 = t / "h.md"
        r8 = subprocess.run(
            [sys.executable, str(CHAM), "bench-csv",
             "--bo", f"flask={bench / 'flask'}",
             "--sarif", f"semgrep-du-an={s8}",
             "--chan", "pipeline-hien-tai=semgrep-du-an:level=error",
             "--do-nguong", "--out", str(t / "h.json"), "--md", str(md8)],
            capture_output=True, text=True)
        if r8.returncode != 0:
            kiem(False, "lenh bench-csv chay duoc",
                 f"khong chay duoc thi khong kiem duoc mau so\n{r8.stdout[-600:]}\n{r8.stderr[-600:]}")
        else:
            txt = md8.read_text(encoding="utf-8")
            # bang chinh: dong cua nhom chan "cong"
            m_chinh = re.search(r"^\| pipeline-hien-tai \| ([\d.]+)% \| ([\d.]+)%",
                                txt, re.M)
            # bang do nguong: dong co nhan "dang dung"
            m_sweep = re.search(r"\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|[^|\n]*đang dùng", txt)
            kiem(bool(m_chinh and m_sweep),
                 "doc duoc ca hai bang (chinh + do nguong)",
                 "khong doc duoc thi khong so sanh duoc hai mau so")
            if m_chinh and m_sweep:
                c = (float(m_chinh.group(1)), float(m_chinh.group(2)))
                w = (float(m_sweep.group(1)), float(m_sweep.group(2)))
                kiem(abs(c[0] - w[0]) < 0.6 and abs(c[1] - w[1]) < 0.6,
                     f"hai bang khop nhau: bang chinh {c[0]}%/{c[1]}% "
                     f"vs do nguong {w[0]}%/{w[1]}%",
                     "bang do nguong dung mau so kieu Juliet (toan bo case) "
                     "trong khi bang chinh tach co_loi/sach -> hai bang canh "
                     "nhau trong CUNG mot bao cao lech nhau dung GAP DOI. Da "
                     "xay ra that o lan chay Phong do Python #2.")

    # ---------------------------------------------------------------- 9
    print("9. Bo loc --chan: &!id= phai loai theo ID truy van, &!cwe= theo ho CWE")
    # VI SAO: cong chan that loai java/concatenated-sql-query theo ID TRUY VAN
    # (G6.6). Neu bo do khong loai duoc y nhu vay thi cot pipeline-hien-tai cua
    # bang do noi 25% bao nham trong khi cong that cho ~9% - bao cao se trich mot
    # con so khong ton tai o dau ca. Bai hoc cua lan loai CWE-643 theo TAG: tag
    # do co o moi ngon ngu nen quyet dinh cua C# bi ap cho ca Java.
    def _r(rule, sev=6.1, cwes=frozenset({89}), level="error"):
        return {"rule": rule, "sev": sev, "level": level, "cwes": set(cwes)}

    f_id = dieu_kien_chan(
        "sev>=4&!id=java/concatenated-sql-query,java/concatenated-command-line")
    kiem(not f_id(_r("java/concatenated-sql-query")),
         "&!id= loai dung truy van duoc liet ke",
         "khong loai duoc thi bo do do cong chan CU, khong phai cong dang chay")
    kiem(f_id(_r("java/sql-injection")),
         "&!id= KHONG loai truy van khac cung ho CWE",
         "loai qua rong thi bo do bao thap hon su that - vua dung cai bay cua "
         "lan loai theo tag cwe-643")
    kiem(not f_id(_r("java/concatenated-command-line", sev=9.8, cwes={78})),
         "&!id= loai duoc ca hai ID trong danh sach",
         "chi loai cai dau thi 4 diem bao nham con lai khong ai thay")

    f_cwe = dieu_kien_chan("sev>=4&!cwe=643")
    kiem(not f_cwe(_r("bat-ky", cwes={643})) and f_cwe(_r("bat-ky", cwes={89})),
         "&!cwe= cu van hoat dong nguyen ven",
         "them &!id= ma lam hong &!cwe= thi phong do C# doi so trong im lang")

    f_ca = dieu_kien_chan("sev>=4&!cwe=643&!id=java/concatenated-sql-query")
    kiem(not f_ca(_r("x", cwes={643})) and not f_ca(_r("java/concatenated-sql-query"))
         and f_ca(_r("java/sql-injection")),
         "dung duoc ca &!cwe= va &!id= trong mot spec",
         "neu khong ket hop duoc thi khong mo hinh hoa duoc cong chan that, "
         "cong do loai CA cs/xml/xpath-injection VA hai truy van java/concatenated-*")

    kiem(dieu_kien_chan("sev>=4")( _r("java/concatenated-sql-query")),
         "khong co bo loc thi khong loai gi (muc `medium` giu nguyen y nghia)",
         "muc `medium` cua truc nguong phai la muc KHONG loai, de so sanh duoc "
         "voi `med-noi` tren cung mot bang")

    # ---------------------------------------------------------------- 10
    print("10. Truc nguong va workflow phai dung CUNG danh sach ID")
    import re as _re
    wf = (Path(__file__).resolve().parent.parent
          / ".github" / "workflows" / "phong-do-java.yml").read_text(encoding="utf-8")
    m_wf = _re.search(r"pipeline-hien-tai=codeql-local:([^\"\\]+)", wf)
    muc_noi = dict(TRUC_NGUONG["codeql-local"]).get("med-noi")
    kiem(bool(m_wf), "doc duoc dieu kien codeql-local tu phong-do-java.yml",
         "khong doc duoc thi khong doi chieu duoc hai cho")
    if m_wf and muc_noi:
        kiem(m_wf.group(1).strip() == muc_noi[0],
             f"workflow va truc nguong khop nhau ({muc_noi[0]})",
             f"workflow dung `{m_wf.group(1).strip()}` con truc nguong dung "
             f"`{muc_noi[0]}` -> nhan_dang_chay() se ghi `?` va bang xep hang "
             f"khong danh dau duoc dong dang chay")

    print()
    if LOI:
        print(f"HONG {len(LOI)} phep kiem: " + "; ".join(LOI))
        return 1
    print("DAT het. Bo cham gan vai tro va tach rule dung.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
