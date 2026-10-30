import sys
import subprocess
import json
import html
from datetime import datetime
from pathlib import Path

import streamlit as st

# PATCHPROOF — single-navigation Security Operations Console
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.analyzer import scan_application
from patcher.patch_engine import generate_patches
from reports.report_engine import generate_report

TARGET = ROOT / "vulnerable_app" / "app.py"
PATCHED = ROOT / "vulnerable_app" / "patched_app.py"
DIFF = ROOT / "reports" / "security_patch.diff"
REPORT = ROOT / "reports" / "security_report.json"

st.set_page_config(
    page_title="PATCHPROOF | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ------------------------------ visual system ------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Manrope:wght@400;500;600;700;800&display=swap');
:root {
 --bg:#080c12; --panel:#101821; --panel2:#141f2b; --line:#263746;
 --text:#edf3f7; --muted:#91a2b2; --cyan:#53d7d1; --lime:#b5ed75;
 --red:#ff6d76; --amber:#f5c56b; --blue:#79aaff;
}
html,body,[class*="css"] {font-family:'Manrope',sans-serif}
.stApp {background:
 radial-gradient(ellipse at 50% -20%,rgba(39,113,125,.22),transparent 42%),
 linear-gradient(180deg,#080c12,#0a1018 60%,#080c12);color:var(--text)}
[data-testid="stHeader"] {background:rgba(8,12,18,.92)}
[data-testid="stSidebar"] {display:none}
.block-container {max-width:1600px;padding:1.4rem 2.5rem 3rem}
h1,h2,h3,h4 {color:var(--text)!important;letter-spacing:-.04em}
p,li,label {color:#c0ccd6}
small,[data-testid="stCaption"] {color:var(--muted)!important}
hr {border-color:var(--line)!important}
code,pre {font-family:'IBM Plex Mono',monospace!important}
header[data-testid="stHeader"] {height:2.5rem}
.brandline {display:flex;align-items:center;justify-content:space-between;
 border-bottom:1px solid var(--line);padding:4px 0 18px;margin-bottom:20px}
.brand {display:flex;align-items:center;gap:13px}
.brandmark {width:43px;height:43px;border:1px solid #347b82;border-radius:12px;
 display:grid;place-items:center;background:linear-gradient(145deg,#173b42,#142638);
 color:var(--cyan);font-size:22px}
.brandname {font-size:19px;font-weight:800;letter-spacing:.16em}
.brandtag {font:10px 'IBM Plex Mono';letter-spacing:.2em;color:var(--cyan);margin-top:3px}
.sysmeta {font:10px 'IBM Plex Mono';letter-spacing:.12em;color:#8194a5;text-align:right}
.live {color:var(--lime)}
.navbox {background:#0d151e;border:1px solid var(--line);border-radius:12px;
 padding:8px 12px;margin:0 0 23px}
.navbox [data-testid="stRadio"] > div {gap:7px;flex-wrap:wrap}
.navbox [data-testid="stRadio"] label {border:1px solid transparent;border-radius:8px;
 padding:9px 14px;background:transparent;color:#9eafbd!important;font-size:12px;font-weight:700}
.navbox [data-testid="stRadio"] label:has(input:checked) {
 background:#18343b;border-color:#34747a;color:#eaffff!important}
.navbox [data-testid="stRadio"] label p {color:inherit!important}
.navbox [data-testid="stRadio"] input {display:none}
.overline {font:10px 'IBM Plex Mono';letter-spacing:.2em;color:#6f8b9c;text-transform:uppercase}
.pagehead {display:flex;justify-content:space-between;align-items:end;gap:18px;
 border-bottom:1px solid var(--line);padding-bottom:17px;margin:5px 0 22px}
.pagehead h1 {font-size:30px;margin:4px 0 0}
.pagehead p {font-size:12px;color:var(--muted);margin:5px 0 0}
.badge {font:10px 'IBM Plex Mono';letter-spacing:.1em;border:1px solid #34515e;
 color:var(--cyan);padding:7px 10px;border-radius:5px;background:#10212a}
.metric {background:linear-gradient(145deg,#131f2a,#0e171f);border:1px solid #293b49;
 border-radius:11px;padding:17px 18px;min-height:116px;position:relative}
.metric:after {content:"";position:absolute;right:13px;top:13px;width:6px;height:6px;
 border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan)}
.mlabel {font:10px 'IBM Plex Mono';letter-spacing:.14em;color:#8296a6;text-transform:uppercase}
.mvalue {font-size:32px;font-weight:800;letter-spacing:-.05em;margin-top:9px;color:#f1f7fb}
.mnote {font-size:11px;color:#8294a3;margin-top:3px}
.box {background:linear-gradient(145deg,#121d27,#0e161f);border:1px solid #293a48;
 border-radius:12px;padding:18px 19px;margin-bottom:14px}
.boxtitle {font-size:15px;font-weight:800;color:#eaf1f6}
.boxsub {font-size:11px;color:#8799a8;line-height:1.6;margin-top:5px}
.command {background:#0c131b;border:1px solid #2b414e;border-radius:12px;padding:20px}
.commandlabel {font:10px 'IBM Plex Mono';letter-spacing:.18em;color:var(--cyan)}
.command h2 {font-size:27px;line-height:1.12;margin:12px 0 8px}
.command p {font-size:12px;color:#9eafbd;line-height:1.7}
.stage {display:flex;gap:12px;align-items:center;padding:12px 0;border-bottom:1px solid #23333f}
.stage:last-child {border-bottom:0}
.stageicon {width:31px;height:31px;border-radius:8px;display:grid;place-items:center;
 border:1px solid #34505c;color:var(--cyan);font:11px 'IBM Plex Mono'}
.stagetitle {font-size:12px;font-weight:800;color:#dfe8ee}
.stagedesc {font-size:10px;color:#8497a6;margin-top:3px}
.status {margin-left:auto;font:9px 'IBM Plex Mono';letter-spacing:.1em;padding:5px 7px;
 border-radius:4px;border:1px solid #344958;color:#8da4b4}
.ok {color:var(--lime);border-color:#45653b;background:#172318}
.wait {color:#8da4b4}
.finding {border:1px solid #35424d;border-left:3px solid var(--red);
 background:#111a23;border-radius:9px;padding:15px 17px;margin:10px 0}
.finding h3 {font-size:14px;margin:0}
.meta {font:10px 'IBM Plex Mono';letter-spacing:.08em;color:#8295a5;margin:7px 0}
.finding p {font-size:11px;color:#adbbc6;line-height:1.6;margin:5px 0}
.pill {font:9px 'IBM Plex Mono';letter-spacing:.1em;padding:4px 7px;border-radius:4px;
 color:#ff9da3;background:#321c22;border:1px solid #66343d}
.log {background:#070b10;border:1px solid #2a3b48;border-radius:9px;padding:14px;
 color:#b7c9d3;font:11px 'IBM Plex Mono';white-space:pre-wrap;overflow-wrap:anywhere}
.stButton>button {background:linear-gradient(100deg,#176a70,#245e83)!important;
 color:#f4ffff!important;border:1px solid #3b8990!important;border-radius:7px!important;
 font-weight:800!important;min-height:43px}
.stButton>button:hover {filter:brightness(1.15);border-color:var(--cyan)!important}
.stDownloadButton>button {background:#172530!important;color:#dcebf3!important;
 border:1px solid #38515f!important;border-radius:7px!important}
.stTextInput input,.stSelectbox div[data-baseweb="select"] {background:#0d1720!important}
div[data-testid="stExpander"] {background:#101a23;border:1px solid #293c49;border-radius:9px}
div[data-testid="stAlert"] {border-radius:8px}
.stTabs [data-baseweb="tab"] {color:#a9b9c5}
.stTabs [aria-selected="true"] {color:var(--cyan)!important}
.footer {border-top:1px solid var(--line);margin-top:35px;padding-top:13px;
 display:flex;justify-content:space-between;color:#718696;font:9px 'IBM Plex Mono';letter-spacing:.12em}
</style>
""", unsafe_allow_html=True)

# ------------------------------ operations ------------------------------
def read_report():
    if not REPORT.exists():
        return None
    try:
        return json.loads(REPORT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

def run_pipeline():
    stages, findings, result = [], [], None
    try:
        with st.spinner("01 / Scanning source with targeted AST rules..."):
            findings = scan_application(TARGET)
        stages.append(("SOURCE ANALYSIS", True, f"{len(findings)} supported finding(s)"))
        with st.spinner("02 / Generating patched application and unified diff..."):
            generate_patches()
        patch_ok = PATCHED.exists() and DIFF.exists()
        stages.append(("PATCH GENERATION", patch_ok, "Patched copy and diff checked"))
        if not patch_ok:
            raise RuntimeError("Patch engine did not create both expected artefacts.")
        with st.spinner("03 / Executing the complete pytest suite..."):
            result = subprocess.run([sys.executable, "-m", "pytest", "-v"],
                cwd=ROOT, capture_output=True, text=True, timeout=180)
        tests_ok = result.returncode == 0
        stages.append(("REGRESSION VALIDATION", tests_ok, f"pytest exit code {result.returncode}"))
        if tests_ok:
            with st.spinner("04 / Refreshing JSON security assessment..."):
                generate_report()
            stages.append(("REPORT GENERATION", REPORT.exists(), "Assessment JSON refreshed"))
        else:
            stages.append(("REPORT GENERATION", False, "Skipped because tests failed"))
        st.session_state.findings = findings
        st.session_state.test_result = result
        st.session_state.stages = stages
        st.session_state.complete = True
        st.session_state.last_run = datetime.now().strftime("%d %b %Y · %H:%M:%S")
        st.session_state.error = None
    except Exception as exc:
        st.session_state.stages = stages
        st.session_state.error = f"{type(exc).__name__}: {exc}"
        st.session_state.complete = True
    st.rerun()

def metric(label, value, note):
    st.markdown(f'<div class="metric"><div class="mlabel">{html.escape(str(label))}</div>'
        f'<div class="mvalue">{html.escape(str(value))}</div>'
        f'<div class="mnote">{html.escape(str(note))}</div></div>', unsafe_allow_html=True)

def finding_card(item, idx):
    title = str(item.get("type", "Finding"))
    severity = str(item.get("severity", "Unknown"))
    evidence = str(item.get("evidence", "No evidence supplied"))
    file_path = str(item.get("file", "Unknown"))
    line = str(item.get("line", "—"))
    if "SQL Injection" in title:
        cwe, impact = "CWE-89", "Untrusted input may alter query logic and expose or modify records."
        fix = "Replace SQL string interpolation with parameterized query execution."
    else:
        cwe, impact = "CWE-639", "A requester may access an object belonging to another account."
        fix = "Bind the resource lookup to authenticated server-side identity and enforce ownership."
    st.markdown(f'<div class="finding"><div style="display:flex;justify-content:space-between;gap:12px">'
        f'<h3>{idx:02d} / {html.escape(title)}</h3><span class="pill">{html.escape(severity.upper())}</span></div>'
        f'<div class="meta">{cwe} &nbsp; / &nbsp; SOURCE LINE {html.escape(line)}</div>'
        f'<p><b>Evidence</b> — {html.escape(evidence)}</p><p><b>Impact</b> — {html.escape(impact)}</p>'
        f'<p><b>Recommended fix</b> — {html.escape(fix)}</p>'
        f'<p style="color:#748a99"><b>File</b> — {html.escape(file_path)}</p></div>', unsafe_allow_html=True)

# ------------------------------ session state ------------------------------
for key, default in {
    "findings": [], "test_result": None, "stages": [], "complete": False,
    "last_run": None, "error": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

findings = st.session_state.findings
test_result = st.session_state.test_result
report = read_report()
patch_ready = PATCHED.exists() and DIFF.exists()
tests_pass = test_result is not None and test_result.returncode == 0

# ------------------------------ masthead ------------------------------
st.markdown(
    '<div class="brandline"><div class="brand"><div class="brandmark">⬡</div><div>'
    '<div class="brandname">PATCHPROOF</div><div class="brandtag">APPLICATION SECURITY / OPERATIONS CONSOLE</div>'
    '</div></div><div class="sysmeta"><span class="live">● SYSTEM ONLINE</span><br>'
    'LOCAL FIXTURE &nbsp; / &nbsp; OFFLINE-CAPABLE CORE</div></div>',
    unsafe_allow_html=True)

pages = ["Command Deck", "Findings", "Patch Review", "Test Bench", "Evidence", "Architecture"]
labels = ["01  Command deck", "02  Findings", "03  Patch review", "04  Test bench", "05  Evidence", "06  Architecture"]
st.markdown('<div class="navbox">', unsafe_allow_html=True)
page = st.radio("Workspace", pages, horizontal=True, format_func=lambda x: labels[pages.index(x)],
    label_visibility="collapsed", key="workspace_navigation")
st.markdown('</div>', unsafe_allow_html=True)

if st.session_state.error:
    st.error("Pipeline error: " + st.session_state.error)

# ------------------------------ command deck ------------------------------
if page == "Command Deck":
    st.markdown('<div class="pagehead"><div><div class="overline">CONTROL DECK / 00</div>'
        '<h1>Security operations</h1><p>One controlled workflow. Four verifiable outputs.</p></div>'
        '<span class="badge">PATCHPROOF / LOCAL SESSION</span></div>', unsafe_allow_html=True)

    left, right = st.columns([1.55, 1], gap="large")
    with left:
        st.markdown('<div class="command"><div class="commandlabel">MISSION / PATCHPROOF-001</div>'
            '<h2>Find the weakness.<br>Ship the proof.</h2>'
            '<p>Inspect the deliberately vulnerable Flask fixture, generate secure remediation changes, '
            'run the regression suite against the patched copy, and package the evidence.</p>'
            '<div class="overline">SCOPE: SQL INJECTION &nbsp; / &nbsp; IDOR</div></div>', unsafe_allow_html=True)
        if st.button("▶  EXECUTE SECURITY PIPELINE", use_container_width=True, key="run_main"):
            run_pipeline()
        st.caption("Runs the real scanner, patch engine, pytest suite and report generator. No dashboard-only results.")
    with right:
        st.markdown('<div class="box"><div class="overline">EXECUTION STATUS</div>'
            f'<div style="font-size:27px;font-weight:800;margin:7px 0">{ "ANALYZED" if st.session_state.complete else "STANDBY" }</div>'
            f'<div class="boxsub">Last run · {html.escape(st.session_state.last_run or "No run in this session")}</div><hr>'
            '<div class="overline">TARGET</div><div style="font-size:13px;margin:7px 0 15px">vulnerable_app / app.py</div>'
            '<div class="overline">EXECUTION MODE</div><div style="font-size:13px;margin-top:7px">Local · Synthetic data · No external target</div>'
            '</div>', unsafe_allow_html=True)

    st.markdown('<div class="overline" style="margin:23px 0 10px">LIVE SECURITY SNAPSHOT</div>', unsafe_allow_html=True)
    high = sum(1 for x in findings if str(x.get("severity", "")).lower() == "high")
    cols = st.columns(4)
    with cols[0]: metric("Findings detected", len(findings) if st.session_state.complete else "—", "Latest scan")
    with cols[1]: metric("High severity", high if st.session_state.complete else "—", "Triage priority")
    with cols[2]: metric("Patch artefacts", "READY" if patch_ready else "—", "Patched copy + diff")
    with cols[3]: metric("Regression suite", "PASS" if tests_pass else ("FAIL" if test_result else "—"), "Complete pytest run")

    st.markdown('<div class="overline" style="margin:24px 0 10px">PIPELINE TELEMETRY</div>', unsafe_allow_html=True)
    stages = [
        ("01", "SOURCE SCAN", "Targeted AST rules", bool(st.session_state.complete and findings is not None)),
        ("02", "PATCH BUILD", "Secure copy + unified diff", patch_ready),
        ("03", "TEST BENCH", "Security and regression suite", tests_pass),
        ("04", "EVIDENCE", "Machine-readable assessment", REPORT.exists()),
    ]
    a, b = st.columns(2, gap="medium")
    for i, (num, title, desc, ok) in enumerate(stages):
        with (a if i % 2 == 0 else b):
            st.markdown(f'<div class="box"><div style="display:flex;align-items:center;gap:12px">'
                f'<div class="stageicon">{num}</div><div><div class="boxtitle">{title}</div>'
                f'<div class="boxsub">{desc}</div></div><span class="status {"ok" if ok else "wait"}">'
                f'{"READY" if ok else "PENDING"}</span></div></div>', unsafe_allow_html=True)

    if findings:
        st.markdown('<div class="overline" style="margin:22px 0 8px">PRIORITY FINDINGS</div>', unsafe_allow_html=True)
        for i, item in enumerate(findings, 1):
            finding_card(item, i)
    if st.session_state.stages:
        with st.expander("Inspect latest pipeline stage results"):
            for name, ok, detail in st.session_state.stages:
                st.write(("✓ " if ok else "✕ ") + name + " — " + detail)

# ------------------------------ findings ------------------------------
elif page == "Findings":
    st.markdown('<div class="pagehead"><div><div class="overline">SOURCE INTELLIGENCE / 01</div>'
        '<h1>Findings register</h1><p>Evidence-backed results from the targeted static-analysis rules.</p></div>'
        '<span class="badge">STATIC ANALYSIS</span></div>', unsafe_allow_html=True)
    if findings:
        severity = st.selectbox("Severity filter", ["All", "High", "Medium", "Low"])
        shown = [x for x in findings if severity == "All" or str(x.get("severity", "")).lower() == severity.lower()]
        c1, c2, c3 = st.columns(3)
        with c1: metric("Total", len(findings), "Latest scan")
        with c2: metric("Visible", len(shown), "Current filter")
        with c3: metric("Ruleset", "2", "Supported patterns")
        for i, item in enumerate(shown, 1):
            finding_card(item, i)
    else:
        st.info("No scan results in this session. Go to Command deck and execute the pipeline.")

# ------------------------------ patch review ------------------------------
elif page == "Patch Review":
    st.markdown('<div class="pagehead"><div><div class="overline">REMEDIATION / 02</div>'
        '<h1>Patch review</h1><p>Review the generated code changes before presenting the remediation.</p></div>'
        '<span class="badge">BEFORE → AFTER</span></div>', unsafe_allow_html=True)
    if PATCHED.exists():
        st.success("Patched application copy is available.")
        if DIFF.exists():
            diff = DIFF.read_text(encoding="utf-8")
            st.markdown('<div class="box"><div class="boxtitle">Change summary</div>'
                '<div class="boxsub">SQL injection · f-string query replaced with parameterized SQL.<br>'
                'IDOR · order lookup constrained by the user identity and patched authentication checks.</div></div>',
                unsafe_allow_html=True)
            st.code(diff, language="diff", line_numbers=True)
            st.download_button("Download unified diff", diff, "security_patch.diff", "text/x-diff")
        else:
            st.warning("Diff file is missing. Re-run the pipeline.")
        with st.expander("Inspect complete patched source"):
            st.code(PATCHED.read_text(encoding="utf-8"), language="python", line_numbers=True)
        st.download_button("Download patched_app.py", PATCHED.read_bytes(), "patched_app.py", "text/x-python")
    else:
        st.info("No patched copy yet. Execute the pipeline from Command deck.")

# ------------------------------ test bench ------------------------------
elif page == "Test Bench":
    st.markdown('<div class="pagehead"><div><div class="overline">VERIFICATION / 03</div>'
        '<h1>Test bench</h1><p>Actual pytest transcript from the latest complete suite execution.</p></div>'
        '<span class="badge">REGRESSION VALIDATION</span></div>', unsafe_allow_html=True)
    if test_result is not None:
        if tests_pass: st.success("VALIDATION PASSED · pytest returned exit code 0.")
        else: st.error(f"VALIDATION FAILED · pytest returned exit code {test_result.returncode}.")
        x, y, z = st.columns(3)
        with x: metric("Exit code", test_result.returncode, "0 means success")
        with y: metric("Status", "PASS" if tests_pass else "FAIL", "Latest full run")
        with z: metric("Command", "pytest -v", "Project root")
        output = (test_result.stdout or "") + (("\n" + test_result.stderr) if test_result.stderr else "")
        st.markdown('<div class="overline" style="margin:18px 0 8px">EXECUTION TRANSCRIPT</div>', unsafe_allow_html=True)
        st.markdown('<div class="log">' + html.escape(output or "No output captured.") + '</div>', unsafe_allow_html=True)
        st.download_button("Download pytest transcript", output, "pytest_validation.log", "text/plain")
    else:
        st.info("No pytest execution captured yet. Execute the pipeline from Command deck.")
    st.markdown("#### Coverage checklist")
    for label, source in [
        ("SQL injection payload is neutralized by the patched app", "tests/test_patched_app.py"),
        ("Normal user search still works", "tests/test_patched_app.py"),
        ("Authenticated user can access their own order", "tests/test_patched_app.py"),
        ("Cross-user order access is blocked", "tests/test_patched_app.py"),
        ("Unauthenticated order access is blocked", "tests/test_patched_app.py"),
        ("Original fixture demonstrates both weaknesses", "tests/test_sql_injection.py / tests/test_idor.py"),
    ]:
        st.markdown(f'<div class="stage"><div class="stageicon">✓</div><div>'
            f'<div class="stagetitle">{html.escape(label)}</div><div class="stagedesc">{html.escape(source)}</div>'
            '</div></div>', unsafe_allow_html=True)

# ------------------------------ evidence ------------------------------
elif page == "Evidence":
    st.markdown('<div class="pagehead"><div><div class="overline">AUDIT TRAIL / 04</div>'
        '<h1>Evidence locker</h1><p>Download the concrete artefacts produced by the pipeline.</p></div>'
        '<span class="badge">EXPORTS & REPORTS</span></div>', unsafe_allow_html=True)
    report = read_report()
    if report:
        summary = report.get("summary", {})
        a, b, c = st.columns(3)
        with a: metric("Findings", summary.get("total_vulnerabilities", "—"), "JSON assessment")
        with b: metric("High", summary.get("high", "—"), "Severity count")
        with c: metric("Validation", report.get("validation", {}).get("status", "—"), "Recorded status")
        report_text = json.dumps(report, indent=4)
        st.download_button("Download security_report.json", report_text, "security_report.json", "application/json")
        with st.expander("Preview JSON assessment"):
            st.json(report)
    else:
        st.info("No report found. Run the pipeline to generate the JSON assessment.")
    st.markdown("#### Artefact registry")
    for title, path, description, mime in [
        ("Security assessment", REPORT, "Machine-readable findings, severity and validation summary.", "application/json"),
        ("Unified patch diff", DIFF, "Exact before/after source changes.", "text/x-diff"),
        ("Patched application", PATCHED, "Generated patched Flask application.", "text/x-python"),
    ]:
        ready = path.exists()
        with st.container():
            st.markdown(f'<div class="box"><div style="display:flex;justify-content:space-between">'
                f'<div class="boxtitle">{html.escape(title)}</div><span class="status {"ok" if ready else "wait"}">'
                f'{"AVAILABLE" if ready else "NOT GENERATED"}</span></div>'
                f'<div class="boxsub">{html.escape(description)}</div>'
                f'<div class="meta">{html.escape(str(path.relative_to(ROOT)))}</div></div>', unsafe_allow_html=True)
            if ready:
                st.download_button("Download " + path.name, path.read_bytes(), path.name, mime,
                    key="download_" + path.name)

# ------------------------------ architecture ------------------------------
elif page == "Architecture":
    st.markdown('<div class="pagehead"><div><div class="overline">SYSTEM MAP / 05</div>'
        '<h1>Architecture & scope</h1><p>What PATCHPROOF does, and exactly what it does not claim to do.</p></div>'
        '<span class="badge">PROJECT BRIEF</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="command"><div class="commandlabel">SYSTEM FLOW</div>'
        '<h2>Source → Scanner → Patch → Tests → Report</h2>'
        '<p>Streamlit interface invokes a Python AST-based targeted scanner, a patch generator, '
        'the pytest regression suite and a JSON report generator. The vulnerable Flask app uses synthetic SQLite data.</p></div>',
        unsafe_allow_html=True)
    a, b = st.columns(2)
    with a:
        st.markdown('<div class="box"><div class="boxtitle">Technology stack</div>'
            '<div class="boxsub">Python · Flask · SQLite · Python AST · Streamlit · pytest · difflib</div></div>',
            unsafe_allow_html=True)
        st.markdown('<div class="box"><div class="boxtitle">Supported detection</div>'
            '<div class="boxsub">SQL injection: targeted detection of f-string SQL passed to execute().<br><br>'
            'IDOR: targeted order-query ownership pattern in the included fixture.</div></div>', unsafe_allow_html=True)
    with b:
        st.markdown('<div class="box"><div class="boxtitle">Security boundaries</div>'
            '<div class="boxsub">Runs against a local, deliberately vulnerable demonstration app with synthetic records. '
            'No external target is scanned. No general-purpose vulnerability coverage is claimed.</div></div>',
            unsafe_allow_html=True)
        st.markdown('<div class="box"><div class="boxtitle">Important limitation</div>'
            '<div class="boxsub">Static rules are tailored to the supplied fixture. IDOR detection in arbitrary applications '
            'requires deeper data-flow and authorization-context analysis than this prototype implements.</div></div>',
            unsafe_allow_html=True)

st.markdown('<div class="footer"><span>PATCHPROOF / SECURITY OPERATIONS CONSOLE</span>'
    '<span>DETECT &nbsp;·&nbsp; PATCH &nbsp;·&nbsp; VALIDATE &nbsp;·&nbsp; REPORT</span></div>',
    unsafe_allow_html=True)
