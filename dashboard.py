import sys
import subprocess
import json
import html
from datetime import datetime
from pathlib import Path

import streamlit as st

# PATCHPROOF — case-file style security investigation workspace.
# Existing scanner, patcher, pytest suite and report generator remain unchanged.
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

st.set_page_config(page_title="PATCHPROOF — Security Investigation", page_icon="◩", layout="wide", initial_sidebar_state="collapsed")

st.markdown(r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{--ink:#101310;--paper:#e9e8df;--paper2:#f2f1e9;--panel:#191e19;--panel2:#222920;--line:#41483c;--muted:#a7ad9d;--acid:#d4ff45;--orange:#ff7657;--blue:#91b9c8;--green:#9ee0a2}
html,body,[class*="css"]{font-family:'Manrope',sans-serif}.stApp{background:var(--ink);color:var(--paper)}
[data-testid="stHeader"]{background:rgba(16,19,16,.96)}.block-container{max-width:1500px;padding:1.1rem 2.2rem 3rem}
h1,h2,h3,h4{color:var(--paper)!important;letter-spacing:-.045em}p,li,label{color:#c5c9bd}
[data-testid="stCaptionContainer"]{color:var(--muted)!important}hr{border-color:var(--line)!important}
code,pre{font-family:'DM Mono',monospace!important}
/* Masthead */
.mast{display:flex;justify-content:space-between;align-items:center;padding:5px 0 17px;border-bottom:1px solid var(--line);margin-bottom:24px}
.wordmark{font:800 30px 'Space Grotesk';letter-spacing:.13em;color:var(--acid);line-height:1.05;text-shadow:0 0 22px rgba(212,255,69,.16)}
.wordsub{font:9px 'DM Mono';letter-spacing:.18em;color:var(--muted);margin-top:4px}
.mast-right{font:10px 'DM Mono';letter-spacing:.12em;color:var(--muted);text-align:right}.live{color:var(--acid)}
/* Navigation is a slim case index, not a sidebar */
.case-nav{border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:26px}
.case-nav [data-testid="stRadio"]>div{gap:5px;flex-wrap:wrap}
.case-nav [data-testid="stRadio"] label{padding:7px 13px;border:1px solid transparent;border-radius:2px;color:#aeb5a7!important;font:10px 'DM Mono';letter-spacing:.1em}
.case-nav [data-testid="stRadio"] label:has(input:checked){background:var(--acid);border-color:var(--acid);color:var(--ink)!important}
.case-nav [data-testid="stRadio"] label:has(input:checked) p{color:var(--ink)!important}
.case-nav [data-testid="stRadio"] input{display:none}
/* Editorial canvas */
.kicker{font:10px 'DM Mono';letter-spacing:.2em;color:var(--acid);text-transform:uppercase}
.display{font:600 clamp(38px,5vw,68px)/.98 'Space Grotesk';letter-spacing:-.075em;color:var(--paper);margin:12px 0}
.display em{font-style:normal;color:var(--acid)}
.lede{font-size:14px;line-height:1.8;color:#b5bbae;max-width:590px}
.case-stamp{border:1px solid var(--line);padding:18px 20px;background:linear-gradient(145deg,#20271e,#151a15);height:100%}
.stamp-label{font:9px 'DM Mono';letter-spacing:.16em;color:var(--muted)}.stamp-value{font:22px 'Space Grotesk';color:var(--acid);margin:7px 0 12px}
.stamp-row{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:9px 0;font-size:11px;color:#c2c9b9}
.stamp-row b{font:10px 'DM Mono';color:var(--paper);font-weight:500}
/* Big horizontal readouts, not card tiles */
.readout-band{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:28px 0 27px}
.readout{padding:16px 18px 17px 0;border-right:1px solid var(--line);margin-right:18px}.readout:last-child{border:0;margin:0}
.readout-label{font:9px 'DM Mono';letter-spacing:.16em;color:var(--muted)}.readout-value{font:38px 'Space Grotesk';letter-spacing:-.06em;color:var(--paper);margin:5px 0 0}.readout-note{font-size:10px;color:#929b8b}
/* Findings as dossier rows */
.sectionline{display:flex;justify-content:space-between;align-items:baseline;border-bottom:1px solid var(--line);padding-bottom:9px;margin:20px 0 10px}
.sectionline h2{font:600 18px 'Space Grotesk';margin:0}.sectionline span{font:9px 'DM Mono';letter-spacing:.14em;color:var(--muted)}
.dossier{display:grid;grid-template-columns:52px 1fr 115px;gap:14px;padding:18px 5px;border-bottom:1px solid #343b32;align-items:start}
.dossier-num{font:18px 'Space Grotesk';color:#707a69}.dossier-title{font:600 16px 'Space Grotesk';color:var(--paper)}
.dossier-meta{font:9px 'DM Mono';letter-spacing:.12em;color:var(--muted);margin:5px 0 8px}.dossier-copy{font-size:11px;line-height:1.65;color:#b3bbae}
.severity{font:9px 'DM Mono';letter-spacing:.12em;padding:6px 8px;text-align:center;border:1px solid #7b453b;color:#ff947d;background:#2b1d18}
.severity.medium{border-color:#80652d;color:#f0c46a;background:#2b2618}.severity.low{border-color:#526d4a;color:#b7d98a;background:#20291d}
/* Panels and timelines */
.dark-panel{background:var(--panel);border:1px solid var(--line);padding:18px 19px;margin-bottom:13px}
.panel-kicker{font:9px 'DM Mono';letter-spacing:.16em;color:var(--acid)}.panel-title{font:600 17px 'Space Grotesk';margin:8px 0;color:var(--paper)}
.panel-copy{font-size:11px;line-height:1.7;color:#aeb7a7}
.timeline{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line);margin-top:22px;padding-top:15px;gap:12px}
.timeitem{border-left:2px solid #59614c;padding-left:11px}.timeitem.done{border-color:var(--acid)}
.time-num{font:9px 'DM Mono';color:var(--acid)}.time-title{font:600 11px 'Space Grotesk';margin-top:5px}.time-desc{font-size:10px;color:var(--muted);margin-top:3px}
.log{background:#0a0d0a;border:1px solid #3b4437;padding:15px;color:#cbd4c2;font:10px 'DM Mono';white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto}
/* Controls */
.stButton>button{background:var(--acid)!important;color:var(--ink)!important;border:1px solid var(--acid)!important;border-radius:2px!important;font:700 11px 'DM Mono'!important;letter-spacing:.08em!important;min-height:44px}
.stButton>button:hover{background:#e2ff7b!important;border-color:#e2ff7b!important}
.stDownloadButton>button{background:transparent!important;color:var(--paper)!important;border:1px solid #68715d!important;border-radius:2px!important;font:10px 'DM Mono'!important}
.stDownloadButton>button:hover{border-color:var(--acid)!important;color:var(--acid)!important}
.stSelectbox div[data-baseweb="select"],.stTextInput input{background:#1a2019!important;color:var(--paper)!important}
div[data-testid="stExpander"]{background:#191e19;border:1px solid var(--line);border-radius:2px}
div[data-testid="stAlert"]{border-radius:2px}.stTabs [data-baseweb="tab"]{color:#b4bcae}.stTabs [aria-selected="true"]{color:var(--acid)!important}
.footer{border-top:1px solid var(--line);margin-top:34px;padding-top:12px;display:flex;justify-content:space-between;font:9px 'DM Mono';letter-spacing:.12em;color:#788171}
@media(max-width:900px){.readout-band{grid-template-columns:repeat(2,1fr)}.dossier{grid-template-columns:35px 1fr}.dossier>div:last-child{grid-column:2}}
</style>
""", unsafe_allow_html=True)

# ------------------------------- operations ----------------------------------
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
        with st.spinner("01 / Analysing source with targeted AST rules…"):
            findings = scan_application(TARGET)
        stages.append(("SOURCE ANALYSIS", True, f"{len(findings)} supported finding(s)"))

        with st.spinner("02 / Generating patched copy and unified diff…"):
            generate_patches()
        patch_ok = PATCHED.exists() and DIFF.exists()
        stages.append(("PATCH GENERATION", patch_ok, "Patched copy and diff checked"))
        if not patch_ok:
            raise RuntimeError("Patch engine did not create both expected artefacts.")

        with st.spinner("03 / Running the complete pytest suite…"):
            result = subprocess.run([sys.executable, "-m", "pytest", "-v"], cwd=ROOT,
                                    capture_output=True, text=True, timeout=180)
        tests_ok = result.returncode == 0
        stages.append(("REGRESSION VALIDATION", tests_ok, f"pytest exit code {result.returncode}"))

        if tests_ok:
            with st.spinner("04 / Refreshing the security assessment…"):
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


def readout(label, value, note):
    return (f'<div class="readout"><div class="readout-label">{html.escape(str(label))}</div>'
            f'<div class="readout-value">{html.escape(str(value))}</div>'
            f'<div class="readout-note">{html.escape(str(note))}</div></div>')


def finding_row(item, idx):
    title = str(item.get("type", "Finding"))
    severity = str(item.get("severity", "Unknown"))
    evidence = str(item.get("evidence", "No evidence supplied."))
    file_path = str(item.get("file", "Unknown"))
    line = str(item.get("line", "—"))
    if "SQL Injection" in title:
        cwe = "CWE-89"
        impact = "Untrusted input may alter query logic and expose or modify records."
        fix = "Replace SQL string interpolation with parameterized query execution."
    else:
        cwe = "CWE-639"
        impact = "A requester may access an object belonging to another account."
        fix = "Bind the resource lookup to authenticated server-side identity and enforce ownership."
    sev_class = severity.lower() if severity.lower() in {"medium", "low"} else "high"
    st.markdown(
        f'<div class="dossier"><div class="dossier-num">{idx:02d}</div><div>'
        f'<div class="dossier-title">{html.escape(title)}</div>'
        f'<div class="dossier-meta">{cwe} &nbsp; / &nbsp; {html.escape(file_path)} &nbsp; / &nbsp; LINE {html.escape(line)}</div>'
        f'<div class="dossier-copy"><b>Evidence</b> — {html.escape(evidence)}<br>'
        f'<b>Impact</b> — {html.escape(impact)}<br><b>Remediation</b> — {html.escape(fix)}</div>'
        f'</div><div class="severity {sev_class}">{html.escape(severity.upper())}</div></div>',
        unsafe_allow_html=True,
    )

# ------------------------------ session state --------------------------------
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

# -------------------------------- masthead ------------------------------------
st.markdown(
    '<div class="mast"><div><div class="wordmark">PATCHPROOF</div>'
    '<div class="wordsub">APPLICATION SECURITY / INVESTIGATION FILE</div></div>'
    '<div class="mast-right"><span class="live">● SYSTEM READY</span><br>LOCAL FIXTURE &nbsp;·&nbsp; SYNTHETIC DATA</div></div>',
    unsafe_allow_html=True,
)

pages = ["Case File", "Findings", "Patch Review", "Verification", "Evidence", "Scope"]
labels = ["00 / CASE FILE", "01 / FINDINGS", "02 / PATCH REVIEW", "03 / VERIFICATION", "04 / EVIDENCE", "05 / SCOPE"]
st.markdown('<div class="case-nav">', unsafe_allow_html=True)
page = st.radio("Investigation index", pages, horizontal=True,
                format_func=lambda x: labels[pages.index(x)],
                label_visibility="collapsed", key="case_navigation")
st.markdown('</div>', unsafe_allow_html=True)

if st.session_state.error:
    st.error("Pipeline stopped: " + st.session_state.error)

# -------------------------------- case file -----------------------------------
if page == "Case File":
    hero_left, hero_right = st.columns([1.55, 1], gap="large")
    with hero_left:
        st.markdown('<div class="kicker">SECURITY INVESTIGATION &nbsp; / &nbsp; FILE PP-001</div>'
                    '<div class="display">Find the flaw.<br><em>Prove the fix.</em></div>'
                    '<div class="lede">A controlled assessment of a deliberately vulnerable Flask application. '
                    'PATCHPROOF traces selected weaknesses from source evidence to generated remediation, '
                    'then checks the patched copy against the regression suite.</div>', unsafe_allow_html=True)
        st.markdown('<div style="margin-top:18px;font:9px DM Mono;letter-spacing:.13em;color:#9ca594">'
                    'TARGET &nbsp; vulnerable_app/app.py &nbsp;&nbsp; / &nbsp;&nbsp; SCOPE &nbsp; SQL INJECTION + IDOR</div>',
                    unsafe_allow_html=True)
        if st.button("RUN THE INVESTIGATION  ↗", use_container_width=True, key="run_case"):
            run_pipeline()
        st.caption("Executes the actual scanner → patch generator → pytest → report pipeline.")
    with hero_right:
        st.markdown('<div class="case-stamp"><div class="stamp-label">CASE STATUS</div>'
                    f'<div class="stamp-value">{"ASSESSED" if st.session_state.complete else "AWAITING RUN"}</div>'
                    f'<div class="stamp-row"><span>Last execution</span><b>{html.escape(st.session_state.last_run or "—")}</b></div>'
                    f'<div class="stamp-row"><span>Findings returned</span><b>{len(findings) if st.session_state.complete else "—"}</b></div>'
                    f'<div class="stamp-row"><span>Patch artefacts</span><b>{"READY" if patch_ready else "PENDING"}</b></div>'
                    f'<div class="stamp-row"><span>Regression suite</span><b>{"PASS" if tests_pass else ("FAIL" if test_result else "PENDING")}</b></div>'
                    '<div style="margin-top:16px;font:9px DM Mono;letter-spacing:.13em;color:#9ca594">'
                    'CONTROLLED LOCAL FIXTURE<br>NO EXTERNAL TARGETS</div></div>', unsafe_allow_html=True)

    high = sum(1 for x in findings if str(x.get("severity", "")).lower() == "high")
    low = sum(1 for x in findings if str(x.get("severity", "")).lower() == "low")
    st.markdown('<div class="readout-band">' +
        readout("TOTAL FINDINGS", len(findings) if st.session_state.complete else "—", "Latest source analysis") +
        readout("HIGH SEVERITY", high if st.session_state.complete else "—", "Triage priority") +
        readout("PATCH OUTPUT", "READY" if patch_ready else "—", "Patched copy + unified diff") +
        readout("TEST RESULT", "PASS" if tests_pass else ("FAIL" if test_result else "—"), "Complete pytest run") +
        '</div>', unsafe_allow_html=True)

    left, right = st.columns([1.5, 1], gap="large")
    with left:
        st.markdown('<div class="sectionline"><h2>Evidence register</h2><span>LIVE FINDINGS / 01</span></div>', unsafe_allow_html=True)
        if findings:
            for i, item in enumerate(findings[:3], 1):
                finding_row(item, i)
            if len(findings) > 3:
                st.caption(f"{len(findings) - 3} additional finding(s) are listed in the Findings register.")
        elif st.session_state.complete:
            st.success("The scanner returned no supported findings for this run.")
        else:
            st.markdown('<div class="panel-copy">No findings have been loaded into this session. '
                        'Run the investigation to populate the evidence register from the AST scanner.</div>',
                        unsafe_allow_html=True)
    with right:
        st.markdown('<div class="dark-panel"><div class="panel-kicker">PIPELINE / 4 STAGES</div>'
                    '<div class="panel-title">From source to proof.</div>'
                    '<div class="panel-copy">Every stage is backed by a real project component. '
                    'A failed test prevents the report from being refreshed.</div>', unsafe_allow_html=True)
        stage_defs = [("01", "Source analysis", "Targeted AST scan", bool(st.session_state.complete and st.session_state.findings is not None)),
                      ("02", "Patch generation", "Patched copy + diff", patch_ready),
                      ("03", "Regression tests", "Full pytest suite", tests_pass),
                      ("04", "Evidence report", "JSON assessment", REPORT.exists())]
        for num, title, desc, ok in stage_defs:
            st.markdown(f'<div class="stage"><div class="stageicon">{num}</div><div><div class="stagetitle">{title}</div>'
                        f'<div class="stagedesc">{desc}</div></div><span class="status {"ok" if ok else "wait"}">'
                        f'{"COMPLETE" if ok else "PENDING"}</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="sectionline"><h2>Investigation sequence</h2><span>DETECT → PATCH → VERIFY → RECORD</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="timeline">'
        '<div class="timeitem done"><div class="time-num">01 / DETECT</div><div class="time-title">Inspect source</div><div class="time-desc">AST-based pattern checks</div></div>'
        '<div class="timeitem done"><div class="time-num">02 / PATCH</div><div class="time-title">Generate changes</div><div class="time-desc">Separate patched copy + diff</div></div>'
        '<div class="timeitem done"><div class="time-num">03 / VERIFY</div><div class="time-title">Run regression suite</div><div class="time-desc">Security and functionality tests</div></div>'
        '<div class="timeitem"><div class="time-num">04 / RECORD</div><div class="time-title">Export evidence</div><div class="time-desc">Machine-readable JSON report</div></div></div>', unsafe_allow_html=True)

    if st.session_state.stages:
        with st.expander("Execution record — inspect stage outcomes"):
            for name, ok, detail in st.session_state.stages:
                st.write(("✓ " if ok else "✕ ") + name + " — " + detail)

# -------------------------------- findings ------------------------------------
elif page == "Findings":
    st.markdown('<div class="kicker">01 / SOURCE INTELLIGENCE</div><div class="display">The <em>findings</em><br>register.</div>'
                '<div class="lede">Evidence-backed results returned by the targeted static-analysis rules. '
                'Each record includes source location, impact and a recommended remediation.</div>', unsafe_allow_html=True)
    if findings:
        selected = st.selectbox("FILTER BY SEVERITY", ["All", "High", "Medium", "Low"], label_visibility="collapsed")
        shown = [x for x in findings if selected == "All" or str(x.get("severity", "")).lower() == selected.lower()]
        st.markdown(f'<div class="sectionline"><h2>{len(shown)} records</h2><span>FILTER: {selected.upper()}</span></div>', unsafe_allow_html=True)
        for i, item in enumerate(shown, 1):
            finding_row(item, i)
    else:
        st.info("No findings in this session. Run the investigation from the Case File page first.")

# -------------------------------- patch review -------------------------------
elif page == "Patch Review":
    st.markdown('<div class="kicker">02 / REMEDIATION REVIEW</div><div class="display">Changes, not<br><em>claims.</em></div>'
                '<div class="lede">Review the exact unified diff generated by the patch engine. Source code stays tucked away until deliberately opened.</div>',
                unsafe_allow_html=True)
    if PATCHED.exists() and DIFF.exists():
        st.markdown('<div class="dark-panel"><div class="panel-kicker">PATCH ENGINE OUTPUT</div>'
                    '<div class="panel-title">A separate patched application has been generated.</div>'
                    '<div class="panel-copy">The original vulnerable fixture is retained. The patch is written to '
                    '<b>vulnerable_app/patched_app.py</b>; the exact changes are recorded in the unified diff.</div></div>',
                    unsafe_allow_html=True)
        diff = DIFF.read_text(encoding="utf-8")
        st.download_button("DOWNLOAD UNIFIED PATCH DIFF", diff, "security_patch.diff", "text/x-diff")
        with st.expander("Inspect exact source diff"):
            st.code(diff, language="diff", line_numbers=True)
        with st.expander("Inspect complete patched application source"):
            st.code(PATCHED.read_text(encoding="utf-8"), language="python", line_numbers=True)
        st.download_button("DOWNLOAD PATCHED APP", PATCHED.read_bytes(), "patched_app.py", "text/x-python")
    else:
        st.info("Patch artefacts are not available yet. Run the investigation to generate the patched copy and diff.")

# -------------------------------- verification -------------------------------
elif page == "Verification":
    st.markdown('<div class="kicker">03 / REGRESSION VALIDATION</div><div class="display">Prove it<br><em>holds.</em></div>'
                '<div class="lede">The validation view reports the actual pytest process result and captured transcript — not simulated pass indicators.</div>',
                unsafe_allow_html=True)
    if test_result is not None:
        if tests_pass:
            st.success("VALIDATION PASSED — pytest returned exit code 0.")
        else:
            st.error(f"VALIDATION FAILED — pytest returned exit code {test_result.returncode}.")
        a, b, c = st.columns(3)
        a.metric("Exit code", test_result.returncode)
        b.metric("Result", "PASS" if tests_pass else "FAIL")
        c.metric("Command", "pytest -v")
        output = (test_result.stdout or "") + (("\n" + test_result.stderr) if test_result.stderr else "")
        st.markdown('<div class="sectionline"><h2>Execution transcript</h2><span>RAW PROCESS OUTPUT</span></div>', unsafe_allow_html=True)
        st.markdown('<div class="log">' + html.escape(output or "No output captured.") + '</div>', unsafe_allow_html=True)
        st.download_button("DOWNLOAD TEST TRANSCRIPT", output, "pytest_validation.log", "text/plain")
    else:
        st.info("No pytest execution captured yet. Run the investigation first.")
    st.markdown('<div class="sectionline"><h2>Demonstration test coverage</h2><span>PROJECT TEST INTENT</span></div>', unsafe_allow_html=True)
    for label, source in [
        ("SQL injection payload is neutralized by the patched app", "tests/test_patched_app.py"),
        ("Normal user search still works", "tests/test_patched_app.py"),
        ("Authenticated user can access their own order", "tests/test_patched_app.py"),
        ("Cross-user order access is blocked", "tests/test_patched_app.py"),
        ("Unauthenticated order access is blocked", "tests/test_patched_app.py"),
        ("Original fixture demonstrates both weaknesses", "tests/test_sql_injection.py / tests/test_idor.py"),
    ]:
        st.markdown(f'<div class="stage"><div class="stageicon">↳</div><div><div class="stagetitle">{html.escape(label)}</div>'
                    f'<div class="stagedesc">{html.escape(source)}</div></div></div>', unsafe_allow_html=True)

# -------------------------------- evidence ------------------------------------
elif page == "Evidence":
    st.markdown('<div class="kicker">04 / AUDIT TRAIL</div><div class="display">The evidence<br><em>locker.</em></div>'
                '<div class="lede">Download the concrete files produced by the pipeline. Every artefact is read from disk and its availability is checked live.</div>',
                unsafe_allow_html=True)
    report = read_report()
    if report:
        summary = report.get("summary", {})
        validation = report.get("validation", {})
        a, b, c = st.columns(3)
        a.metric("Findings", summary.get("total_vulnerabilities", "—"))
        b.metric("High severity", summary.get("high", "—"))
        c.metric("Validation", validation.get("status", "—"))
        report_text = json.dumps(report, indent=4)
        st.download_button("DOWNLOAD SECURITY REPORT JSON", report_text, "security_report.json", "application/json")
        with st.expander("Preview machine-readable assessment"):
            st.json(report)
    else:
        st.info("No report is available yet. The report is generated after the regression suite passes.")

    st.markdown('<div class="sectionline"><h2>Artefact index</h2><span>FILESYSTEM CHECK</span></div>', unsafe_allow_html=True)
    for title, path, description, mime in [
        ("Security assessment", REPORT, "Machine-readable findings, severity and validation summary.", "application/json"),
        ("Unified patch diff", DIFF, "Exact source changes produced by the patch engine.", "text/x-diff"),
        ("Patched application", PATCHED, "Generated patched Flask application copy.", "text/x-python"),
    ]:
        available = path.exists() and path.is_file()
        st.markdown(f'<div class="stage"><div class="stageicon">{ "✓" if available else "—" }</div><div>'
                    f'<div class="stagetitle">{html.escape(title)}</div><div class="stagedesc">{html.escape(description)}<br>'
                    f'{html.escape(str(path.relative_to(ROOT)))}</div></div><span class="status {"ok" if available else "wait"}">'
                    f'{"AVAILABLE" if available else "NOT GENERATED"}</span></div>', unsafe_allow_html=True)
        if available:
            st.download_button("DOWNLOAD " + path.name.upper(), path.read_bytes(), path.name, mime, key="evidence_" + path.name)

# -------------------------------- scope ---------------------------------------
elif page == "Scope":
    st.markdown('<div class="kicker">05 / SYSTEM BOUNDARIES</div><div class="display">Know what it<br><em>covers.</em></div>'
                '<div class="lede">A credible security tool states its boundaries clearly. PATCHPROOF demonstrates a focused workflow against a controlled fixture.</div>',
                unsafe_allow_html=True)
    left, right = st.columns(2, gap="large")
    with left:
        st.markdown('<div class="dark-panel"><div class="panel-kicker">DETECTION SCOPE</div><div class="panel-title">Two targeted vulnerability patterns</div>'
                    '<div class="panel-copy"><b>SQL Injection · CWE-89</b><br>Detects the supported f-string SQL construction pattern passed to execute().<br><br>'
                    '<b>Broken Access Control / IDOR · CWE-639</b><br>Checks the demonstration order lookup for a missing ownership constraint.</div></div>',
                    unsafe_allow_html=True)
        st.markdown('<div class="dark-panel"><div class="panel-kicker">TECHNOLOGY</div><div class="panel-title">The implementation stack</div>'
                    '<div class="panel-copy">Python · Flask · SQLite · Python AST · Streamlit · pytest · difflib</div></div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="dark-panel"><div class="panel-kicker">EXECUTION MODEL</div><div class="panel-title">Local and controlled</div>'
                    '<div class="panel-copy">The vulnerable Flask application is a local fixture populated with synthetic SQLite records. '
                    'The original file is retained; the patch engine creates a separate patched copy. No external target is scanned.</div></div>',
                    unsafe_allow_html=True)
        st.warning("Scope limitation: the scanner uses targeted static rules for the included fixture. It is not a general-purpose SAST engine, does not detect every vulnerability, and does not replace a professional security audit. The patched fixture is for local demonstration, not production deployment.")

st.markdown('<div class="footer"><span>PATCH/PROOF &nbsp;·&nbsp; APPLICATION SECURITY PROTOTYPE</span>'
            '<span>DETECT &nbsp; / &nbsp; PATCH &nbsp; / &nbsp; VERIFY &nbsp; / &nbsp; RECORD</span></div>',
            unsafe_allow_html=True)
