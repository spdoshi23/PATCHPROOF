import sys
import subprocess
import json
import html
from datetime import datetime
from pathlib import Path

import streamlit as st

# PATCHPROOF — Security Incident Response Workbench

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
    page_title="PATCHPROOF — Security Workbench",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# VISUAL SYSTEM
# ============================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700;800&display=swap');

:root {
    --paper: #f1efe8;
    --surface: #fbfaf6;
    --ink: #17242b;
    --muted: #68767a;
    --rule: #d8d7cf;
    --blue: #2457d6;
    --blue-soft: #e7edff;
    --red: #c84c3a;
    --red-soft: #f8e9e5;
    --green: #28734f;
    --green-soft: #e5f1e9;
    --yellow-soft: #f8efd9;
}

html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}

.stApp {
    background: var(--paper);
    color: var(--ink);
}

[data-testid="stHeader"] {
    background: rgba(241,239,232,.92);
}

[data-testid="stSidebar"] {
    background: #18262d;
    border-right: 1px solid #34454b;
}

[data-testid="stSidebar"] * {
    color: #e9eee9;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label {
    padding: 10px 12px;
    border-radius: 5px;
    margin: 3px 0;
    color: #c5d0ce !important;
    font-size: 13px;
    font-weight: 600;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
    background: #2b414a;
    color: white !important;
    border-left: 3px solid #8fb4ff;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label p {
    color: inherit !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] input {
    display: none;
}

[data-testid="stSidebar"] hr {
    border-color: #3b4a50;
}

[data-testid="stSidebar"] [data-testid="stCaption"] {
    color: #aab9b7 !important;
}

.block-container {
    max-width: 1500px;
    padding: 1.8rem 2.7rem 3.5rem;
}

h1, h2, h3, h4 {
    color: var(--ink) !important;
    letter-spacing: -.045em;
}

p, li {
    color: #45545a;
}

small, [data-testid="stCaption"] {
    color: var(--muted) !important;
}

hr {
    border-color: var(--rule) !important;
}

code, pre {
    font-family: 'DM Mono', monospace !important;
}

.masthead {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 0 17px;
    border-bottom: 2px solid var(--ink);
    margin-bottom: 26px;
}

.wordmark {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: .13em;
    color: var(--ink);
}

.wordmark span {
    color: var(--blue);
}

.mast-sub {
    font: 10px 'DM Mono';
    letter-spacing: .12em;
    color: var(--muted);
    margin-top: 4px;
}

.top-state {
    font: 10px 'DM Mono';
    letter-spacing: .12em;
    text-align: right;
    color: var(--green);
}

.eyebrow {
    font: 10px 'DM Mono';
    letter-spacing: .16em;
    text-transform: uppercase;
    color: var(--muted);
}

.title-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--rule);
    margin-bottom: 24px;
}

.page-title {
    font-size: 35px;
    font-weight: 800;
    line-height: 1.05;
    margin: 7px 0 8px;
}

.page-intro {
    font-size: 13px;
    color: var(--muted);
    max-width: 720px;
    line-height: 1.65;
}

.stamp {
    font: 10px 'DM Mono';
    letter-spacing: .08em;
    padding: 8px 10px;
    border: 1px solid #aeb6b3;
    color: #46565b;
    background: #f8f7f1;
    white-space: nowrap;
}

.panel {
    background: var(--surface);
    border: 1px solid var(--rule);
    padding: 19px 20px;
    margin-bottom: 14px;
}

.panel-dark {
    background: #1b2b33;
    color: #f4f4ec;
    padding: 22px 23px;
    margin-bottom: 14px;
}

.panel-dark h2,
.panel-dark h3,
.panel-dark p {
    color: #f4f4ec !important;
}

.panel-kicker {
    font: 10px 'DM Mono';
    letter-spacing: .14em;
    text-transform: uppercase;
    color: #78868a;
}

.panel-dark .panel-kicker {
    color: #9db6ba;
}

.big-number {
    font-size: 36px;
    font-weight: 800;
    letter-spacing: -.06em;
    margin-top: 8px;
    color: var(--ink);
}

.stat-label {
    font: 10px 'DM Mono';
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--muted);
}

.stat-note {
    font-size: 11px;
    color: var(--muted);
    margin-top: 2px;
}

.stat-block {
    background: var(--surface);
    border-top: 3px solid var(--blue);
    padding: 14px 16px;
    min-height: 105px;
    border-right: 1px solid var(--rule);
    border-bottom: 1px solid var(--rule);
    border-left: 1px solid var(--rule);
}

.rule-row {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 13px 0;
    border-bottom: 1px solid var(--rule);
}

.rule-row:last-child {
    border-bottom: 0;
}

.rule-number {
    font: 11px 'DM Mono';
    color: var(--blue);
    padding-top: 2px;
}

.rule-name {
    font-weight: 700;
    font-size: 13px;
    color: var(--ink);
}

.rule-desc {
    font-size: 11px;
    color: var(--muted);
    margin-top: 3px;
    line-height: 1.5;
}

.tag {
    display: inline-block;
    font: 9px 'DM Mono';
    letter-spacing: .08em;
    padding: 5px 7px;
    border: 1px solid #d8aaa2;
    background: var(--red-soft);
    color: #963b2e;
}

.finding-card {
    background: var(--surface);
    border: 1px solid var(--rule);
    border-left: 4px solid var(--red);
    padding: 17px 19px;
    margin: 12px 0;
}

.finding-card h3 {
    font-size: 16px;
    margin: 0;
}

.finding-meta {
    font: 10px 'DM Mono';
    letter-spacing: .07em;
    color: var(--muted);
    margin: 8px 0 12px;
}

.finding-card p {
    font-size: 12px;
    line-height: 1.6;
    margin: 5px 0;
}

.stage-line {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--rule);
}

.stage-line:last-child {
    border-bottom: 0;
}

.stage-no {
    font: 11px 'DM Mono';
    color: var(--blue);
    width: 24px;
}

.stage-copy {
    flex: 1;
}

.stage-copy b {
    font-size: 12px;
    color: var(--ink);
}

.stage-copy small {
    display: block;
    font-size: 10px;
    color: var(--muted);
    margin-top: 3px;
}

.stage-state {
    font: 9px 'DM Mono';
    letter-spacing: .08em;
    padding: 5px 7px;
    border: 1px solid var(--rule);
    color: var(--muted);
}

.stage-state.ok {
    color: var(--green);
    background: var(--green-soft);
    border-color: #b5d1bd;
}

.logbox {
    background: #18262d;
    color: #e1e9e5;
    padding: 16px;
    border: 1px solid #34454b;
    font: 11px 'DM Mono';
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-height: 560px;
    overflow: auto;
}

.note {
    background: var(--yellow-soft);
    border-left: 3px solid #c18a2d;
    padding: 12px 14px;
    font-size: 11px;
    color: #6d531f;
    line-height: 1.6;
    margin: 12px 0;
}

.stButton > button {
    background: var(--blue) !important;
    color: white !important;
    border: 1px solid var(--blue) !important;
    border-radius: 3px !important;
    font-weight: 700 !important;
    min-height: 44px;
}

.stButton > button:hover {
    background: #1745b7 !important;
    border-color: #1745b7 !important;
}

.stDownloadButton > button {
    background: #e8ecf8 !important;
    color: #203d91 !important;
    border: 1px solid #bdc9e8 !important;
    border-radius: 3px !important;
    font-weight: 700 !important;
}

.stTextInput input,
.stSelectbox div[data-baseweb="select"] {
    background: var(--surface) !important;
}

div[data-testid="stExpander"] {
    background: var(--surface);
    border: 1px solid var(--rule);
    border-radius: 2px;
}

div[data-testid="stAlert"] {
    border-radius: 2px;
}

.footer {
    border-top: 2px solid var(--ink);
    margin-top: 38px;
    padding-top: 12px;
    display: flex;
    justify-content: space-between;
    color: #68767a;
    font: 9px 'DM Mono';
    letter-spacing: .1em;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# BACKEND OPERATIONS
# ============================================================

def read_report():
    if not REPORT.exists():
        return None

    try:
        return json.loads(REPORT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def run_pipeline():
    stages = []
    findings = []
    result = None

    try:
        with st.spinner("01 / Inspecting the demonstration source..."):
            findings = scan_application(TARGET)

        stages.append((
            "SOURCE ANALYSIS",
            True,
            f"{len(findings)} supported finding(s)"
        ))

        with st.spinner("02 / Building remediation artefacts..."):
            generate_patches()

        patch_ok = PATCHED.exists() and DIFF.exists()

        stages.append((
            "PATCH GENERATION",
            patch_ok,
            "Patched copy and unified diff checked"
        ))

        if not patch_ok:
            raise RuntimeError(
                "Patch engine did not create both expected artefacts."
            )

        with st.spinner("03 / Running the complete pytest suite..."):
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-v"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=180
            )

        tests_ok = result.returncode == 0

        stages.append((
            "REGRESSION VALIDATION",
            tests_ok,
            f"pytest exit code {result.returncode}"
        ))

        if tests_ok:
            with st.spinner("04 / Refreshing the security report..."):
                generate_report()

            stages.append((
                "REPORT GENERATION",
                REPORT.exists(),
                "JSON assessment refreshed"
            ))
        else:
            stages.append((
                "REPORT GENERATION",
                False,
                "Skipped because tests failed"
            ))

        st.session_state.findings = findings
        st.session_state.test_result = result
        st.session_state.stages = stages
        st.session_state.complete = True
        st.session_state.last_run = datetime.now().strftime(
            "%d %b %Y · %H:%M:%S"
        )
        st.session_state.error = None

    except Exception as exc:
        st.session_state.stages = stages
        st.session_state.error = f"{type(exc).__name__}: {exc}"
        st.session_state.complete = True

    st.rerun()


# ============================================================
# REUSABLE UI COMPONENTS
# ============================================================

def stat(label, value, note):
    st.markdown(
        f'<div class="stat-block">'
        f'<div class="stat-label">{html.escape(str(label))}</div>'
        f'<div class="big-number">{html.escape(str(value))}</div>'
        f'<div class="stat-note">{html.escape(str(note))}</div>'
        f'</div>',
        unsafe_allow_html=True
    )


def finding_card(item, number):
    title = str(item.get("type", "Finding"))
    severity = str(item.get("severity", "Unknown"))
    evidence = str(item.get("evidence", "No evidence supplied"))
    file_path = str(item.get("file", "Unknown"))
    line = str(item.get("line", "—"))

    if "SQL Injection" in title:
        cwe = "CWE-89"
        impact = (
            "Untrusted input may alter query logic and expose "
            "or modify records."
        )
        fix = (
            "Use parameterized SQL instead of interpolating "
            "input into the query string."
        )
    else:
        cwe = "CWE-639"
        impact = (
            "A requester may access an object belonging "
            "to another account."
        )
        fix = (
            "Bind the resource lookup to authenticated "
            "server-side identity and enforce ownership."
        )

    st.markdown(
        f'<div class="finding-card">'
        f'<div style="display:flex;justify-content:space-between;gap:12px">'
        f'<h3>{number:02d} / {html.escape(title)}</h3>'
        f'<span class="tag">{html.escape(severity.upper())}</span>'
        f'</div>'
        f'<div class="finding-meta">{cwe} &nbsp;·&nbsp; SOURCE LINE '
        f'{html.escape(line)}</div>'
        f'<p><b>Observed evidence:</b> {html.escape(evidence)}</p>'
        f'<p><b>Potential impact:</b> {html.escape(impact)}</p>'
        f'<p><b>Remediation direction:</b> {html.escape(fix)}</p>'
        f'<p style="color:#78868a"><b>File:</b> '
        f'{html.escape(file_path)}</p>'
        f'</div>',
        unsafe_allow_html=True
    )


# ============================================================
# SESSION STATE
# ============================================================

defaults = {
    "findings": [],
    "test_result": None,
    "stages": [],
    "complete": False,
    "last_run": None,
    "error": None,
}

for key, default in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = default


findings = st.session_state.findings
test_result = st.session_state.test_result

tests_pass = (
    test_result is not None
    and test_result.returncode == 0
)

patch_ready = PATCHED.exists() and DIFF.exists()

report = read_report()


# ============================================================
# NAVIGATION
# ============================================================

with st.sidebar:

    st.markdown(
        '<div style="padding:12px 2px 20px">'
        '<div style="font:10px DM Mono;letter-spacing:.2em;color:#9db6ba">'
        'SECURITY TOOL / 001</div>'
        '<div style="font-size:25px;font-weight:800;letter-spacing:.08em;margin-top:7px">'
        'PATCH<span style="color:#8fb4ff">PROOF</span></div>'
        '<div style="font:10px DM Mono;color:#aab9b7;margin-top:5px">'
        'APPLICATION SECURITY WORKBENCH</div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("---")

    page = st.radio(
        "WORKSPACE",
        [
            "Overview",
            "Threat register",
            "Patch workshop",
            "Verification",
            "Evidence",
            "System notes"
        ],
        label_visibility="visible",
        key="workspace_navigation"
    )

    st.markdown("---")

    st.markdown(
        '<div style="font:10px DM Mono;letter-spacing:.12em;color:#9db6ba">'
        'TARGET PROFILE</div>',
        unsafe_allow_html=True
    )

    st.caption("vulnerable_app / app.py")
    st.caption("Synthetic SQLite records")
    st.caption("Local fixture only")

    st.markdown("---")

    st.markdown(
        '<div style="font:10px DM Mono;color:#9db6ba;line-height:1.8">'
        'PATCHPROOF IS A TARGETED DEMONSTRATION.<br>'
        'NOT A GENERAL-PURPOSE SCANNER.'
        '</div>',
        unsafe_allow_html=True
    )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="masthead">'
    '<div>'
    '<div class="wordmark">PATCH<span>PROOF</span></div>'
    '<div class="mast-sub">'
    'APPLICATION SECURITY / INCIDENT RESPONSE WORKSPACE'
    '</div>'
    '</div>'
    '<div class="top-state">'
    '● WORKSPACE AVAILABLE<br>'
    '<span style="color:#68767a">'
    'LOCAL FIXTURE · SYNTHETIC DATA'
    '</span>'
    '</div>'
    '</div>',
    unsafe_allow_html=True
)

if st.session_state.error:
    st.error("Pipeline error: " + st.session_state.error)


# ============================================================
# 00 — OVERVIEW
# ============================================================

if page == "Overview":

    st.markdown(
        '<div class="title-row">'
        '<div>'
        '<div class="eyebrow">WORKSPACE / 00 — SITUATION REPORT</div>'
        '<div class="page-title">Security, in context.</div>'
        '<div class="page-intro">'
        'A focused assessment of the supplied Flask demonstration app. '
        'Inspect the source, produce a remediation, verify the result '
        'and retain the evidence.'
        '</div>'
        '</div>'
        '<div class="stamp">PATCHPROOF / DEMO TARGET</div>'
        '</div>',
        unsafe_allow_html=True
    )

    left, right = st.columns([1.35, 1], gap="large")

    with left:

        st.markdown(
            '<div class="panel-dark">'
            '<div class="panel-kicker">01 / Start an assessment</div>'
            '<h2 style="font-size:29px;line-height:1.12;margin:12px 0">'
            'Find the flaw.<br>Verify the fix.</h2>'
            '<p style="font-size:12px;line-height:1.7">'
            'The pipeline runs the project scanner, creates a patched '
            'copy and unified diff, executes pytest, then refreshes '
            'the JSON assessment.</p>'
            '<div style="font:10px DM Mono;color:#9db6ba;margin-top:17px">'
            'SCOPE: SQL INJECTION · IDOR</div>'
            '</div>',
            unsafe_allow_html=True
        )

        if st.button(
            "RUN SECURITY ASSESSMENT  →",
            use_container_width=True,
            key="run_main"
        ):
            run_pipeline()

        st.caption(
            "This executes the actual project modules and test suite."
        )

    with right:

        st.markdown(
            '<div class="panel">'
            '<div class="eyebrow">CURRENT SESSION</div>'
            f'<div style="font-size:24px;font-weight:800;margin:9px 0">'
            f'{"ASSESSMENT COMPLETE" if st.session_state.complete else "AWAITING RUN"}'
            '</div>'
            f'<div class="stat-note">Last execution · '
            f'{html.escape(st.session_state.last_run or "Not run in this session")}'
            '</div>'
            '<hr>'
            '<div class="eyebrow">SOURCE UNDER REVIEW</div>'
            '<div style="font:12px DM Mono;margin:8px 0 17px">'
            'vulnerable_app/app.py</div>'
            '<div class="eyebrow">EXECUTION BOUNDARY</div>'
            '<div style="font-size:12px;margin-top:8px">'
            'Local fixture · synthetic records · no external target'
            '</div></div>',
            unsafe_allow_html=True
        )

    st.markdown(
        '<div class="eyebrow" style="margin:26px 0 10px">'
        'ASSESSMENT SNAPSHOT</div>',
        unsafe_allow_html=True
    )

    high_count = sum(
        1 for item in findings
        if str(item.get("severity", "")).lower() == "high"
    )

    cols = st.columns(4, gap="small")

    with cols[0]:
        stat(
            "Detected findings",
            len(findings) if st.session_state.complete else "—",
            "Latest in-session scan"
        )

    with cols[1]:
        stat(
            "High severity",
            high_count if st.session_state.complete else "—",
            "Triage priority"
        )

    with cols[2]:
        stat(
            "Patch artefacts",
            "READY" if patch_ready else "—",
            "Patched copy + diff"
        )

    with cols[3]:
        stat(
            "Test result",
            "PASS" if tests_pass else (
                "FAIL" if test_result else "—"
            ),
            "Latest pytest run"
        )

    st.markdown(
        '<div class="eyebrow" style="margin:27px 0 8px">'
        'WORKFLOW CHECKPOINTS</div>',
        unsafe_allow_html=True
    )

    checkpoints = [
        (
            "01",
            "Source inspection",
            "Targeted Python AST rules",
            bool(st.session_state.complete)
        ),
        (
            "02",
            "Remediation build",
            "Patched copy and unified diff",
            patch_ready
        ),
        (
            "03",
            "Regression verification",
            "Full project pytest suite",
            tests_pass
        ),
        (
            "04",
            "Evidence generation",
            "Machine-readable JSON report",
            REPORT.exists()
        ),
    ]

    for number, title, desc, ready in checkpoints:

        st.markdown(
            f'<div class="stage-line">'
            f'<div class="stage-no">{number}</div>'
            f'<div class="stage-copy">'
            f'<b>{html.escape(title)}</b>'
            f'<small>{html.escape(desc)}</small>'
            f'</div>'
            f'<div class="stage-state {"ok" if ready else ""}">'
            f'{"COMPLETE" if ready else "PENDING"}'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True
        )

    if findings:

        st.markdown(
            '<div class="eyebrow" style="margin:27px 0 8px">'
            'LATEST OBSERVATIONS</div>',
            unsafe_allow_html=True
        )

        for i, item in enumerate(findings, 1):
            finding_card(item, i)

    if st.session_state.stages:

        with st.expander("View pipeline stage details"):

            for name, ok, detail in st.session_state.stages:
                st.write(
                    ("✓ " if ok else "✕ ")
                    + name
                    + " — "
                    + detail
                )


# ============================================================
# 01 — THREAT REGISTER
# ============================================================

elif page == "Threat register":

    st.markdown(
        '<div class="title-row">'
        '<div>'
        '<div class="eyebrow">WORKSPACE / 01 — SOURCE INTELLIGENCE</div>'
        '<div class="page-title">Threat register</div>'
        '<div class="page-intro">'
        'A record of the supported vulnerability patterns '
        'detected in the latest scan.'
        '</div>'
        '</div>'
        '<div class="stamp">AST RULESET / 2 PATTERNS</div>'
        '</div>',
        unsafe_allow_html=True
    )

    if findings:

        selected = st.selectbox(
            "Filter by severity",
            ["All severities", "High", "Medium", "Low"]
        )

        visible = [
            item for item in findings
            if selected == "All severities"
            or str(item.get("severity", "")).lower()
            == selected.lower()
        ]

        x, y, z = st.columns(3)

        with x:
            stat("Total observations", len(findings), "Latest scan")

        with y:
            stat("Shown in register", len(visible), "Active filter")

        with z:
            stat("Rules supported", "02", "SQL injection / IDOR")

        for i, item in enumerate(visible, 1):
            finding_card(item, i)

    else:

        st.info(
            "No scan results are stored in this session. "
            "Run the assessment from Overview first."
        )


# ============================================================
# 02 — PATCH WORKSHOP
# ============================================================

elif page == "Patch workshop":

    st.markdown(
        '<div class="title-row">'
        '<div>'
        '<div class="eyebrow">WORKSPACE / 02 — REMEDIATION REVIEW</div>'
        '<div class="page-title">Patch workshop</div>'
        '<div class="page-intro">'
        'Inspect the generated changes. The original vulnerable '
        'fixture remains available for comparison.'
        '</div>'
        '</div>'
        '<div class="stamp">SOURCE → PATCHED COPY</div>'
        '</div>',
        unsafe_allow_html=True
    )

    if PATCHED.exists():

        st.success("Generated patched application is available.")

        if DIFF.exists():

            diff_text = DIFF.read_text(encoding="utf-8")

            st.markdown(
                '<div class="panel">'
                '<div class="eyebrow">CHANGE INTENT</div>'
                '<p style="font-size:12px;line-height:1.8;margin:10px 0 0">'
                '<b>SQL injection:</b> replace interpolated SQL with a parameterized query.<br>'
                '<b>IDOR:</b> use authenticated session identity and constrain order ownership.'
                '</p></div>',
                unsafe_allow_html=True
            )

            st.markdown(
                '<div class="eyebrow" style="margin:15px 0 8px">'
                'UNIFIED PATCH / GENERATED DIFF</div>',
                unsafe_allow_html=True
            )

            st.code(
                diff_text,
                language="diff",
                line_numbers=True
            )

            st.download_button(
                "Download patch diff",
                diff_text,
                "security_patch.diff",
                "text/x-diff"
            )

        else:

            st.warning(
                "The patched copy exists, but the diff is missing. "
                "Run the assessment again."
            )

        with st.expander("Inspect complete patched source"):

            st.code(
                PATCHED.read_text(encoding="utf-8"),
                language="python",
                line_numbers=True
            )

        st.download_button(
            "Download patched Flask app",
            PATCHED.read_bytes(),
            "patched_app.py",
            "text/x-python"
        )

    else:

        st.info(
            "No patched copy is available yet. "
            "Run the assessment from Overview."
        )


# ============================================================
# 03 — VERIFICATION
# ============================================================

elif page == "Verification":

    st.markdown(
        '<div class="title-row">'
        '<div>'
        '<div class="eyebrow">WORKSPACE / 03 — VALIDATION RECORD</div>'
        '<div class="page-title">Verification bench</div>'
        '<div class="page-intro">'
        'The actual pytest output captured by the most recent '
        'pipeline execution.'
        '</div>'
        '</div>'
        '<div class="stamp">PYTEST / REGRESSION</div>'
        '</div>',
        unsafe_allow_html=True
    )

    if test_result is not None:

        if tests_pass:
            st.success(
                "VALIDATION PASSED — pytest returned exit code 0."
            )
        else:
            st.error(
                f"VALIDATION FAILED — pytest returned exit code "
                f"{test_result.returncode}."
            )

        x, y, z = st.columns(3)

        with x:
            stat(
                "Exit code",
                test_result.returncode,
                "Zero indicates success"
            )

        with y:
            stat(
                "Suite status",
                "PASS" if tests_pass else "FAIL",
                "Latest full run"
            )

        with z:
            stat(
                "Command",
                "pytest -v",
                "Project root"
            )

        transcript = (test_result.stdout or "") + (
            ("\n" + test_result.stderr)
            if test_result.stderr else ""
        )

        st.markdown(
            '<div class="eyebrow" style="margin:22px 0 9px">'
            'CAPTURED TEST TRANSCRIPT</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="logbox">'
            + html.escape(transcript or "No output captured.")
            + '</div>',
            unsafe_allow_html=True
        )

        st.download_button(
            "Download test transcript",
            transcript,
            "pytest_validation.log",
            "text/plain"
        )

    else:

        st.info(
            "No test run has been captured in this session. "
            "Run the assessment from Overview."
        )

    st.markdown("### Verification coverage")

    coverage_items = [
        (
            "SQL injection payload is neutralized by the patched app",
            "tests/test_patched_app.py"
        ),
        (
            "Normal user search continues to work",
            "tests/test_patched_app.py"
        ),
        (
            "Authenticated user can access their own order",
            "tests/test_patched_app.py"
        ),
        (
            "Cross-user order access is blocked",
            "tests/test_patched_app.py"
        ),
        (
            "Unauthenticated order access is blocked",
            "tests/test_patched_app.py"
        ),
        (
            "Original fixture demonstrates both weaknesses",
            "tests/test_sql_injection.py / tests/test_idor.py"
        ),
    ]

    for label, source in coverage_items:

        st.markdown(
            f'<div class="rule-row">'
            f'<div class="rule-number">✓</div>'
            f'<div>'
            f'<div class="rule-name">{html.escape(label)}</div>'
            f'<div class="rule-desc">{html.escape(source)}</div>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True
        )


# ============================================================
# 04 — EVIDENCE
# ============================================================

elif page == "Evidence":

    st.markdown(
        '<div class="title-row">'
        '<div>'
        '<div class="eyebrow">WORKSPACE / 04 — AUDIT MATERIAL</div>'
        '<div class="page-title">Evidence archive</div>'
        '<div class="page-intro">'
        'Generated artefacts from the most recent successful '
        'pipeline stages.'
        '</div>'
        '</div>'
        '<div class="stamp">REPORTS / EXPORTS</div>'
        '</div>',
        unsafe_allow_html=True
    )

    report = read_report()

    if report:

        summary = report.get("summary", {})
        validation = report.get("validation", {})

        x, y, z = st.columns(3)

        with x:
            stat(
                "Reported findings",
                summary.get("total_vulnerabilities", "—"),
                "JSON assessment"
            )

        with y:
            stat(
                "High severity",
                summary.get("high", "—"),
                "JSON assessment"
            )

        with z:
            stat(
                "Validation",
                validation.get("status", "—"),
                "Recorded status"
            )

        report_text = json.dumps(report, indent=4)

        st.download_button(
            "Download security assessment",
            report_text,
            "security_report.json",
            "application/json"
        )

        with st.expander("Inspect JSON assessment"):
            st.json(report)

    else:

        st.info(
            "No JSON report is available. "
            "Run the pipeline to generate one."
        )

    st.markdown("### Artefact inventory")

    artefacts = [
        (
            "Security assessment",
            REPORT,
            "Machine-readable findings, severity and validation summary.",
            "application/json"
        ),
        (
            "Unified patch diff",
            DIFF,
            "Exact source changes produced by the patch engine.",
            "text/x-diff"
        ),
        (
            "Patched application",
            PATCHED,
            "Generated patched Flask application copy.",
            "text/x-python"
        ),
    ]

    for title, path, description, mime in artefacts:

        available = path.exists()

        st.markdown(
            f'<div class="panel">'
            f'<div style="display:flex;justify-content:space-between;gap:12px">'
            f'<b>{html.escape(title)}</b>'
            f'<span class="stage-state {"ok" if available else ""}">'
            f'{"AVAILABLE" if available else "NOT GENERATED"}'
            f'</span></div>'
            f'<p style="font-size:11px;margin:8px 0">'
            f'{html.escape(description)}</p>'
            f'<div class="eyebrow">'
            f'{html.escape(str(path.relative_to(ROOT)))}'
            f'</div></div>',
            unsafe_allow_html=True
        )

        if available:

            st.download_button(
                f"Export {path.name}",
                path.read_bytes(),
                path.name,
                mime,
                key="export_" + path.name
            )


# ============================================================
# 05 — SYSTEM NOTES
# ============================================================

elif page == "System notes":

    st.markdown(
        '<div class="title-row">'
        '<div>'
        '<div class="eyebrow">WORKSPACE / 05 — ENGINEERING NOTES</div>'
        '<div class="page-title">System notes</div>'
        '<div class="page-intro">'
        'Architecture, supported detection patterns and the '
        'boundaries of this prototype.'
        '</div>'
        '</div>'
        '<div class="stamp">PROJECT SPECIFICATION</div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="panel-dark">'
        '<div class="panel-kicker">PROCESS MODEL</div>'
        '<h2 style="font-size:25px;margin:10px 0">'
        'Inspect → Remediate → Verify → Record</h2>'
        '<p style="font-size:12px;line-height:1.7">'
        'The Streamlit interface invokes a Python AST-based targeted '
        'scanner, a patch generator, the project pytest suite and a '
        'JSON report generator. The vulnerable Flask fixture uses '
        'synthetic SQLite records.</p>'
        '</div>',
        unsafe_allow_html=True
    )

    left, right = st.columns(2, gap="large")

    with left:

        st.markdown(
            '<div class="panel">'
            '<div class="eyebrow">TECHNOLOGY</div>'
            '<h3>Project components</h3>'
            '<p style="font-size:12px;line-height:1.9">'
            'Python · Flask · SQLite<br>'
            'Python AST · Streamlit<br>'
            'pytest · difflib'
            '</p></div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="panel">'
            '<div class="eyebrow">DETECTION SCOPE</div>'
            '<h3>Two supported patterns</h3>'
            '<p style="font-size:12px;line-height:1.9">'
            'SQL injection: targeted detection of f-string SQL '
            'passed to execute().<br><br>'
            'IDOR: targeted order-query ownership pattern in '
            'the included fixture.'
            '</p></div>',
            unsafe_allow_html=True
        )

    with right:

        st.markdown(
            '<div class="panel">'
            '<div class="eyebrow">BOUNDARIES</div>'
            '<h3>What this demo does</h3>'
            '<p style="font-size:12px;line-height:1.9">'
            'Runs against a deliberately vulnerable local '
            'demonstration app with synthetic records. '
            'It does not scan external targets.'
            '</p></div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="note">'
            '<b>Important limitation</b><br>'
            'The static rules are tailored to the supplied fixture. '
            'Detecting IDOR in arbitrary applications requires deeper '
            'data-flow and authorization-context analysis than this '
            'prototype implements.'
            '</div>',
            unsafe_allow_html=True
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    '<div class="footer">'
    '<span>PATCHPROOF / APPLICATION SECURITY WORKBENCH</span>'
    '<span>INSPECT · REMEDIATE · VERIFY · RECORD</span>'
    '</div>',
    unsafe_allow_html=True
)