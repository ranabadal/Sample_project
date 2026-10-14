"""IncidentIQ — AI Incident Triage Dashboard
A fast, offline, deterministic incident triage platform for on-call engineers.
"""

import streamlit as st
import json
from datetime import datetime

from engine.models import SeverityLevel, IncidentCategory, IncidentAnalysis
from engine.analyzer import RuleBasedAnalyzer
from engine.samples import get_sample_incidents, SAMPLE_INCIDENTS

# Configure Streamlit page layout
st.set_page_config(
    page_title="IncidentIQ — Incident Triage Dashboard",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished dark-mode styling and badge rendering
st.markdown(
    """
    <style>
    /* Metric and card stylings */
    .metric-card {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.85rem;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        margin-right: 8px;
    }
    .badge-critical {
        background-color: #7F1D1D;
        color: #FECACA;
        border: 1px solid #DC2626;
    }
    .badge-high {
        background-color: #7C2D12;
        color: #FED7AA;
        border: 1px solid #EA580C;
    }
    .badge-medium {
        background-color: #713F12;
        color: #FEF08A;
        border: 1px solid #CA8A04;
    }
    .badge-low {
        background-color: #14532D;
        color: #BBF7D0;
        border: 1px solid #16A34A;
    }
    .badge-category {
        background-color: #1E3A8A;
        color: #BFDBFE;
        border: 1px solid #3B82F6;
    }
    .badge-radius {
        background-color: #312E81;
        color: #DDD6FE;
        border: 1px solid #6366F1;
    }
    .callout-box {
        background-color: #1E293B;
        border-left: 5px solid #3B82F6;
        border-radius: 0 8px 8px 0;
        padding: 14px 18px;
        margin: 12px 0;
    }
    .callout-action {
        background-color: #182822;
        border-left: 5px solid #10B981;
        border-radius: 0 8px 8px 0;
        padding: 14px 18px;
        margin: 12px 0;
    }
    .evidence-item {
        background-color: #0F172A;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.9rem;
        color: #E2E8F0;
    }
    .step-item {
        background-color: #1E293B;
        border-left: 3px solid #38BDF8;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 0 6px 6px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []

if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None

if "input_text" not in st.session_state:
    st.session_state.input_text = ""

# Analyzer instance
analyzer = RuleBasedAnalyzer()
samples = get_sample_incidents()

# ---------------------------------------------------------
# Sidebar: Metrics, Controls & Session History
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("## 🚨 IncidentIQ")
    st.caption("AI Incident Triage & Root Cause Engine")
    st.markdown("---")

    # Session Metrics
    total_triaged = len(st.session_state.history)
    crit_count = sum(1 for inc in st.session_state.history if inc.severity == SeverityLevel.CRITICAL)
    high_count = sum(1 for inc in st.session_state.history if inc.severity == SeverityLevel.HIGH)

    st.markdown("### 📊 Session Summary")
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.metric("Total Triaged", total_triaged)
    with col_m2:
        st.metric("Critical / High", f"{crit_count} / {high_count}")

    st.markdown("---")
    st.markdown("### 🕒 Session History")

    if not st.session_state.history:
        st.info("No incidents analyzed yet in this session.")
    else:
        for idx, item in enumerate(reversed(st.session_state.history)):
            history_key = f"hist_{item.incident_id}_{idx}"
            badge_color = {
                SeverityLevel.CRITICAL: "🔴",
                SeverityLevel.HIGH: "🟠",
                SeverityLevel.MEDIUM: "🟡",
                SeverityLevel.LOW: "🟢",
            }.get(item.severity, "⚪")

            button_label = f"{badge_color} {item.incident_id} · {item.title[:22]}..."
            if st.button(button_label, key=history_key, use_container_width=True):
                st.session_state.current_analysis = item
                st.session_state.input_text = item.raw_input
                st.rerun()

        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.history = []
            st.session_state.current_analysis = None
            st.session_state.input_text = ""
            st.rerun()

    st.markdown("---")
    st.caption("🔒 **Mode**: Offline Deterministic Engine")
    st.caption("⚡ **Zero API Keys Required**")


# ---------------------------------------------------------
# Main Dashboard Area
# ---------------------------------------------------------
st.title("IncidentIQ — Incident Triage Dashboard")
st.markdown(
    "Automated, evidence-backed incident severity triage, root-cause diagnostics, and prioritized response runbooks."
)

# Incident Input Section
st.markdown("### 📥 Incident Intake")

col_sample, col_spacer = st.columns([3, 1])
with col_sample:
    sample_options = ["-- Choose a pre-configured sample incident --"] + list(samples.keys())
    selected_sample = st.selectbox(
        "Load a realistic production scenario:",
        sample_options,
        index=0,
        help="Select any of the 8 production incident scenarios to populate the triage intake.",
    )

# When a sample is selected from dropdown, update input text
if selected_sample != "-- Choose a pre-configured sample incident --":
    loaded_desc = samples[selected_sample].description
    if st.session_state.input_text != loaded_desc:
        st.session_state.input_text = loaded_desc

# Text area for incident details
user_input = st.text_area(
    "Incident Description / System Logs / PagerDuty Alert:",
    value=st.session_state.input_text,
    height=160,
    placeholder="Paste incident alerts, stderr stack traces, pgbouncer logs, Kubernetes pod events, or user impact reports...",
    help="Provide as much technical context, error codes, and symptoms as possible.",
)

col_btn1, col_btn2, col_btn_spacer = st.columns([2, 1, 4])

with col_btn1:
    triage_clicked = st.button("⚡ Triage Incident", type="primary", use_container_width=True)

with col_btn2:
    if st.button("Reset", use_container_width=True):
        st.session_state.input_text = ""
        st.session_state.current_analysis = None
        st.rerun()

# Execute analysis if triggered
if triage_clicked:
    st.session_state.input_text = user_input
    try:
        with st.spinner("Analyzing incident context, extracting evidence, and evaluating root cause..."):
            result = analyzer.analyze(user_input)
            st.session_state.current_analysis = result
            # Add to history if not duplicate of the latest entry
            if not st.session_state.history or st.session_state.history[-1].raw_input != result.raw_input:
                st.session_state.history.append(result)
            st.success(f"Analysis complete for {result.incident_id}")
    except ValueError as val_err:
        st.error(f"⚠️ Validation Error: {str(val_err)}")
    except Exception as exc:
        st.error(f"❌ Unexpected Error during analysis: {str(exc)}")

st.markdown("---")

# ---------------------------------------------------------
# Results Section: Display Current Analysis
# ---------------------------------------------------------
analysis: IncidentAnalysis = st.session_state.current_analysis

if analysis:
    st.markdown(f"## 📋 Triage Report: `{analysis.incident_id}`")
    st.caption(f"Generated at: {analysis.timestamp} · Heuristic Confidence: **{analysis.confidence_score}%**")

    # Badges Header Row
    severity_css_class = {
        SeverityLevel.CRITICAL: "badge-critical",
        SeverityLevel.HIGH: "badge-high",
        SeverityLevel.MEDIUM: "badge-medium",
        SeverityLevel.LOW: "badge-low",
    }.get(analysis.severity, "badge-medium")

    badge_html = f"""
    <div style="margin-bottom: 20px;">
        <span class="badge {severity_css_class}">Severity: {analysis.severity.value}</span>
        <span class="badge badge-category">Category: {analysis.category.value}</span>
        <span class="badge badge-radius">Blast Radius: {analysis.blast_radius}</span>
    </div>
    """
    st.markdown(badge_html, unsafe_allow_html=True)

    # Incident Summary
    st.markdown(
        f"""
        <div class="callout-box">
            <strong>Executive Summary:</strong> {analysis.summary}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2-Column Main Analysis View
    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        # Root Cause Diagnosis
        st.markdown("### 🔍 Root Cause Diagnosis")
        st.info(analysis.likely_root_cause)

        # Supporting Evidence Quotes
        st.markdown("#### 📑 Extracted Supporting Evidence")
        if analysis.supporting_evidence:
            for ev in analysis.supporting_evidence:
                st.markdown(f'<div class="evidence-item">❝ {ev} ❞</div>', unsafe_allow_html=True)
        else:
            st.caption("No direct error lines isolated; evaluated using heuristic context.")

    with col_right:
        # Prioritized Troubleshooting Steps
        st.markdown("### 🛠️ Prioritized Troubleshooting Steps")
        for idx, step in enumerate(analysis.prioritized_troubleshooting_steps, 1):
            st.markdown(
                f'<div class="step-item"><strong>Step {idx}:</strong> {step}</div>',
                unsafe_allow_html=True,
            )

        # Immediate Recommended Action Callout
        st.markdown("### ⚡ Immediate Next Action")
        st.markdown(
            f"""
            <div class="callout-action">
                <strong>Recommended Immediate Step:</strong><br/>
                <code>{analysis.recommended_next_action}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # JSON Export & Raw Data
    st.markdown("---")
    col_exp1, col_exp2 = st.columns([2, 4])

    with col_exp1:
        json_filename = f"{analysis.incident_id.lower()}_triage_report.json"
        st.download_button(
            label="💾 Download Triage Report (JSON)",
            data=analysis.to_json(indent=2),
            file_name=json_filename,
            mime="application/json",
            use_container_width=True,
        )

    with col_exp2:
        with st.expander("👁️ View Raw Structured JSON Payload"):
            st.code(analysis.to_json(indent=2), language="json")

else:
    st.info("👆 Enter an incident description above or pick a sample scenario, then click **Triage Incident** to generate a triage report.")
