# IncidentIQ — AI Incident Triage Dashboard

**IncidentIQ** is a fast, deterministic incident triage platform designed for on-call site reliability engineers and developers during high-stakes outages. It parses raw system logs, alerts, and stack traces to immediately classify incident severity, isolate root causes with verbatim evidence, produce prioritized operational runbooks, and identify the single most critical next remediation action.

Built with **Python** and **Streamlit**, IncidentIQ runs **100% offline** without requiring external APIs, credentials, or paid cloud services.

---

## 🚀 Key Features

* **Instant Triage**: Classifies severity (`Critical`, `High`, `Medium`, `Low`), architecture category, and estimated blast radius.
* **Evidence-Backed Root Cause Diagnosis**: Extracts verbatim quotes and telemetry signals directly from logs to substantiate hypotheses.
* **Prioritized Operational Runbooks**: Step-by-step remediation procedures tailored to the specific failure domain.
* **Immediate Next Action**: Highlights the single immediate command or operational step to execute first.
* **8 Realistic Production Scenarios**: 1-click load pre-configured incidents spanning PostgreSQL deadlocks, Kubernetes OOMKills, DNS resolution storms, expired SSL certificates, Redis cache avalanches, Stripe webhook signature mismatches, AWS IAM policy drift, and disk exhaustion.
* **Session History**: Track, compare, and switch back to previously analyzed incidents during the active session.
* **JSON Export**: Download structured triage reports for immediate handoff to Slack, PagerDuty, or postmortem tickets.
* **Pluggable Architecture**: Clear separation of engine logic from the presentation layer; ready to drop in an LLM provider later.

---

## 📁 Project Structure

```text
Sample_project/
├── .streamlit/
│   └── config.toml          # Native dark theme styling & telemetry suppression
├── engine/
│   ├── __init__.py          # Engine package exports
│   ├── models.py            # Dataclasses (IncidentAnalysis, SeverityLevel, IncidentCategory)
│   ├── analyzer.py          # BaseIncidentAnalyzer & RuleBasedAnalyzer (offline, deterministic)
│   └── samples.py           # 8 production-grade incident scenarios
├── tests/
│   └── test_analyzer.py     # Unit test suite verifying scenarios, validation & export
├── app.py                   # Streamlit dashboard interface & session management
├── requirements.txt         # Minimal dependency: streamlit>=1.35.0
└── README.md                # Documentation & run instructions
```

---

## 🛠️ Quick Start

### 1. Prerequisites
* Python 3.10+ (tested on Python 3.11)

### 2. Setup Virtual Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 4. Run the Dashboard
```powershell
python -m streamlit run app.py
```
The application will launch automatically in your browser at `http://localhost:8501`.

---

## 🧪 Running Tests

Execute the unit test suite to verify the analyzer logic, scenario detection, and validation rules:

```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
```

---

## 🔌 Future LLM Integration

IncidentIQ uses an abstract base class (`BaseIncidentAnalyzer`) located in [`engine/models.py`](engine/models.py) and [`engine/analyzer.py`](engine/analyzer.py):

```python
from engine.analyzer import BaseIncidentAnalyzer
from engine.models import IncidentAnalysis

class LLMIncidentAnalyzer(BaseIncidentAnalyzer):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def analyze(self, incident_text: str) -> IncidentAnalysis:
        # Prompt LLM with structured output schema matching IncidentAnalysis
        ...
```

To switch from the rule-based engine to an LLM, simply replace `analyzer = RuleBasedAnalyzer()` in [`app.py`](app.py) with `analyzer = LLMIncidentAnalyzer(...)`.
