# Incident Resolution MCP tools

Simple, deterministic Python tools that an agent can call to analyse IT incidents, find likely root causes, suggest remediation steps and write escalation summaries. See [plan.md](plan.md) for the full approach. This repository implements the "simple track" in section 15.

The tools only read the text they are given and the files in `incident_mcp/knowledge/`. **They never change a real system.** Root causes are hypotheses, and remediation steps are recommendations.

## Tools

All tools are methods on `incident_mcp.IncidentResolution`. Each method's docstring (`description`, `expose`, `tags`, `args`) is its MCP/FastAPI tool definition. Every tool returns a `dict` with `success` and never raises.

| Activity | Tool | What it does |
|---|---|---|
| Health | `health_check` | Service status and how much knowledge is loaded |
| Analysis | `classify_incident` | Category with confidence, from weighted whole-word keywords |
| | `assess_severity` | SEV1–SEV4 with reasons (impact words, users or % affected, production, revenue) |
| | `extract_incident_details` | Services, hosts, IPs, HTTP codes, error codes, exceptions, tickets, times, metrics |
| | `analyze_logs` | Groups error lines into signatures with counts and first/last seen, with secrets redacted |
| | `build_timeline` | Sorts events and computes the gaps between them and the total duration |
| | `find_similar_incidents` | TF-IDF match against `knowledge/past_incidents.json` |
| Root cause | `find_root_cause` | Ranked causes with likelihood, evidence and a check to confirm each one |
| | `correlate_with_changes` | Scores recent changes by how close they were to the incident, same service and risk |
| | `five_whys` | Guided 5 whys chain, with warnings about blame and answers that are still symptoms |
| Remediation | `generate_remediation` | Ordered steps (diagnose → mitigate → fix → verify), each with risk, verification and rollback |
| | `get_runbook` | Runbook by root cause or category |
| | `verify_recovery` | Compares a metric before and after a fix with a threshold |
| Escalation | `determine_escalation` | Whether to escalate, which team and which tier, by SLA |
| | `create_escalation_summary` | Markdown handoff note for the next team |
| | `create_executive_summary` | Short, non-technical management summary |
| | `draft_postmortem` | Blameless postmortem draft |
| Composite | `triage_incident` | Runs the analysis, root cause, remediation and escalation tools in one call |

## Usage

```python
from incident_mcp import IncidentResolution

ir = IncidentResolution()
result = ir.triage_incident(
    "Checkout API returning 500s in prod, ~30% of users, logs show too many connections",
    minutes_open=75,
)
print(result["summary"])
# SEV2 Database incident. Most likely cause: Database connection pool exhaustion (medium likelihood). ...
```

## Tuning the knowledge

Change behaviour by editing the files below. No code changes are needed.

| File | Holds |
|---|---|
| `knowledge/categories.yaml` | Categories, keywords and weights |
| `knowledge/causes.yaml` | Causes per category, with indicator words and a check to confirm each one |
| `knowledge/remediation.yaml` | Steps per category, and per cause where they differ |
| `knowledge/runbooks.yaml` | Runbook index. **The links and owners are placeholders.** |
| `knowledge/escalation.yaml` | SLA minutes, tiers and team routing. **The team names are placeholders.** |
| `knowledge/severity.yaml` | Severity words and thresholds |
| `knowledge/past_incidents.json` | Sample past incidents. Replace them with your own. |
| `templates/*.md` | Templates for the escalation summary, executive summary and postmortem |

In `remediation.yaml`, quote any value that contains a comma inside a `{...}` mapping, or YAML will split it.

## Development

```bash
pip install -e ".[test]"
```

```bash
pytest -q
```

The tests also check that every tool's docstring parses as YAML, contains no tabs, and lists the same args as the method signature.
