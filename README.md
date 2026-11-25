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

## Running as an MCP server

`incident_mcp/server.py` exposes every tool whose docstring lists `mcp` under `expose`:

- The docstring's `description` becomes the tool description.
- Each `args` description becomes a parameter description in the input schema.
- The `tags` are sent in the tool's `_meta`.
- Every tool is marked read-only, idempotent and closed-world.

The server also sends the suggested workflow as server instructions, and offers an `incident_response` prompt. It works with MCP Python SDK 2.x (`MCPServer`) and 1.x (`FastMCP`).

```bash
pip install -e .
```

```bash
incident-mcp                                            # stdio, for Claude Code / Claude Desktop
```

```bash
incident-mcp --transport streamable-http --port 8000    # shared HTTP server at http://127.0.0.1:8000/mcp
```

Options: `--host`, `--port`, `--knowledge-dir` and `--templates-dir` (to use your own rules and templates), and `--log-level`. Logs go to stderr, so they never mix with the stdio protocol.

**Claude Code:**

```bash
claude mcp add incident-resolution -- python -m incident_mcp.server
```

**Claude Desktop** (`claude_desktop_config.json`). Set `cwd` to this repository, or install the package first:

```json
{
  "mcpServers": {
    "incident-resolution": {
      "command": "python",
      "args": ["-m", "incident_mcp.server"],
      "cwd": "/path/to/Incident-management"
    }
  }
}
```

The HTTP transport has no authentication. Bind it to `127.0.0.1` (the default) or put it behind your gateway or OAuth before you share it (see `plan.md` §8–9).

To try it interactively, use the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector python -m incident_mcp.server
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

The tests also check that every tool's docstring parses as YAML, contains no tabs, and lists the same args as the method signature. `tests/test_server.py` checks the MCP tool schemas and runs a real client against the server over stdio.
