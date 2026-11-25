# Incident Management MCP Server — Plan

## 1. Goal

Support and Operations engineers spend much of their time on four activities:

1. **Analyzing incidents.** They gather alerts, logs, metrics, recent changes and related tickets, then work out what is happening.
2. **Finding root causes.** They connect symptoms to a cause such as a deploy, a config change, a dependency failure or capacity.
3. **Creating remediation steps.** They write concrete, safe and ordered actions, often taken from runbooks.
4. **Generating escalation summaries.** They write short handoffs for the next tier, management or a vendor.

The goal is to expose these activities as **MCP (Model Context Protocol) tools** so that any agent (Claude Code, Claude Desktop, a custom Agent SDK app, or a Slack bot) can carry out the workflow from start to finish, or help a person with it.

### Success criteria
| Metric | Target (first 3 months) |
|---|---|
| Time to first useful triage summary | < 2 min (from ~20–30 min) |
| Root cause hypothesis accepted by an engineer | ≥ 60% of P2/P3 incidents |
| Escalation summary written by hand | ↓ 80% |
| MTTR for incident classes with runbooks | ↓ 25% |
| Unsafe or automatic production changes | **0** (human approval is always required) |

---

## 2. Key design principle: tools gather data, the agent reasons

There are two ways to build "MCP tools for incident analysis":

- **Option A: "Smart" tools.** Each tool calls an LLM inside itself. For example, `find_root_cause()` returns an answer.
- **Option B: "Data + structure" tools.** The tools fetch, correlate and shape data deterministically. The agent's model reasons over the results, and the analysis steps are provided as **MCP prompts**.

**Recommendation: mostly Option B, with a few composite tools.**

- The agent already contains an LLM. Putting a second LLM inside a tool hides the reasoning, doubles the cost and makes evaluation harder.
- Deterministic tools are testable, cacheable and auditable.
- The *analysis* parts (root cause analysis, remediation, escalation) are delivered as **prompts or templates** plus **tools with structured output**. The agent fills in a schema, and the tool validates it, stores it and publishes it.
- Add server-side LLM calls (MCP *sampling*, or a direct API call) only where they clearly help, for example to summarize 50k log lines before returning them.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Agent hosts: Claude Code / Claude Desktop / Agent SDK app / Slack bot│
└───────────────┬──────────────────────────────────────────────────────┘
                │ MCP (stdio for local, Streamable HTTP for shared)
┌───────────────▼──────────────────────────────────────────────────────┐
│                  incident-mcp server                                  │
│  ┌────────────┐ ┌────────────┐ ┌─────────────┐ ┌──────────────────┐  │
│  │  Tools     │ │ Resources  │ │  Prompts    │ │ Policy / Audit   │  │
│  │ (actions)  │ │ (read ctx) │ │ (workflows) │ │ (RBAC, redaction,│  │
│  └─────┬──────┘ └─────┬──────┘ └─────────────┘ │  approval gates) │  │
│        │              │                         └──────────────────┘  │
│  ┌─────▼──────────────▼─────────────────────────────────────────────┐ │
│  │  Connector layer (adapters, one interface per source type)       │ │
│  │  Ticketing │ Alerting │ Logs │ Metrics │ Traces │ Deploys/CI │    │ │
│  │  CMDB/Topology │ Runbooks/KB │ Chat │ On-call                     │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  Knowledge store: past incidents + postmortems + runbooks         │ │
│  │  (vector index + metadata) for similarity search                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

### Connector layer (pluggable)
Define one abstract interface per **source type**, then implement it for whatever tools you use:

| Source type | Example backends |
|---|---|
| Ticketing / ITSM | ServiceNow, Jira Service Management, Zendesk |
| Alerting / on-call | PagerDuty, Opsgenie, Alertmanager |
| Logs | Elastic/OpenSearch, Splunk, Loki, CloudWatch Logs, Datadog Logs |
| Metrics | Prometheus, Datadog, CloudWatch, Azure Monitor |
| Traces | Jaeger, Tempo, Datadog APM, Honeycomb |
| Change / deploys | GitHub/GitLab, ArgoCD, Jenkins, Spinnaker, change records in ITSM |
| Topology / CMDB | ServiceNow CMDB, Backstage catalog, k8s API |
| Knowledge | Confluence, Git-hosted runbooks, past postmortems |
| Communication | Slack, Teams, email |

Start with **mock or file-based adapters** (JSON fixtures) so the whole flow can be built and evaluated before any real integration is connected.

---

## 4. Tool catalogue

Tools are grouped by the four activities. Every tool returns **structured JSON** (described by an output schema) as well as a short text summary.

### 4.1 Incident analysis (context gathering)

| Tool | Purpose | Key inputs | Output highlights |
|---|---|---|---|
| `get_incident` | Fetch an incident or ticket with its timeline | `incident_id` | title, severity, status, affected services, timeline, assignees |
| `list_active_incidents` | Triage queue | `severity?`, `service?`, `since?` | short list |
| `get_alerts` | Alerts for a service or time window | `service`, `start`, `end` | alerts grouped and deduplicated by fingerprint |
| `search_logs` | Run a log query, returning **patterns, not raw dumps** | `service`, `query`, `start`, `end`, `limit` | top error signatures, counts, first/last seen, sample lines (redacted) |
| `query_metrics` | Fetch golden signals or a custom metric | `service`, `metric` or `signal` (latency/errors/traffic/saturation), window | series summary, detected anomalies, baseline comparison |
| `get_traces` | Slow or failing traces | `service`, `window`, `status` | critical path, failing span, downstream service |
| `get_service_topology` | Dependencies upstream and downstream | `service`, `depth` | graph (nodes and edges with health) |
| `get_recent_changes` | Deploys, config changes, feature flags and infra changes | `services[]`, `window` | changes sorted by time with author, diff link and risk tags |
| `find_similar_incidents` | Semantic search over past incidents and postmortems | `description` or `incident_id`, `k` | matches with similarity score, root cause and fix |
| `build_incident_timeline` | Merge alerts, changes, log spikes and ticket events into one timeline | `incident_id`, `window` | ordered events with source attribution |
| `get_incident_context` *(composite)* | Runs the tools above in parallel and returns one context bundle | `incident_id` | the full bundle, for a fast first pass |

### 4.2 Root cause analysis

| Tool | Purpose |
|---|---|
| `correlate_changes_with_symptoms` | Deterministic scoring: how close each change is in time to the anomaly onset, and whether it touched an affected service or dependency. Returns ranked suspects. |
| `analyze_error_patterns` | Clusters log errors, finds **new** signatures (missing from the baseline window) and spots stack-trace commonality. |
| `check_dependency_health` | Walks the topology and reports which upstream or downstream services are unhealthy. Separates *caused by* from *causing*. |
| `compare_windows` | Compares the incident window with a baseline (metrics, error rates, traffic mix, versions) and reports what is different. |
| `record_rca_hypothesis` | The agent submits a structured hypothesis (`cause`, `evidence[]`, `confidence`, `category`, `contributing_factors[]`, `ruled_out[]`). The server validates and stores it and attaches it to the incident. |

> The *reasoning* ("five whys", fault tree analysis, change-first heuristics) lives in the `root_cause_analysis` **prompt** (§5). The tools supply evidence and store the result.

### 4.3 Remediation

| Tool | Purpose |
|---|---|
| `search_runbooks` | Finds runbooks by service, symptom or error signature (semantic and tag-based). |
| `get_runbook` | Returns the full runbook as structured steps (`step`, `command`, `risk`, `verification`, `rollback`). |
| `get_rollback_options` | Lists previous good versions or config revisions for the suspect change. |
| `propose_remediation_plan` | The agent submits an ordered plan (`steps[]` with `action`, `owner`, `risk_level`, `blast_radius`, `verification`, `rollback`). The server validates it against policy (for example, flags prod writes and missing rollback steps) and stores it. |
| `execute_remediation_step` *(phase 3, gated)* | Runs **only** allow-listed, idempotent actions such as restarting a pod, scaling a deployment or toggling a flag. **It requires a human approval token**, and dry run is the default. |
| `verify_recovery` | Checks the golden signals against the SLO after a fix and returns recovered, partial or not recovered. |

### 4.4 Escalation and communication

| Tool | Purpose |
|---|---|
| `get_oncall` | Finds who is on call for a service or team, plus the escalation policy. |
| `generate_escalation_summary` | Assembles a summary from the stored incident, RCA hypothesis and plan using a **template**: *what / impact / since when / what was tried / current hypothesis / ask / next update time*. Returns markdown and JSON. Variants for audiences: `engineering`, `management`, `vendor`, `customer`. |
| `post_update` | Posts the summary to Slack/Teams or the ticket. **Requires confirmation.** |
| `escalate_incident` | Pages the next tier or reassigns the ticket with the summary attached. **Requires confirmation.** |
| `draft_postmortem` | Creates a postmortem draft (timeline, root cause, impact, action items) after resolution. |

---

## 5. MCP prompts (packaged workflows)

Prompts let any host start a repeatable, well-structured workflow:

| Prompt | What it tells the agent to do |
|---|---|
| `triage_incident(incident_id)` | Call `get_incident_context`, classify severity and impact, list unknowns and suggest the next queries. |
| `root_cause_analysis(incident_id)` | Look at changes first, then dependencies, then capacity and resources, then code or data. Gather evidence for each hypothesis, rule others out explicitly, assign a confidence level, then call `record_rca_hypothesis`. |
| `remediation_plan(incident_id)` | Prefer mitigation (rollback, failover, scale) before a fix. Use runbooks. Give every step a verification and a rollback. Then call `propose_remediation_plan`. |
| `escalation_summary(incident_id, audience)` | Produce a summary that fits the audience, then call `generate_escalation_summary`. |
| `full_incident_workflow(incident_id)` | Chains all four, stopping for a human checkpoint before any write action. |

## 6. MCP resources (read-only context)

- `incident://{id}`: the live incident record
- `incident://{id}/timeline`, `incident://{id}/rca`, `incident://{id}/plan`
- `runbook://{service}/{name}`
- `service://{name}`: owner, tier, SLOs and dependencies
- `postmortem://{id}`

---

## 7. Data model (core schemas)

```jsonc
// Incident (normalized from any ITSM)
{ "id": "INC-1234", "title": "", "severity": "SEV2", "status": "investigating",
  "services": ["checkout-api"], "started_at": "", "detected_at": "",
  "impact": { "users_affected": null, "slo_breached": ["availability"] },
  "timeline": [ { "ts": "", "source": "alert|deploy|log|human", "event": "" } ] }

// RCA hypothesis
{ "incident_id": "", "cause": "", "category": "deploy|config|dependency|capacity|data|infra|security|unknown",
  "confidence": 0.0, "evidence": [ { "type": "", "ref": "", "summary": "" } ],
  "ruled_out": [ { "hypothesis": "", "reason": "" } ], "contributing_factors": [] }

// Remediation plan
{ "incident_id": "", "strategy": "mitigate|fix|workaround",
  "steps": [ { "order": 1, "action": "", "command": null, "owner": "", "risk": "low|med|high",
               "requires_approval": true, "verification": "", "rollback": "" } ] }

// Escalation summary
{ "incident_id": "", "audience": "engineering|management|vendor|customer",
  "headline": "", "impact": "", "status": "", "actions_taken": [], "hypothesis": "",
  "ask": "", "next_update_at": "" }
```

---

## 8. Technology choices

| Concern | Recommendation |
|---|---|
| Language / SDK | **Python + the official `mcp` SDK (FastMCP)**, which is quick to build with and well suited to data and ML work. TypeScript (`@modelcontextprotocol/sdk`) is an equally good choice if your team prefers it. |
| Transport | `stdio` for local development and Claude Code; **Streamable HTTP** for a shared, centrally deployed server. |
| Auth | OAuth 2.1 for the HTTP transport (per the MCP spec). The server holds the backend credentials, and users never see them. |
| Similar-incident search | Postgres + `pgvector` (or OpenSearch k-NN), with embeddings of incident title, description, root cause and fix. |
| Storage of RCA, plans and audit | Postgres |
| Caching | Redis, keyed by query, with a short TTL to protect log and metric backends |
| Testing | pytest + recorded fixtures + the MCP Inspector |
| Deploy | Container on k8s, behind an internal gateway |

### Suggested repository layout
```
incident-mcp/
├── pyproject.toml
├── src/incident_mcp/
│   ├── server.py              # FastMCP app: registers tools/prompts/resources
│   ├── config.py              # which adapters are enabled, credentials via env/secret store
│   ├── models.py              # pydantic schemas (§7)
│   ├── tools/
│   │   ├── analysis.py        # §4.1
│   │   ├── rca.py             # §4.2
│   │   ├── remediation.py     # §4.3
│   │   └── escalation.py      # §4.4
│   ├── prompts/               # §5 prompt templates
│   ├── resources.py           # §6
│   ├── connectors/
│   │   ├── base.py            # abstract interfaces per source type
│   │   ├── mock/              # fixture-backed adapters (phase 0)
│   │   ├── servicenow.py, pagerduty.py, elastic.py, prometheus.py, github.py, ...
│   ├── correlation/           # deterministic scoring, log clustering, anomaly detection
│   ├── knowledge/             # embeddings + similar-incident index
│   └── policy/                # redaction, RBAC, approval gates, audit log
├── fixtures/                  # sample incidents, logs, metrics for dev/evals
├── evals/                     # golden incidents + scoring harness
└── tests/
```

---

## 9. Safety, security and governance

Incident tooling touches production, so build these in from the first day:

1. **Read-only by default.** Phases 1 and 2 ship no write tools that touch production.
2. **Tiered tool permissions.** `read` (analysis), `write-ticket` (comment or update), `notify` (Slack, paging) and `act` (production changes). Map them to RBAC roles and expose only the tiers the caller is allowed to use.
3. **Human-in-the-loop.** Every `notify` or `act` tool needs explicit confirmation (MCP elicitation, or an approval token from an approver). Production actions run as a **dry run by default**.
4. **Allow-listed actions only** for `execute_remediation_step`. There is no arbitrary shell or `kubectl`.
5. **PII and secret redaction** of log and ticket text before it reaches the model (regexes for emails, tokens, card numbers and IPs, plus custom patterns).
6. **Output size limits.** Tools summarize and paginate instead of dumping 10 MB of logs into context.
7. **Audit log.** Record who called which tool, the arguments, the result hash, and the incident it relates to.
8. **Prompt-injection awareness.** Log lines and ticket text are *untrusted data*. Wrap them clearly in tool output, and never let them trigger write actions without a human checkpoint.
9. **Rate limiting and caching** to protect observability backends during a major incident, when many agents and people query them at once.

---

## 10. Evaluation

You can't improve what you don't measure. Build this alongside the tools:

- **Golden dataset.** 30–50 past incidents with known root cause, fix and a good escalation note. Replay their logs, metrics and changes through the mock adapters.
- **Automatic scoring:**
  - RCA: is the correct cause in the top-1 or top-3 hypotheses? Category accuracy.
  - Remediation: did it reference the right runbook or rollback? Does every step have a verification and a rollback?
  - Escalation: completeness against the template fields; an LLM judge for clarity and accuracy, checked by spot reviews.
  - Efficiency: number of tool calls, tokens and wall-clock time.
- **Online feedback.** Engineers rate each hypothesis or summary (👍/👎 plus a correction). Store these ratings and feed corrections back into the similar-incident index.

---

## 11. Phased roadmap

### Phase 0: Foundations (1–2 weeks)
- [ ] Set up the repository scaffold, a FastMCP server, pydantic models and the connector interfaces
- [ ] Build mock connectors plus 5–10 fixture incidents
- [ ] Get the MCP Inspector and Claude Code connecting over stdio
- [ ] Write a first version of the eval harness

### Phase 1: Analysis + escalation (read-only, 2–3 weeks) — *fastest value*
- [ ] `get_incident`, `get_alerts`, `search_logs`, `query_metrics`, `get_recent_changes`, `get_service_topology`, `build_incident_timeline`, `get_incident_context`
- [ ] `generate_escalation_summary` (returns text, posts nothing)
- [ ] Prompts: `triage_incident`, `escalation_summary`
- [ ] Real adapters for **your** ITSM, logs, metrics and deploy sources (start with the top one of each)
- [ ] Redaction and audit logging
- [ ] Pilot with 3–5 engineers in Claude Code or Desktop

### Phase 2: RCA + remediation planning (3–4 weeks)
- [ ] `correlate_changes_with_symptoms`, `analyze_error_patterns`, `compare_windows`, `check_dependency_health`
- [ ] Similar-incident index (backfill postmortems), `find_similar_incidents`
- [ ] `search_runbooks`, `get_runbook`, `get_rollback_options`
- [ ] `record_rca_hypothesis`, `propose_remediation_plan`, `verify_recovery`
- [ ] Prompts: `root_cause_analysis`, `remediation_plan`, `full_incident_workflow`
- [ ] Run the evals on the golden dataset and tune the correlation heuristics

### Phase 3: Controlled actions + integration (ongoing)
- [ ] `post_update`, `escalate_incident` with confirmation
- [ ] `execute_remediation_step` for a small allow-list, with approvals and dry run
- [ ] Deploy the HTTP transport centrally with OAuth
- [ ] Slack bot or Agent SDK app that starts automatically on new SEV1/SEV2 incidents and posts a triage summary within minutes
- [ ] `draft_postmortem`, plus a feedback loop into the knowledge base

### Phase 4: Proactive (optional)
- [ ] Run triage automatically on alert storms; suggest deduplicating or linking related incidents
- [ ] Spot trends across incidents (recurring causes, noisy alerts, runbook gaps)

---

## 12. Example end-to-end agent flow

```
User / trigger: "SEV2 INC-1234 checkout errors spiking"
 └─ prompt: full_incident_workflow("INC-1234")
     1. get_incident_context(INC-1234)        → alerts, error spike at 14:02, deploy checkout-api v2.31 at 13:58
     2. analyze_error_patterns(checkout-api)  → NEW: "NullPointerException in PriceCalculator" (0 in baseline)
     3. correlate_changes_with_symptoms(...)  → v2.31 deploy, score 0.92
     4. find_similar_incidents(...)           → INC-0987 (similar NPE after pricing change, fixed by rollback)
     5. record_rca_hypothesis(cause="v2.31 regression in PriceCalculator", confidence=0.85, evidence=[...])
     6. get_rollback_options(checkout-api)    → v2.30 (healthy 3 days)
     7. propose_remediation_plan([rollback to v2.30 → verify error rate < 0.5% → open bug])
     ── HUMAN CHECKPOINT: approve plan ──
     8. execute_remediation_step(rollback, approval_token=…)   [phase 3]
     9. verify_recovery(checkout-api)         → recovered at 14:21
    10. generate_escalation_summary(audience="management") → post_update(#inc-1234)  [confirmed]
```

---

## 13. Open questions to decide early

1. Which ITSM, observability and deploy tools are actually in use? This decides the first adapters.
2. Where will agents run: local IDE or desktop, a central service, or a chat bot? This decides stdio vs. HTTP and how auth works.
3. Data residency and PII rules for sending logs or tickets to an LLM provider.
4. Who can approve production actions, and how is approval recorded?
5. Is there a body of past postmortems to seed the similar-incident index and the eval set?
6. Which language and runtime does the team support: Python or TypeScript?

---

## 14. Immediate next steps

1. Answer the open questions in §13 (mainly the tool inventory).
2. Collect 10 representative past incidents with their logs, metrics, changes and final RCA to use as fixtures and evals.
3. Build Phase 0 with mock connectors, and demo `get_incident_context` → `generate_escalation_summary` in Claude Code.
4. Replace the mocks with real read-only adapters one source at a time, then pilot.
