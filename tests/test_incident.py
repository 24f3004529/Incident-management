"""Tests for the IncidentResolution MCP tools."""

from __future__ import annotations

import inspect
import shutil

import pytest
import yaml
from loguru import logger

from incident_mcp import IncidentResolution

logger.remove()

TOOLS = [
    name
    for name, fn in inspect.getmembers(IncidentResolution, inspect.isfunction)
    if not name.startswith("_")
]

LOGS = """2026-11-25 14:05:01 INFO request ok id=123
2026-11-25 14:05:02 ERROR Timeout acquiring connection from pool after 30000 ms request_id=8f14e45f-ceea-467a-9b36-9d3b5c2a1e01
2026-11-25 14:05:03 ERROR Timeout acquiring connection from pool after 30000 ms request_id=1a2b3c4d-ceea-467a-9b36-9d3b5c2a1e01
2026-11-25 14:05:04 WARN Pool usage at 98%
2026-11-25 14:06:10 ERROR too many connections for role app user=bob@example.com password=hunter2
    at com.shop.Db.connect(Db.java:42)
2026-11-25 14:07:00 ERROR Timeout acquiring connection from pool after 30000 ms request_id=5b2c9a1e-ceea-467a-9b36-9d3b5c2a1e01
"""


@pytest.fixture(scope="module")
def ir() -> IncidentResolution:
    return IncidentResolution()


# ------------------------------------------------------------------ tool definitions


@pytest.mark.parametrize("name", TOOLS)
def test_docstring_is_valid_tool_definition(name: str) -> None:
    fn = getattr(IncidentResolution, name)
    raw = fn.__doc__
    assert "\t" not in raw, "tabs break YAML parsing of the docstring"
    doc = yaml.safe_load(inspect.getdoc(fn))
    assert isinstance(doc["description"], str) and doc["description"].strip()
    assert doc["expose"] == ["mcp", "fastapi"]
    assert doc["tags"]
    params = [p for p in inspect.signature(fn).parameters if p != "self"]
    assert list((doc.get("args") or {}).keys()) == params
    for arg in (doc.get("args") or {}).values():
        assert isinstance(arg["description"], str) and isinstance(arg["required"], bool)


@pytest.mark.parametrize("name", [n for n in TOOLS if n != "health_check"])
def test_descriptions_say_when_to_use(name: str) -> None:
    doc = yaml.safe_load(inspect.getdoc(getattr(IncidentResolution, name)))
    assert doc["description"].startswith("Use this tool when")


def test_tools_count(ir: IncidentResolution) -> None:
    assert len(TOOLS) == 18


# ------------------------------------------------------------------ empty input & errors


@pytest.mark.parametrize(
    "name",
    [
        "classify_incident", "assess_severity", "extract_incident_details", "find_similar_incidents",
        "find_root_cause", "five_whys", "generate_remediation", "create_escalation_summary",
        "create_executive_summary", "draft_postmortem", "triage_incident",
    ],
)
@pytest.mark.parametrize("text", ["", "   ", None])
def test_empty_incident_text(ir: IncidentResolution, name: str, text: str | None) -> None:
    assert getattr(ir, name)(text) == {"success": False, "error": "incident text is empty"}


def test_other_required_inputs(ir: IncidentResolution) -> None:
    assert ir.analyze_logs("")["error"] == "log_text is empty"
    assert ir.build_timeline([])["error"] == "events is empty"
    assert ir.correlate_with_changes("14:05", [])["error"] == "changes is empty"
    assert ir.get_runbook()["success"] is False
    assert ir.determine_escalation("Database", "")["success"] is False


def test_tools_never_raise(ir: IncidentResolution) -> None:
    assert ir.verify_recovery("x", before="abc", after=1, threshold=1)["success"] is False
    assert ir.correlate_with_changes("not a time", ["14:00 - deploy"])["success"] is False
    assert ir.classify_incident()["success"] is False  # missing argument


def test_health_check(ir: IncidentResolution) -> None:
    result = ir.health_check()
    assert result["success"] and result["status"] == "healthy"
    assert result["knowledge"]["past_incidents"] > 0


# ------------------------------------------------------------------ classification


@pytest.mark.parametrize(
    "text, category",
    [
        ("Database response time is above threshold", "Database"),
        ("Deadlock detected on orders table", "Database"),
        ("Memory usage is very high, pods OOMKilled", "Memory"),
        ("CPU usage is saturated at 98%", "Performance"),
        ("connection timeout calling payment API", "Network"),
        ("DNS lookups failing for internal hosts", "Network"),
        ("No space left on device on app-01", "Disk"),
        ("NullPointerException in PriceCalculator", "Application"),
        ("Errors started right after the deploy of v2.31", "Deployment"),
        ("Possible breach, suspicious logins from many IPs", "Security"),
        ("Third-party payment provider returning 503", "Dependency"),
        ("TLS certificate expired on partner endpoint", "Auth"),
        ("The office coffee machine is broken", "Other"),
    ],
)
def test_classify_categories(ir: IncidentResolution, text: str, category: str) -> None:
    result = ir.classify_incident(text)
    assert result["success"] and result["category"] == category


def test_classify_whole_words_only(ir: IncidentResolution) -> None:
    # "cpu" must not match inside "occupy"; "db" must not match inside "feedback"
    assert ir.classify_incident("Users occupy all seats and leave feedback")["category"] == "Other"


def test_classify_scores_instead_of_first_match(ir: IncidentResolution) -> None:
    result = ir.classify_incident("Database connection timeout, slow query and deadlock")
    assert result["category"] == "Database"
    assert 0 < result["confidence"] < 1
    assert "Network" in result["scores"]


# ------------------------------------------------------------------ severity


def test_severity_rules(ir: IncidentResolution) -> None:
    assert ir.assess_severity("Checkout is down for all users")["severity"] == "SEV1"
    assert ir.assess_severity("Search is degraded for some users")["severity"] == "SEV2"
    assert ir.assess_severity("Report export is slow")["severity"] == "SEV3"
    assert ir.assess_severity("Typo on the settings page, cosmetic")["severity"] == "SEV4"
    assert ir.assess_severity("Checkout errors in prod, ~30% of users affected")["severity"] == "SEV2"
    assert ir.assess_severity("Checkout errors", users_affected=5000)["severity"] == "SEV1"
    assert ir.assess_severity("Checkout errors", revenue_impact=True)["severity"] == "SEV2"


def test_severity_capped_outside_production(ir: IncidentResolution) -> None:
    result = ir.assess_severity("Staging checkout is down for all users")
    assert result["severity"] == "SEV3" and result["is_production"] is False
    assert ir.assess_severity("Checkout outage", is_production=False)["severity"] == "SEV3"


# ------------------------------------------------------------------ extraction


def test_extract_incident_details(ir: IncidentResolution) -> None:
    result = ir.extract_incident_details(
        "INC-1234: checkout-api on web-03 (10.0.4.12) returning HTTP 503 since 2026-11-25T14:05:00Z, "
        "ORA-00060 and ECONNREFUSED, NullPointerException, CPU at 98%, p99 1200 ms. Payment API slow at 14:10."
    )
    assert result["ticket_ids"] == ["INC-1234"]
    assert "checkout-api" in result["services"] and "payment" in result["services"]
    assert result["hosts"] == ["web-03"]
    assert result["ip_addresses"] == ["10.0.4.12"]
    assert result["http_status_codes"] == ["503"]
    assert set(result["error_codes"]) == {"ORA-00060", "ECONNREFUSED"}
    assert result["exceptions"] == ["NullPointerException"]
    assert result["timestamps"] == ["2026-11-25T14:05:00Z", "14:10"]
    assert result["metrics"] == ["98%", "1200 ms"]


# ------------------------------------------------------------------ logs


def test_analyze_logs_groups_and_counts(ir: IncidentResolution) -> None:
    result = ir.analyze_logs(LOGS)
    assert result["success"]
    assert result["total_lines"] == 6  # stack trace line skipped
    assert result["error_lines"] == 4
    top = result["top_errors"][0]
    assert top["count"] == 3
    assert "<uuid>" in top["signature"] and "<n>" in top["signature"]
    assert top["first_seen"] == "2026-11-25 14:05:02" and top["last_seen"] == "2026-11-25 14:07:00"
    assert result["top_warnings"][0]["signature"] == "Pool usage at <n>%"
    assert result["category_hint"] == "Database"


def test_analyze_logs_redacts_secrets(ir: IncidentResolution) -> None:
    result = ir.analyze_logs(LOGS)
    dump = str(result)
    assert "hunter2" not in dump and "bob@example.com" not in dump
    assert "<redacted>" in dump and "<email>" in dump


def test_analyze_logs_without_levels(ir: IncidentResolution) -> None:
    result = ir.analyze_logs("request failed: connection refused\nrequest ok\n")
    assert result["error_lines"] == 1


# ------------------------------------------------------------------ timeline


def test_build_timeline_sorts_and_measures(ir: IncidentResolution) -> None:
    result = ir.build_timeline(
        ["14:40 - Rolled back", "2026-11-25T14:05:00Z - Alert fired", "14:20 - Pod restarted",
         {"time": "14:10", "event": "On-call paged"}, "no time here"]
    )
    events = [e["event"] for e in result["timeline"]]
    assert events == ["Alert fired", "On-call paged", "Pod restarted", "Rolled back"]
    assert result["duration_minutes"] == 35
    assert result["timeline"][2]["gap_minutes"] == 10
    assert result["unparsed"] == ["no time here"]


# ------------------------------------------------------------------ similar incidents


def test_find_similar_incidents(ir: IncidentResolution) -> None:
    result = ir.find_similar_incidents("Checkout returns 500 with too many connections", top_k=2)
    assert result["matches"][0]["id"] == "INC-1001"
    assert len(result["matches"]) <= 2
    assert ir.find_similar_incidents("zzz qqq")["matches"] == []


# ------------------------------------------------------------------ root cause


def test_find_root_cause_ranks_with_evidence(ir: IncidentResolution) -> None:
    result = ir.find_root_cause("Checkout API 500s", log_text=LOGS)
    assert result["category"] == "Database"
    assert result["top_cause"] == "Database connection pool exhaustion"
    top = result["possible_causes"][0]
    assert top["likelihood"] == "high" and top["evidence"] and top["check_to_confirm"]


def test_find_root_cause_other(ir: IncidentResolution) -> None:
    result = ir.find_root_cause("Something odd happened")
    assert result["category"] == "Other"
    assert result["top_cause"] == "Unknown cause, needs manual review"


def test_correlate_with_changes(ir: IncidentResolution) -> None:
    result = ir.correlate_with_changes(
        "2026-11-25T14:05:00",
        [
            {"time": "2026-11-25T09:00:00", "service": "search", "description": "Config change to cache TTL"},
            {"time": "2026-11-25T13:58:00", "service": "checkout-api", "description": "Deploy v2.31"},
            {"time": "2026-11-25T14:30:00", "service": "checkout-api", "description": "Hotfix"},
            {"time": "2026-11-20T10:00:00", "service": "checkout-api", "description": "Old deploy"},
            "13:30 - DNS record update",
        ],
        service="checkout-api",
    )
    assert result["top_suspect"]["description"] == "Deploy v2.31"
    by_desc = {c["description"]: c for c in result["suspect_changes"]}
    assert by_desc["Hotfix"]["score"] == 0
    assert by_desc["Old deploy"]["score"] == 0
    assert by_desc["DNS record update"]["minutes_before_incident"] == 35


def test_five_whys(ir: IncidentResolution) -> None:
    result = ir.five_whys("Checkout returned 500 errors", ["The database refused new connections",
                                                          "Someone forgot to close connections"])
    assert len(result["chain"]) == 2 and not result["complete"]
    assert "Someone forgot" in result["next_question"]
    assert any("blames a person" in w for w in result["warnings"])
    done = ir.five_whys("x", ["a", "b", "c", "d", "e"])
    assert done["complete"] and done["next_question"] is None and done["suggested_root_cause"] == "e"


# ------------------------------------------------------------------ remediation


def test_generate_remediation_default(ir: IncidentResolution) -> None:
    result = ir.generate_remediation("Database response time is above threshold")
    assert result["category"] == "Database" and result["matched_cause"] is None
    phases = [s["phase"] for s in result["steps"]]
    assert phases == sorted(phases, key=["diagnose", "mitigate", "fix", "verify"].index)
    assert [s["order"] for s in result["steps"]] == list(range(1, len(result["steps"]) + 1))
    for step in result["steps"]:
        assert step["verification"] and step["rollback"]
        assert step["requires_approval"] == (step["risk"] in ("medium", "high"))


def test_generate_remediation_by_cause(ir: IncidentResolution) -> None:
    result = ir.generate_remediation("Memory usage is very high", root_cause="Memory leak")
    assert result["matched_cause"] == "Memory leak"
    assert any("heap dump" in s["action"] for s in result["steps"])
    other = ir.generate_remediation("Site is weird", root_cause="TLS certificate expired")
    assert other["category"] == "Auth" and other["matched_cause"] == "Expired TLS or SSL certificate"


def test_get_runbook(ir: IncidentResolution) -> None:
    assert ir.get_runbook(root_cause="Disk full")["runbook"]["id"] == "RB-DISK-001"
    assert ir.get_runbook(category="network")["runbook"]["id"] == "RB-NET-001"
    assert ir.get_runbook(category="pods OOMKilled")["runbook"]["category"] == "Memory"
    assert ir.get_runbook(category="Other")["found"] is False


@pytest.mark.parametrize(
    "before, after, threshold, higher, status",
    [
        (12.5, 0.4, 1, False, "recovered"),
        (12.5, 5, 1, False, "improving"),
        (12.5, 12.5, 1, False, "not recovered"),
        (12.5, 20, 1, False, "worse"),
        (80, 99.5, 99, True, "recovered"),
    ],
)
def test_verify_recovery(ir: IncidentResolution, before, after, threshold, higher, status) -> None:
    result = ir.verify_recovery("m", before=before, after=after, threshold=threshold, higher_is_better=higher)
    assert result["status"] == status
    assert result["recovered"] == (status == "recovered")


# ------------------------------------------------------------------ escalation & summaries


@pytest.mark.parametrize(
    "category, severity, minutes, escalate, tier",
    [
        ("Database", "SEV2", 10, False, "L1"),
        ("Database", "Sev 2", 75, True, "L2"),
        ("database", "P2", 130, True, "L3"),
        ("Security", "SEV4", 0, True, "L2"),
        ("SEV1", "1", 15, True, "L2"),
    ],
)
def test_determine_escalation(ir: IncidentResolution, category, severity, minutes, escalate, tier) -> None:
    result = ir.determine_escalation(category, severity, minutes_open=minutes)
    assert result["success"] and result["escalate"] == escalate and result["tier"] == tier


def test_determine_escalation_routing(ir: IncidentResolution) -> None:
    assert ir.determine_escalation("Database", "SEV2")["team"] == "DBA Team"
    assert ir.determine_escalation("disk full on app-01", "SEV3")["team"] == "Infrastructure Team"
    assert ir.determine_escalation("Database", "urgent")["success"] is False


def test_create_escalation_summary(ir: IncidentResolution) -> None:
    result = ir.create_escalation_summary(
        "Checkout API 500 errors, too many connections in prod",
        actions_taken=["Restarted checkout pods"],
        severity="SEV2",
        minutes_open=75,
    )
    assert result["success"] and result["team"] == "DBA Team" and result["tier"] == "L2"
    assert "not confirmed" in result["hypothesis"]
    assert "- Restarted checkout pods" in result["summary"]
    assert "in 60 minutes" in result["summary"]
    assert "$" not in result["summary"]


def test_create_executive_summary(ir: IncidentResolution) -> None:
    result = ir.create_executive_summary("CPU usage is saturated at 98%", duration="45 minutes", users_affected=3000)
    assert result["category"] == "Performance"
    assert result["root_cause"] == "High CPU usage"
    assert result["summary"] == (
        "Incident category: Performance. Most likely cause: High CPU usage. First action: Check CPU metrics."
    )
    assert "3,000 users" in result["business_impact"] and "45 minutes" in result["business_impact"]
    assert "$" not in result["report"]


def test_draft_postmortem(ir: IncidentResolution) -> None:
    result = ir.draft_postmortem(
        "Checkout outage after release 2.31",
        timeline=["14:40 - Rolled back", "14:05 - Alert fired"],
        root_cause="Bad release",
        actions_taken=["Rolled back to 2.30"],
    )
    assert result["duration_minutes"] == 35 and result["missing_sections"] == []
    pm = result["postmortem"]
    assert pm.index("Alert fired") < pm.index("Rolled back")
    assert "- [ ]" in pm and "$" not in pm
    assert set(ir.draft_postmortem("Checkout outage")["missing_sections"]) == {"timeline", "root_cause", "resolution"}


def test_triage_incident(ir: IncidentResolution) -> None:
    result = ir.triage_incident(
        "Checkout API returning 500s in prod, ~30% of users",
        log_text=LOGS,
        minutes_open=75,
    )
    assert result["success"]
    assert result["classification"]["category"] == "Database"
    assert result["severity"]["severity"] == "SEV2"
    assert result["logs"]["error_lines"] == 4
    assert result["root_cause"]["top_cause"] == "Database connection pool exhaustion"
    assert result["similar_incidents"][0]["id"] == "INC-1001"
    assert result["escalation"]["escalate"] is True
    assert result["summary"].startswith("SEV2 Database incident.")


# ------------------------------------------------------------------ knowledge files


def test_custom_knowledge_dir_is_validated(tmp_path) -> None:
    from incident_mcp.incident import DEFAULT_KNOWLEDGE_DIR

    knowledge = tmp_path / "knowledge"
    shutil.copytree(DEFAULT_KNOWLEDGE_DIR, knowledge)
    causes = yaml.safe_load((knowledge / "causes.yaml").read_text())
    del causes["Other"]
    (knowledge / "causes.yaml").write_text(yaml.safe_dump(causes))
    with pytest.raises(ValueError, match="Other"):
        IncidentResolution(knowledge_dir=knowledge)


def test_knowledge_consistency(ir: IncidentResolution) -> None:
    categories = set(ir.categories) | {"Other"}
    assert set(ir.causes) == categories
    assert set(ir.remediation) == categories
    assert set(ir.escalation["routing"]) == categories
    cause_names = {c["cause"] for causes in ir.causes.values() for c in causes}
    for spec in ir.remediation.values():
        assert set(spec.get("by_cause") or {}) <= cause_names
    for runbook in ir.runbooks:
        assert set(runbook["causes"]) <= cause_names
        assert runbook["category"] in categories
