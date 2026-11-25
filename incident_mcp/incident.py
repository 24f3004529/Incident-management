"""Incident Resolution MCP tools.

Simple, deterministic tools that help an agent analyse IT incidents, find likely root causes,
suggest remediation steps and write escalation summaries.

The tools only read the text they are given and the knowledge files in ``knowledge/``.
They never change a real system. The rules (keywords, causes, steps, runbooks, escalation
policy) live in YAML so they can be tuned without code changes.

Every public method is a tool. Its docstring (description, expose, tags, args) is the tool
definition, and every tool returns a dict with ``success`` and never raises.
"""

from __future__ import annotations

import functools
import inspect
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any, Callable

import yaml
from loguru import logger

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_KNOWLEDGE_DIR = PACKAGE_DIR / "knowledge"
DEFAULT_TEMPLATES_DIR = PACKAGE_DIR / "templates"

PHASE_ORDER = {"diagnose": 0, "mitigate": 1, "fix": 2, "verify": 3}
LIKELIHOOD_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_LOG_LINES = 50_000

# --------------------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------------------

_TS_PATTERN = (
    r"\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp][Mm])?"
)
_LEADING_TS_RE = re.compile(
    r"^\s*\[?(?P<ts>" + _TS_PATTERN + r")\]?\s*(?:UTC|utc|GMT)?\s*(?:[-–|,]\s*|:\s+)?(?P<text>.*)$"
)
_LEVEL_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|FATAL|CRIT(?:ICAL)?|SEVERE)\b", re.IGNORECASE
)
_LEVEL_MAP = {"WARNING": "WARN", "ERR": "ERROR", "CRIT": "FATAL", "CRITICAL": "FATAL", "SEVERE": "FATAL"}
_ERRORISH_RE = re.compile(
    r"\b(exception|error|failed|failure|fatal|refused|timed out|timeout|traceback|panic)\b", re.IGNORECASE
)
_CONTINUATION_RE = re.compile(r"^\s+(at\s|\.\.\.\s\d+\smore|File\s\")")

_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_HEX_RE = re.compile(r"\b0x[0-9a-f]+\b", re.IGNORECASE)
_LONG_ID_RE = re.compile(r"\b(?=[0-9a-f]*\d)[0-9a-f]{12,}\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"[A-Z]{2,}[-_]\d+|\b[45]\d\d\b|\d+(?:\.\d+)?")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)\b(\s*[=:]\s*|\s+)([^\s,;]+)"
)

_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "are", "was", "were", "has", "have", "had",
    "not", "but", "all", "after", "into", "about", "than", "then", "when", "which", "while", "our",
    "their", "its", "per", "via", "out", "off", "too", "can", "cannot", "being", "been", "some",
    "users", "user", "service", "services", "error", "errors", "issue", "incident",
}
_SERVICE_STOPWORDS = {
    "the", "a", "an", "external", "third-party", "this", "that", "our", "their", "every", "each",
    "rest", "public", "internal", "same", "new", "old", "web", "any", "calling", "call", "to", "from",
}
_BLAME_WORDS = ["human error", "someone", "operator error", "forgot", "careless", "fault of", "his fault", "her fault"]
_SYMPTOM_WORDS = ["error", "errors", "slow", "down", "failed", "failing", "timeout", "high", "spike"]


@functools.lru_cache(maxsize=4096)
def _keyword_re(keyword: str) -> re.Pattern[str]:
    """Whole-word, case-insensitive match for a keyword or phrase, allowing a plural ending."""
    return re.compile(r"(?<![a-z0-9])" + re.escape(keyword.lower()) + r"(?:s|es)?(?![a-z0-9])")


def _find_keywords(text: str, keywords: list[Any]) -> list[str]:
    lowered = text.lower()
    return [str(k) for k in keywords if _keyword_re(str(k)).search(lowered)]


def _redact(text: str) -> str:
    """Hide e-mail addresses and obvious secrets before text is returned to the agent."""
    text = _EMAIL_RE.sub("<email>", text)
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)


def _parse_time(value: Any) -> datetime | None:
    """Parse ISO, 'YYYY-MM-DD HH:MM' or time-only strings. Time-only values get the year 1900."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = re.sub(r"\s*(UTC|utc|GMT)$", "", str(value).strip().strip("[]"))
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace(",", "."))
        except ValueError:
            dt = None
            for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%H:%M:%S", "%H:%M", "%I:%M %p", "%I:%M%p"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if dt is None:
                return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _align(dt: datetime, reference: datetime | None) -> datetime:
    """Give a time-only value (year 1900) the date of a reference that has a real date."""
    if reference is not None and dt.year == 1900 and reference.year != 1900:
        return datetime.combine(reference.date(), dt.time())
    return dt


def _split_event(event: Any) -> tuple[str, str]:
    """Split an event into (timestamp, text). Accepts 'HH:MM - text' strings or dicts."""
    if isinstance(event, dict):
        ts = event.get("time") or event.get("timestamp") or event.get("ts") or ""
        text = event.get("event") or event.get("description") or event.get("text") or ""
        return str(ts), str(text)
    match = _LEADING_TS_RE.match(str(event))
    if match:
        return match.group("ts"), match.group("text").strip()
    return "", str(event).strip()


def _bullets(items: list[str], empty: str = "None yet") -> str:
    items = [str(i).strip() for i in items if str(i).strip()]
    return "\n".join(f"- {i}" for i in items) if items else f"- {empty}"


def _first_sentence(text: str, limit: int = 120) -> str:
    sentence = re.split(r"(?<=[.!?])\s", text.strip(), maxsplit=1)[0]
    return sentence if len(sentence) <= limit else sentence[: limit - 3].rstrip() + "..."


def _tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if len(t) > 2 and t not in _STOPWORDS]


def _normalize_severity(value: Any) -> str | None:
    match = re.fullmatch(r"(?i)\s*(?:sev(?:erity)?|p|s)?\s*[-_ ]?\s*([1-4])\s*", str(value or ""))
    return f"SEV{match.group(1)}" if match else None


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return False


def _tool(*required: str) -> Callable[[Callable[..., dict[str, Any]]], Callable[..., dict[str, Any]]]:
    """Shared behaviour for every tool: start log, required-argument check, and never raise.

    functools.wraps keeps the original name, docstring and signature, so tool discovery
    (docstring parsing and signature inspection) works the same as on an undecorated method.
    """

    def decorator(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        signature = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
            logger.info(f"{fn.__name__} started")
            try:
                bound = signature.bind(self, *args, **kwargs)
                for name in required:
                    if _is_empty(bound.arguments.get(name)):
                        message = "incident text is empty" if name == "incident" else f"{name} is empty"
                        return {"success": False, "error": message}
                return fn(self, *args, **kwargs)
            except Exception as e:  # noqa: BLE001 - tools must never raise
                logger.error(f"Error in {fn.__name__}: {e}")
                return {"success": False, "error": str(e)}

        return wrapper

    return decorator


# --------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------


class IncidentResolution:
    """IncidentResolution - MCP tools to analyse, diagnose, remediate and escalate IT incidents."""

    def __init__(self, knowledge_dir: str | Path | None = None, templates_dir: str | Path | None = None) -> None:
        logger.info("Initializing IncidentResolution")
        self.knowledge_dir = Path(knowledge_dir) if knowledge_dir else DEFAULT_KNOWLEDGE_DIR
        self.templates_dir = Path(templates_dir) if templates_dir else DEFAULT_TEMPLATES_DIR

        self.categories: dict[str, Any] = self._load_yaml("categories.yaml")
        self.causes: dict[str, list[dict[str, Any]]] = self._load_yaml("causes.yaml")
        self.remediation: dict[str, Any] = self._load_yaml("remediation.yaml")
        self.runbooks: list[dict[str, Any]] = self._load_yaml("runbooks.yaml").get("runbooks", [])
        self.escalation: dict[str, Any] = self._load_yaml("escalation.yaml")
        self.severity_rules: dict[str, Any] = self._load_yaml("severity.yaml")
        self.past_incidents: list[dict[str, Any]] = self._load_past_incidents()
        self.templates: dict[str, str] = {
            p.stem: p.read_text(encoding="utf-8") for p in sorted(self.templates_dir.glob("*.md"))
        }
        self._validate_knowledge()
        self._similarity_index = self._build_similarity_index()
        logger.success("IncidentResolution initialized")

    # ---------------------------------------------------------------- health

    @_tool()
    def health_check(self) -> dict[str, Any]:
        """
        description:
            Check the health status of the IncidentResolution service.
            It also reports how much knowledge was loaded (categories, causes, runbooks and past incidents).

        expose:
            - mcp
            - fastapi

        tags:
            - health
            - status
        """
        return {
            "success": True,
            "status": "healthy",
            "service": "incident_mcp",
            "knowledge": {
                "categories": len(self.categories),
                "causes": sum(len(v) for v in self.causes.values()),
                "runbooks": len(self.runbooks),
                "past_incidents": len(self.past_incidents),
            },
        }

    # ---------------------------------------------------------------- A. analysis

    @_tool("incident")
    def classify_incident(self, incident: str) -> dict[str, Any]:
        """
        description:
            Use this tool when the user wants to know what type of incident it is, or as a first step before looking for causes or fixes.
            Classify an IT incident into one category. The categories are Database, Memory,
            Performance, Network, Disk, Application, Deployment, Security, Dependency, Auth or Other.
            How it works. It looks for whole-word keywords for every category (for example
            database, deadlock, oom, cpu, timeout, dns, disk full, exception, deploy, breach,
            third-party, certificate). Each keyword has a weight, the weights are added up per
            category and the highest score wins. If no keyword matches, the category is Other.
            It expects an incident string with a free-text description, for example
            classify_incident("Database response time is above threshold").
            It returns a dict with success, category, confidence (0 to 1), matched_keywords and
            scores for every category that matched. If the text is empty it returns success false
            and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - classification

        args:
            incident:
                description: Free-text description of the incident
                required: true
        """
        return {"success": True, **self._classify(incident)}

    @_tool("incident")
    def assess_severity(
        self,
        incident: str,
        users_affected: int | None = None,
        is_production: bool | None = None,
        revenue_impact: bool = False,
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks how serious an incident is, what priority it should get, or before deciding whether to escalate.
            Assess the severity of an IT incident as SEV1 (critical), SEV2 (major), SEV3 (minor) or SEV4 (low).
            How it works. It starts at SEV3 and applies simple rules. Words such as outage,
            is down, all users or data loss raise it to SEV1. Words such as degraded, partial,
            intermittent or some users raise it to SEV2. The number or percentage of affected users
            and revenue impact can raise it too. Staging, test or single-user incidents are capped
            at SEV3. If is_production is not given it is guessed from the text.
            It expects an incident string and optional users_affected, is_production and
            revenue_impact, for example assess_severity("Checkout is down for all users", is_production=True).
            It returns a dict with success, severity, label, level (1 to 4), reasons (a list),
            is_production, users_affected and percent_affected. If the text is empty it returns
            success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - severity

        args:
            incident:
                description: Free-text description of the incident
                required: true
            users_affected:
                description: Optional number of users affected
                required: false
            is_production:
                description: Optional flag, true if production is affected
                required: false
            revenue_impact:
                description: Optional flag, true if the incident affects revenue (default false)
                required: false
        """
        return {"success": True, **self._assess_severity(incident, users_affected, is_production, revenue_impact)}

    @_tool("incident")
    def extract_incident_details(self, incident: str) -> dict[str, Any]:
        """
        description:
            Use this tool when the user pastes an incident description, alert or ticket text and you need the key facts from it.
            Extract structured details from free incident text.
            How it works. It uses regular expressions to find service names (for example
            checkout-api or Payment API), host names, IP addresses, HTTP status codes, error codes
            (for example ORA-00060 or ECONNREFUSED), exception names, ticket IDs, timestamps and
            measured values (for example 98%, 450 ms or 2 GB).
            It expects an incident string, for example
            extract_incident_details("checkout-api on web-03 returning 503 since 14:05, CPU at 98%").
            It returns a dict with success, services, hosts, ip_addresses, http_status_codes,
            error_codes, exceptions, ticket_ids, timestamps and metrics (all lists). If the text is
            empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - extraction

        args:
            incident:
                description: Free-text description of the incident, alert or ticket
                required: true
        """
        return {"success": True, **self._extract_details(incident)}

    @_tool("log_text")
    def analyze_logs(self, log_text: str, top_k: int = 5) -> dict[str, Any]:
        """
        description:
            Use this tool when the user pastes log lines and wants to know which errors are happening, how often, and since when.
            Summarise raw log lines into error patterns instead of reading them one by one.
            How it works. It finds the log level of each line, then turns error lines into a
            signature by replacing numbers, IDs, UUIDs and IP addresses with placeholders, so the
            same error from different requests is counted once. It counts each signature and
            records when it was first and last seen. Stack trace lines are skipped. E-mail
            addresses and secrets are hidden in the sample lines.
            It expects log_text with one log line per line and an optional top_k (default 5),
            for example analyze_logs("2026-11-25 14:05:01 ERROR Timeout acquiring connection from pool").
            It returns a dict with success, total_lines, levels (count per level), error_lines,
            error_rate, top_errors (signature, count, level, first_seen, last_seen, sample),
            top_warnings and category_hint. If the text is empty it returns success false and an
            error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - logs
            - analysis

        args:
            log_text:
                description: Raw log lines, one per line
                required: true
            top_k:
                description: How many error patterns to return (default 5)
                required: false
        """
        return {"success": True, **self._analyze_logs(log_text, int(top_k))}

    @_tool("events")
    def build_timeline(self, events: list[Any]) -> dict[str, Any]:
        """
        description:
            Use this tool when the user gives a set of events, alerts or notes with times and wants them in order or wants to know how long the incident lasted.
            Sort incident events into a timeline and compute the gaps between them.
            How it works. Each event is a string that starts with a time, such as
            "14:05 - Alert fired" or "2026-11-25T14:05:00Z Pod restarted", or a dict with time and
            event keys. Times without a date get the date of the first dated event. Events are sorted
            by time, and the minutes from the start and since the previous event are added.
            It expects events as a list, for example
            build_timeline(["14:20 - Pod restarted", "14:05 - Alert fired"]).
            It returns a dict with success, timeline (time, event, minutes_from_start, gap_minutes),
            start, end, duration_minutes and unparsed (events without a readable time). If the
            list is empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - timeline

        args:
            events:
                description: List of events, each one a string that starts with a time or a dict with time and event
                required: true
        """
        return {"success": True, **self._build_timeline(events)}

    @_tool("incident")
    def find_similar_incidents(self, incident: str, top_k: int = 3) -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks whether this has happened before, or to find how a similar incident was fixed in the past.
            Find past incidents that are similar to the current one.
            How it works. It compares the words of the incident with the title, description,
            category and root cause of past incidents in the knowledge base, using TF-IDF cosine
            similarity. Matches below a similarity of 0.1 are left out.
            It expects an incident string and an optional top_k (default 3), for example
            find_similar_incidents("Checkout returns 500 with too many connections").
            It returns a dict with success and matches (id, title, similarity, category,
            root_cause, fix). If the text is empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - knowledge
            - similarity

        args:
            incident:
                description: Free-text description of the incident
                required: true
            top_k:
                description: How many matches to return (default 3)
                required: false
        """
        return {"success": True, "matches": self._similar(incident, int(top_k))}

    # ---------------------------------------------------------------- B. root cause

    @_tool("incident")
    def find_root_cause(self, incident: str, log_text: str = "") -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks why an incident happened or what could be causing it.
            Return the most likely root causes of an IT incident, ranked by likelihood.
            How it works. It classifies the incident with the same keyword rules as
            classify_incident, then ranks the known causes for that category by how many of each
            cause's indicator words appear in the incident text and the optional log lines.
            Two or more matches give high likelihood, one gives medium, none gives low. Each cause
            comes with the matched evidence and a check the engineer can run to confirm it.
            The causes are hypotheses, not confirmed facts.
            It expects an incident string and optional log_text, for example
            find_root_cause("Database response time is above threshold").
            It returns a dict with success, category, top_cause and possible_causes (a list of
            cause, likelihood, evidence and check_to_confirm). If the text is empty it returns
            success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - root-cause

        args:
            incident:
                description: Free-text description of the incident
                required: true
            log_text:
                description: Optional log lines or error messages related to the incident
                required: false
        """
        text = f"{incident}\n{log_text or ''}"
        category = self._classify(text)["category"]
        ranked = self._rank_causes(category, text)
        return {
            "success": True,
            "category": category,
            "top_cause": ranked[0]["cause"] if ranked else None,
            "possible_causes": ranked,
        }

    @_tool("incident_start", "changes")
    def correlate_with_changes(
        self, incident_start: str, changes: list[Any], service: str = "", window_hours: float = 24
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks whether a recent deploy, configuration change or release could have caused the incident.
            Rank recent changes by how likely they are to be related to the incident.
            How it works. Each change gets a score from 0 to 1. Changes made shortly before the
            incident start score higher (60% of the score), changes to the affected service score
            higher (30%), and risky change types such as migrations, configuration or feature flags
            add the rest. Changes after the incident start, or older than window_hours, score 0.
            It expects incident_start as a time (ISO or HH.MM style), changes as a list of dicts with
            time, service and description (or strings that start with a time), and optional service
            and window_hours (default 24), for example
            correlate_with_changes("2026-11-25T14:05:00", ["2026-11-25T13:58:00 - Deploy checkout-api v2.31"], service="checkout-api").
            It returns a dict with success, top_suspect and suspect_changes (time, service,
            description, minutes_before_incident, score, reasons), sorted by score. If an input is
            empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - root-cause
            - change-management

        args:
            incident_start:
                description: When the incident started, as an ISO date-time or a time of day
                required: true
            changes:
                description: List of recent changes, each a dict with time, service and description
                required: true
            service:
                description: Optional name of the affected service
                required: false
            window_hours:
                description: Only changes within this many hours before the incident count (default 24)
                required: false
        """
        return {"success": True, **self._correlate_changes(incident_start, changes, service, float(window_hours))}

    @_tool("incident")
    def five_whys(self, incident: str, answers: list[str] | None = None) -> dict[str, Any]:
        """
        description:
            Use this tool when the user wants to run a 5 whys root cause analysis, or to guide a person step by step from the symptom to the underlying cause.
            Build and check a 5 whys chain for an incident.
            How it works. The first question asks why the incident happened. Each answer becomes
            the subject of the next why question, up to five. The tool returns the next question
            to ask until five answers are given. It warns when an answer blames a person (the
            review should be blameless) or when the last answer still sounds like a symptom. It
            also lists known causes for the incident category as hints.
            It expects an incident string and an optional list of answers given so far, for example
            five_whys("Checkout returned 500 errors", ["The database refused new connections"]).
            It returns a dict with success, chain (why, question, answer), next_question, complete,
            suggested_root_cause, warnings and hints. If the text is empty it returns success false
            and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - root-cause
            - five-whys

        args:
            incident:
                description: Free-text description of the incident
                required: true
            answers:
                description: Optional list of answers given so far, in order
                required: false
        """
        return {"success": True, **self._five_whys(incident, answers or [])}

    # ---------------------------------------------------------------- C. remediation

    @_tool("incident")
    def generate_remediation(self, incident: str, root_cause: str = "") -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks what to do to fix an incident or which steps to follow.
            Return an ordered list of remediation steps for an IT incident.
            How it works. It classifies the incident with the same keyword rules and looks up the
            recommended steps for that category. If a root cause is given and specific steps exist
            for it, those steps are used instead. Steps are ordered as a quick diagnosis, then
            mitigation to restore service, then the lasting fix, then verification. Every step has
            a risk level, a way to verify it and a way to roll it back. Medium and high risk steps
            are marked requires_approval. The steps are only recommendations, the tool does not
            change any real system.
            It expects an incident string and an optional root_cause, for example
            generate_remediation("Memory usage is very high", root_cause="Memory leak").
            It returns a dict with success, category, matched_cause, strategy (mitigate or fix),
            steps (order, phase, action, risk, requires_approval, verification, rollback) and note.
            If the text is empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - remediation

        args:
            incident:
                description: Free-text description of the incident
                required: true
            root_cause:
                description: Optional known or suspected root cause
                required: false
        """
        return {"success": True, **self._remediation(incident, root_cause)}

    @_tool()
    def get_runbook(self, category: str = "", root_cause: str = "") -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks for the runbook, procedure or documented steps for a type of incident or a root cause.
            Find the runbook for an incident category or root cause.
            How it works. It first looks for a runbook that lists the root cause, then falls back
            to the runbook for the category. A category that is not a known name is classified
            with the same keyword rules as classify_incident.
            It expects a category or a root_cause (at least one), for example
            get_runbook(root_cause="Database connection pool exhaustion") or get_runbook(category="Disk").
            It returns a dict with success, found and runbook (id, title, category, owner, link,
            steps). If no runbook matches, found is false. If both inputs are empty it returns
            success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - remediation
            - runbook

        args:
            category:
                description: Optional incident category, for example Database or Network
                required: false
            root_cause:
                description: Optional root cause, for example Disk full
                required: false
        """
        if _is_empty(category) and _is_empty(root_cause):
            return {"success": False, "error": "category or root_cause is required"}
        runbook = self._find_runbook(category or "", root_cause or "")
        if runbook is None:
            return {"success": True, "found": False, "runbook": None, "message": "No runbook found"}
        return {"success": True, "found": True, "runbook": runbook}

    @_tool("metric_name")
    def verify_recovery(
        self, metric_name: str, before: float, after: float, threshold: float, higher_is_better: bool = False
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when the user has applied a fix and wants to know whether the service has recovered.
            Compare a metric before and after a fix with a healthy threshold.
            How it works. For metrics where lower is better (error rate, latency, CPU) the service
            has recovered when the after value is at or below the threshold. For metrics where
            higher is better (success rate, throughput) set higher_is_better to true, and the after
            value must be at or above the threshold. It also reports the improvement in percent.
            It expects metric_name, before, after, threshold and optional higher_is_better (default
            false), for example verify_recovery("error_rate_pct", before=12.5, after=0.4, threshold=1).
            It returns a dict with success, metric_name, recovered, status (recovered, improving,
            not recovered or worse) and improvement_pct. If metric_name is empty it returns success
            false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - remediation
            - verification

        args:
            metric_name:
                description: Name of the metric, for example error_rate_pct or p99_latency_ms
                required: true
            before:
                description: Metric value during the incident
                required: true
            after:
                description: Metric value after the fix
                required: true
            threshold:
                description: Healthy value the metric must reach
                required: true
            higher_is_better:
                description: Set to true when a higher value is healthier (default false)
                required: false
        """
        before_v, after_v, threshold_v = float(before), float(after), float(threshold)
        if higher_is_better:
            recovered = after_v >= threshold_v
            improved = after_v > before_v
            change = after_v - before_v
        else:
            recovered = after_v <= threshold_v
            improved = after_v < before_v
            change = before_v - after_v
        improvement_pct = round(change / abs(before_v) * 100, 1) if before_v else None
        if recovered:
            status = "recovered"
        elif improved:
            status = "improving"
        elif after_v == before_v:
            status = "not recovered"
        else:
            status = "worse"
        return {
            "success": True,
            "metric_name": metric_name,
            "before": before_v,
            "after": after_v,
            "threshold": threshold_v,
            "recovered": recovered,
            "status": status,
            "improvement_pct": improvement_pct,
        }

    # ---------------------------------------------------------------- D. escalation & summaries

    @_tool("category", "severity")
    def determine_escalation(self, category: str, severity: str, minutes_open: int = 0) -> dict[str, Any]:
        """
        description:
            Use this tool when the user asks whether to escalate an incident, to whom, or how long they have before escalation.
            Decide whether an incident should be escalated, to which team and to which tier.
            How it works. Each severity has a time limit (SEV1 15 minutes, SEV2 60, SEV3 240,
            SEV4 1440). An incident open longer than the limit goes to L2, and longer than twice the
            limit goes to L3. Security incidents are always escalated straight away. The team comes
            from a routing table by category. Severity can be written as SEV2, Sev 2, P2 or 2.
            It expects category, severity and minutes_open (default 0), for example
            determine_escalation("Database", "SEV2", minutes_open=75).
            It returns a dict with success, escalate, team, tier, tier_description, reason,
            sla_minutes, minutes_until_escalation, notify_management and next_update_minutes. If the
            severity cannot be read it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - escalation

        args:
            category:
                description: Incident category, for example Database (free text is classified)
                required: true
            severity:
                description: Severity such as SEV1, SEV2, SEV3 or SEV4
                required: true
            minutes_open:
                description: How many minutes the incident has been open (default 0)
                required: false
        """
        result = self._escalation(category, severity, minutes_open)
        if "error" in result:
            return {"success": False, **result}
        return {"success": True, **result}

    @_tool("incident")
    def create_escalation_summary(
        self,
        incident: str,
        actions_taken: list[str] | None = None,
        root_cause: str = "",
        severity: str = "",
        ask: str = "",
        minutes_open: int | None = None,
        status: str = "",
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when the user needs to hand an incident over to another team or the next support tier, or asks for an escalation note.
            Write an engineer-to-engineer escalation summary for an IT incident.
            How it works. It classifies the incident, works out the severity if it is not given,
            finds the team to escalate to, uses the given root cause or the most likely cause as
            the hypothesis, and adds the first recommended remediation steps. It fills a fixed
            template with headline, impact, status, actions taken, hypothesis, next steps, ask and
            next update time.
            It expects an incident string and optional actions_taken (list), root_cause, severity,
            ask, minutes_open and status, for example
            create_escalation_summary("Checkout API 500 errors, too many connections", actions_taken=["Restarted checkout pods"]).
            It returns a dict with success, the fields above, team, tier and summary (markdown).
            If the text is empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - escalation
            - summary

        args:
            incident:
                description: Free-text description of the incident
                required: true
            actions_taken:
                description: Optional list of actions already taken
                required: false
            root_cause:
                description: Optional known or suspected root cause
                required: false
            severity:
                description: Optional severity such as SEV2 (worked out from the text if missing)
                required: false
            ask:
                description: Optional request to the receiving team
                required: false
            minutes_open:
                description: Optional number of minutes the incident has been open
                required: false
            status:
                description: Optional current status, for example Mitigation in progress
                required: false
        """
        category = self._classify(f"{incident} {root_cause or ''}")["category"]
        severity_info = self._assess_severity(incident)
        sev = _normalize_severity(severity) or severity_info["severity"]
        escalation = self._escalation(category, sev, minutes_open or 0)
        team = escalation["team"]
        tier = escalation["tier"] if minutes_open is not None else "on-call"

        if root_cause and root_cause.strip():
            hypothesis = f"{root_cause.strip()} (suspected, not yet confirmed)"
        else:
            ranked = self._rank_causes(category, incident)
            top = ranked[0]
            evidence = f" Evidence: {', '.join(top['evidence'])}." if top["evidence"] else ""
            hypothesis = f"{top['cause']} ({top['likelihood']} likelihood, not confirmed).{evidence}"

        remediation = self._remediation(incident, root_cause or "")
        next_steps = [s["action"] for s in remediation["steps"][:3]]
        actions = [a for a in (actions_taken or []) if str(a).strip()]
        impact = f"{sev} ({self._severity_label(sev)}). " + "; ".join(severity_info["reasons"])
        status_text = status.strip() if status and status.strip() else (
            "Mitigation in progress" if actions else "Investigating"
        )
        ask_text = ask.strip() if ask and ask.strip() else (
            f"Please engage {team} on-call to confirm the hypothesis and help with remediation."
        )
        next_update = f"in {self.escalation['next_update_minutes'][sev]} minutes"
        headline = f"[{sev}] {category} incident - {_first_sentence(incident, 90)}"

        summary = self._render(
            "escalation_summary",
            headline=headline,
            severity=sev,
            category=category,
            team=team,
            tier=tier,
            issue=incident.strip(),
            impact=impact,
            status=status_text,
            actions_taken=_bullets(actions),
            hypothesis=hypothesis,
            next_steps=_bullets(next_steps),
            ask=ask_text,
            next_update=next_update,
        )
        return {
            "success": True,
            "headline": headline,
            "severity": sev,
            "category": category,
            "team": team,
            "tier": tier,
            "impact": impact,
            "status": status_text,
            "actions_taken": actions,
            "hypothesis": hypothesis,
            "next_steps": next_steps,
            "ask": ask_text,
            "next_update": next_update,
            "summary": summary,
        }

    @_tool("incident")
    def create_executive_summary(
        self,
        incident: str,
        severity: str = "",
        duration: str = "",
        users_affected: int | None = None,
        root_cause: str = "",
        status: str = "",
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when the user needs a short report for management that combines the category, the cause and the first action.
            Write a short, non-technical executive summary of an IT incident for management.
            How it works. It classifies the incident with the same keyword rules, works out the
            severity if it is not given, takes the given root cause or the most likely cause and the
            recommended actions for that category, and describes the business impact in plain words.
            A calling agent can turn these fields into a longer narrative.
            It expects an incident string and optional severity, duration, users_affected,
            root_cause and status, for example
            create_executive_summary("CPU usage is saturated at 98%", duration="45 minutes").
            It returns a dict with success, category, severity, issue, root_cause, actions (a list),
            business_impact, status, next_steps, summary (one line) and report (markdown). If the
            text is empty it returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - summary

        args:
            incident:
                description: Free-text description of the incident
                required: true
            severity:
                description: Optional severity such as SEV2 (worked out from the text if missing)
                required: false
            duration:
                description: Optional duration, for example 45 minutes
                required: false
            users_affected:
                description: Optional number of users affected
                required: false
            root_cause:
                description: Optional known or suspected root cause
                required: false
            status:
                description: Optional current status, for example Resolved
                required: false
        """
        category = self._classify(f"{incident} {root_cause or ''}")["category"]
        severity_info = self._assess_severity(incident, users_affected)
        sev = _normalize_severity(severity) or severity_info["severity"]
        cause = root_cause.strip() if root_cause and root_cause.strip() else self._rank_causes(category, incident)[0]["cause"]
        actions = [s["action"] for s in self._remediation(incident, root_cause or "")["steps"]]
        next_steps = actions[:3]
        status_text = status.strip() if status and status.strip() else "Under investigation"

        plain = self.categories.get(category, {}).get("plain", "an IT problem")
        impact_parts = [f"A {sev} ({self._severity_label(sev).lower()}) incident caused by {plain}"]
        if users_affected:
            impact_parts.append(f"affecting about {int(users_affected):,} users")
        elif severity_info["percent_affected"] is not None:
            impact_parts.append(f"affecting about {severity_info['percent_affected']:g}% of users")
        if duration and str(duration).strip():
            impact_parts.append(f"lasting {str(duration).strip()}")
        business_impact = ", ".join(impact_parts) + "."

        summary = (
            f"Incident category: {category}. "
            f"Most likely cause: {cause}. "
            f"First action: {actions[0] if actions else 'Escalate to the on-call engineer'}."
        )
        report = self._render(
            "executive_summary",
            severity=sev,
            severity_label=self._severity_label(sev),
            issue=_first_sentence(incident, 200),
            business_impact=business_impact,
            root_cause=f"{cause} (to be confirmed)" if not root_cause else cause,
            status=status_text,
            next_steps="; ".join(next_steps),
        )
        return {
            "success": True,
            "category": category,
            "severity": sev,
            "issue": incident.strip(),
            "root_cause": cause,
            "actions": actions,
            "business_impact": business_impact,
            "status": status_text,
            "next_steps": next_steps,
            "summary": summary,
            "report": report,
        }

    @_tool("incident")
    def draft_postmortem(
        self,
        incident: str,
        timeline: list[Any] | None = None,
        root_cause: str = "",
        actions_taken: list[str] | None = None,
        impact: str = "",
        action_items: list[str] | None = None,
        severity: str = "",
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when an incident is resolved and the user wants a postmortem, incident report or review document.
            Draft a blameless postmortem for a resolved IT incident.
            How it works. It sorts the timeline with the same rules as build_timeline, works out
            category, severity and duration, and fills a template with the sections Summary, Impact,
            Timeline, Root cause, Resolution, Action items and Lessons learned. If no action items
            are given it suggests some from the lasting fix steps for the category. Missing parts
            are marked to be completed so the team can fill them in.
            It expects an incident string and optional timeline (list of events that start with a
            time), root_cause, actions_taken (list), impact, action_items (list) and severity, for
            example draft_postmortem("Checkout outage", timeline=["14:05 - Alert fired", "14:40 - Rolled back"], root_cause="Bad release").
            It returns a dict with success, title, category, severity, duration_minutes,
            missing_sections and postmortem (markdown). If the text is empty it returns success
            false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - postmortem
            - summary

        args:
            incident:
                description: Free-text description of the incident
                required: true
            timeline:
                description: Optional list of events, each starting with a time
                required: false
            root_cause:
                description: Optional confirmed root cause
                required: false
            actions_taken:
                description: Optional list of actions that resolved the incident
                required: false
            impact:
                description: Optional description of the user or business impact
                required: false
            action_items:
                description: Optional list of follow-up action items
                required: false
            severity:
                description: Optional severity such as SEV2 (worked out from the text if missing)
                required: false
        """
        category = self._classify(f"{incident} {root_cause or ''}")["category"]
        severity_info = self._assess_severity(incident)
        sev = _normalize_severity(severity) or severity_info["severity"]
        todo = "_To be completed._"
        missing: list[str] = []

        timeline_text, duration_minutes = todo, None
        if timeline:
            built = self._build_timeline(timeline)
            lines = [f"**{e['time']}** - {e['event']}" for e in built["timeline"]]
            lines += [f"(time unknown) - {e}" for e in built["unparsed"]]
            timeline_text = _bullets(lines)
            duration_minutes = built["duration_minutes"]
        else:
            missing.append("timeline")

        if root_cause and root_cause.strip():
            root_cause_text = root_cause.strip()
        else:
            missing.append("root_cause")
            ranked = self._rank_causes(category, incident)
            root_cause_text = f"{todo} Leading hypothesis: {ranked[0]['cause']}."

        actions = [a for a in (actions_taken or []) if str(a).strip()]
        if not actions:
            missing.append("resolution")
        items = [a for a in (action_items or []) if str(a).strip()]
        if not items:
            fix_steps = [s["action"] for s in self._remediation(incident, root_cause or "")["steps"] if s["phase"] == "fix"]
            items = fix_steps + [
                "Add or tune monitoring so this is detected earlier",
                "Update the runbook with what was learned",
            ]

        if not impact or not impact.strip():
            impact = f"{sev} ({self._severity_label(sev)}). " + "; ".join(severity_info["reasons"])
        title = _first_sentence(incident, 80)
        duration = f"{duration_minutes:g} minutes" if duration_minutes is not None else "unknown"
        postmortem = self._render(
            "postmortem",
            title=title,
            severity=sev,
            category=category,
            duration=duration,
            summary=incident.strip(),
            impact=impact.strip(),
            timeline=timeline_text,
            root_cause=root_cause_text,
            resolution=_bullets(actions, empty=todo),
            action_items="\n".join(f"- [ ] {i}" for i in items),
        )
        return {
            "success": True,
            "title": title,
            "category": category,
            "severity": sev,
            "duration_minutes": duration_minutes,
            "missing_sections": missing,
            "postmortem": postmortem,
        }

    # ---------------------------------------------------------------- E. composite

    @_tool("incident")
    def triage_incident(
        self,
        incident: str,
        log_text: str = "",
        users_affected: int | None = None,
        is_production: bool | None = None,
        minutes_open: int = 0,
    ) -> dict[str, Any]:
        """
        description:
            Use this tool when the user reports a new incident and wants a full first assessment in one step.
            Run a complete first-pass triage of an IT incident.
            How it works. It runs the same logic as classify_incident, assess_severity,
            extract_incident_details, analyze_logs (only if log_text is given), find_root_cause,
            find_similar_incidents, generate_remediation and determine_escalation, and returns all
            results together with a one-line summary. Root causes are hypotheses and remediation
            steps are recommendations only.
            It expects an incident string and optional log_text, users_affected, is_production and
            minutes_open, for example
            triage_incident("Checkout API returning 500s, logs show too many connections", is_production=True, minutes_open=20).
            It returns a dict with success, summary, classification, severity, details, logs,
            root_cause, similar_incidents, remediation and escalation. If the text is empty it
            returns success false and an error message.

        expose:
            - mcp
            - fastapi

        tags:
            - incident
            - triage

        args:
            incident:
                description: Free-text description of the incident
                required: true
            log_text:
                description: Optional log lines related to the incident
                required: false
            users_affected:
                description: Optional number of users affected
                required: false
            is_production:
                description: Optional flag, true if production is affected
                required: false
            minutes_open:
                description: How many minutes the incident has been open (default 0)
                required: false
        """
        text = f"{incident}\n{log_text or ''}"
        classification = self._classify(text)
        category = classification["category"]
        severity = self._assess_severity(incident, users_affected, is_production)
        logs = self._analyze_logs(log_text, 5) if log_text and log_text.strip() else None
        ranked = self._rank_causes(category, text)
        remediation = self._remediation(text, "")
        escalation = self._escalation(category, severity["severity"], minutes_open or 0)
        summary = (
            f"{severity['severity']} {category} incident. "
            f"Most likely cause: {ranked[0]['cause']} ({ranked[0]['likelihood']} likelihood). "
            f"First step: {remediation['steps'][0]['action'] if remediation['steps'] else 'Escalate'}. "
            + (f"Escalate to {escalation['team']} ({escalation['tier']})." if escalation["escalate"]
               else f"Escalate to {escalation['team']} in {escalation['minutes_until_escalation']:g} minutes if not resolved.")
        )
        return {
            "success": True,
            "summary": summary,
            "classification": classification,
            "severity": severity,
            "details": self._extract_details(incident),
            "logs": logs,
            "root_cause": {"category": category, "top_cause": ranked[0]["cause"], "possible_causes": ranked},
            "similar_incidents": self._similar(text, 3),
            "remediation": remediation,
            "escalation": escalation,
        }

    # ==================================================================================
    # Internal helpers (not tools)
    # ==================================================================================

    def _load_yaml(self, name: str) -> dict[str, Any]:
        path = self.knowledge_dir / name
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path} must contain a mapping at the top level")
        return data

    def _load_past_incidents(self) -> list[dict[str, Any]]:
        path = self.knowledge_dir / "past_incidents.json"
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("incidents", []) if isinstance(data, dict) else list(data)

    def _validate_knowledge(self) -> None:
        for name, table in (("causes.yaml", self.causes), ("remediation.yaml", self.remediation)):
            if "Other" not in table:
                raise ValueError(f"{name} must define the category Other")
        for key in ("sla_minutes", "next_update_minutes", "routing", "tiers"):
            if key not in self.escalation:
                raise ValueError(f"escalation.yaml is missing {key}")
        if "Other" not in self.escalation["routing"]:
            raise ValueError("escalation.yaml routing must define Other")
        for template in ("escalation_summary", "executive_summary", "postmortem"):
            if template not in self.templates:
                raise ValueError(f"templates/{template}.md is missing")

    def _render(self, template: str, **values: Any) -> str:
        return Template(self.templates[template]).safe_substitute(**{k: str(v) for k, v in values.items()})

    def _severity_label(self, severity: str) -> str:
        return self.severity_rules.get("labels", {}).get(severity, severity)

    # ---------------------------------------------------------------- classification

    def _classify(self, text: str) -> dict[str, Any]:
        scores: dict[str, float] = {}
        matched: dict[str, list[str]] = {}
        for category, spec in self.categories.items():
            keywords = {str(k): float(v) for k, v in ((spec or {}).get("keywords") or {}).items()}
            hits = _find_keywords(text, list(keywords))
            if hits:
                scores[category] = sum(keywords[h] for h in hits)
                matched[category] = hits
        if not scores:
            return {"category": "Other", "confidence": 0.0, "matched_keywords": [], "scores": {}}
        best = max(scores, key=lambda c: scores[c])  # ties keep the order of categories.yaml
        return {
            "category": best,
            "confidence": round(scores[best] / sum(scores.values()), 2),
            "matched_keywords": matched[best],
            "scores": dict(sorted(scores.items(), key=lambda kv: -kv[1])),
        }

    def _normalize_category(self, value: str) -> str:
        cleaned = (value or "").strip().lower()
        for category in list(self.categories) + ["Other"]:
            if category.lower() == cleaned:
                return category
        return self._classify(value or "")["category"]

    # ---------------------------------------------------------------- severity

    def _assess_severity(
        self,
        incident: str,
        users_affected: int | None = None,
        is_production: bool | None = None,
        revenue_impact: bool = False,
    ) -> dict[str, Any]:
        rules = self.severity_rules
        thresholds = rules.get("thresholds", {})
        level, reasons = 3, []

        users = int(users_affected) if users_affected not in (None, "") else None
        if users is None:
            m = re.search(r"(\d[\d,]*)\s*\+?\s*(?:users|customers)\b", incident, re.IGNORECASE)
            users = int(m.group(1).replace(",", "")) if m else None
        pct_match = re.search(
            r"(\d{1,3}(?:\.\d+)?)\s?%\s*(?:of\s+)?(?:the\s+|all\s+)?(?:users|customers|traffic|requests)",
            incident,
            re.IGNORECASE,
        )
        percent = float(pct_match.group(1)) if pct_match else None

        if is_production is None:
            if _find_keywords(incident, rules.get("non_production_keywords", [])):
                is_production = False
            elif _find_keywords(incident, rules.get("production_keywords", [])):
                is_production = True

        sev1 = _find_keywords(incident, rules.get("sev1_keywords", []))
        sev2 = _find_keywords(incident, rules.get("sev2_keywords", []))
        if sev1:
            level = 1
            reasons.append(f"Critical impact words found: {', '.join(sev1)}")
        elif sev2:
            level = 2
            reasons.append(f"Major impact words found: {', '.join(sev2)}")

        if users is not None:
            if users >= thresholds.get("sev1_users", 1000):
                level = min(level, 1)
                reasons.append(f"{users:,} users affected")
            elif users >= thresholds.get("sev2_users", 100):
                level = min(level, 2)
                reasons.append(f"{users:,} users affected")
        if percent is not None:
            if percent >= thresholds.get("sev1_percent", 50):
                level = min(level, 1)
                reasons.append(f"{percent:g}% of users or traffic affected")
            elif percent >= thresholds.get("sev2_percent", 10):
                level = min(level, 2)
                reasons.append(f"{percent:g}% of users or traffic affected")
        if revenue_impact:
            level = min(level, 2)
            reasons.append("Revenue impact")

        low = _find_keywords(incident, rules.get("low_impact_keywords", []))
        if is_production is False:
            if level < 3:
                reasons.append("Capped at SEV3 because production is not affected")
            level = max(level, 3)
        elif low:
            if level < 3:
                reasons.append(f"Capped at SEV3 because impact is limited ({', '.join(low)})")
            level = max(level, 3)
        if level == 3 and not reasons and _find_keywords(incident, rules.get("minor_keywords", [])):
            level = 4
            reasons.append("Minor issue with no service impact")
        if is_production is True and level >= 3:
            reasons.append("Production affected")
        if not reasons:
            reasons.append("No clear impact information, default severity")

        severity = f"SEV{level}"
        return {
            "severity": severity,
            "label": self._severity_label(severity),
            "level": level,
            "reasons": reasons,
            "is_production": is_production,
            "users_affected": users,
            "percent_affected": percent,
        }

    # ---------------------------------------------------------------- extraction

    def _extract_details(self, text: str) -> dict[str, Any]:
        def unique(values: list[str]) -> list[str]:
            seen: dict[str, None] = {}
            for v in values:
                v = v.strip()
                if v and v.lower() not in {s.lower() for s in seen}:
                    seen[v] = None
            return list(seen)

        ticket_ids = unique(re.findall(r"\b(?:INC|CHG|PRB|RITM|REQ|SR|TKT)[-_]?\d+\b", text, re.IGNORECASE))
        ticket_set = {t.upper() for t in ticket_ids}

        iso = re.findall(r"\b\d{4}-\d{2}-\d{2}[T ]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", text)
        rest = text
        for value in iso:
            rest = rest.replace(value, " ")
        times = re.findall(r"(?<![\d:.])(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:\s?(?:AM|PM|am|pm|UTC|utc))?(?![\d:])", rest)

        ips = [ip for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text) if all(int(p) <= 255 for p in ip.split("."))]

        http_codes = re.findall(
            r"(?i)(?:\bhttp\s*|\bstatus(?:\s*code)?\s*[=:]?\s*|\bcode\s*[=:]?\s*|\breturn(?:s|ed|ing)?\s+(?:an?\s+)?)([45]\d{2})\b", text
        )
        http_codes += re.findall(r"\b([45]\d{2})s?\s+(?:errors?|responses?|status)\b", text, re.IGNORECASE)
        http_codes += re.findall(r"\b([45]\d{2})s\b", text)
        http_codes += [c.lower() for c in re.findall(r"\b[45]xx\b", text, re.IGNORECASE)]

        error_codes = re.findall(r"\b[A-Z]{2,}[-_]\d{2,6}\b", text)
        error_codes += re.findall(r"\bE[A-Z]{4,}\b", text)
        error_codes += re.findall(r"\bERR_[A-Z_]+\b", text)
        error_codes += re.findall(r"\bSQLSTATE\s*\[?\w+\]?", text)
        error_codes = [c for c in error_codes if c.upper() not in ticket_set and not re.fullmatch(r"(?i)sev[-_]?\d", c)]

        exceptions = re.findall(r"\b[A-Z][A-Za-z0-9]*(?:Exception|Error)\b", text)

        services = re.findall(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-(?:api|service|svc|app|db|web|worker|gateway|server|ui)\b", text)
        for name in re.findall(r"\b([A-Za-z][\w-]*)\s+(?:API|api|Api|service|Service)\b", text):
            if name.lower() not in _SERVICE_STOPWORDS:
                services.append(name.lower())

        hosts = re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|local|internal|corp|cloud|lan)\b", text, re.IGNORECASE)
        hosts += re.findall(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-\d{1,3}[a-z]?\b", text)
        hosts = [h for h in hosts if "@" not in h and h.upper() not in ticket_set]

        metrics = re.findall(
            r"(?<![\w.])\d+(?:\.\d+)?\s?(?:%|ms\b|secs?\b|seconds\b|mins?\b|minutes\b|hours?\b|[KMGT]i?B\b|rps\b|qps\b)",
            text,
        )

        return {
            "services": unique(services),
            "hosts": unique(hosts),
            "ip_addresses": unique(ips),
            "http_status_codes": unique(http_codes),
            "error_codes": unique(error_codes),
            "exceptions": unique(exceptions),
            "ticket_ids": unique(ticket_ids),
            "timestamps": unique(iso + times),
            "metrics": unique(metrics),
        }

    # ---------------------------------------------------------------- logs

    @staticmethod
    def _log_signature(message: str) -> str:
        sig = _UUID_RE.sub("<uuid>", _redact(message))
        sig = _EMAIL_RE.sub("<email>", sig)
        sig = _IP_RE.sub("<ip>", sig)
        sig = _HEX_RE.sub("<hex>", sig)
        sig = _LONG_ID_RE.sub("<id>", sig)
        sig = _NUMBER_RE.sub(lambda m: m.group(0) if re.fullmatch(r"[A-Z]{2,}[-_]\d+|[45]\d\d", m.group(0)) else "<n>", sig)
        sig = re.sub(r"\s+", " ", sig).strip(" -:|[]")
        return sig[:200]

    def _analyze_logs(self, log_text: str, top_k: int = 5) -> dict[str, Any]:
        raw_lines = log_text.splitlines()
        truncated = len(raw_lines) > MAX_LOG_LINES
        lines = [l for l in raw_lines[:MAX_LOG_LINES] if l.strip()]

        levels: Counter[str] = Counter()
        errors: dict[str, dict[str, Any]] = {}
        warnings: dict[str, dict[str, Any]] = {}
        log_lines = error_lines = 0

        for line in lines:
            if _CONTINUATION_RE.match(line):
                continue
            log_lines += 1
            ts_match = _LEADING_TS_RE.match(line)
            timestamp = ts_match.group("ts") if ts_match else None
            message = ts_match.group("text") if ts_match else line.strip()

            level_match = _LEVEL_RE.search(message)
            if level_match:
                level = level_match.group(1).upper()
                level = _LEVEL_MAP.get(level, level)
                message = (message[: level_match.start()] + message[level_match.end():]).strip(" -:|[]")
            elif _ERRORISH_RE.search(message):
                level = "ERROR"
            else:
                level = "UNKNOWN"
            levels[level] += 1

            bucket = errors if level in ("ERROR", "FATAL") else warnings if level == "WARN" else None
            if bucket is None:
                continue
            if bucket is errors:
                error_lines += 1
            signature = self._log_signature(message)
            entry = bucket.setdefault(
                signature,
                {"signature": signature, "count": 0, "level": level, "first_seen": timestamp, "last_seen": timestamp,
                 "sample": _redact(line.strip())[:300]},
            )
            entry["count"] += 1
            if timestamp:
                entry["first_seen"] = entry["first_seen"] or timestamp
                entry["last_seen"] = timestamp
            if level == "FATAL":
                entry["level"] = "FATAL"

        top_errors = sorted(errors.values(), key=lambda e: -e["count"])[: max(top_k, 0)]
        top_warnings = sorted(warnings.values(), key=lambda e: -e["count"])[:3]
        hint_text = " ".join(e["signature"] for e in top_errors) or " ".join(e["signature"] for e in top_warnings)
        return {
            "total_lines": log_lines,
            "truncated": truncated,
            "levels": dict(levels.most_common()),
            "error_lines": error_lines,
            "error_rate": round(error_lines / log_lines, 3) if log_lines else 0.0,
            "unique_errors": len(errors),
            "top_errors": top_errors,
            "top_warnings": top_warnings,
            "category_hint": self._classify(hint_text)["category"] if hint_text else "Other",
        }

    # ---------------------------------------------------------------- timeline

    def _build_timeline(self, events: list[Any]) -> dict[str, Any]:
        parsed: list[tuple[datetime, str, str]] = []
        unparsed: list[str] = []
        for event in events:
            ts, text = _split_event(event)
            dt = _parse_time(ts) if ts else None
            if dt is None:
                unparsed.append(str(event))
            else:
                parsed.append((dt, ts, text))

        reference = next((dt for dt, _, _ in parsed if dt.year != 1900), None)
        parsed = sorted(((_align(dt, reference), ts, text) for dt, ts, text in parsed), key=lambda p: p[0])

        timeline = []
        previous = None
        for dt, ts, text in parsed:
            timeline.append({
                "time": ts,
                "iso": dt.isoformat() if dt.year != 1900 else dt.time().isoformat(),
                "event": text,
                "minutes_from_start": round((dt - parsed[0][0]).total_seconds() / 60, 1),
                "gap_minutes": round((dt - previous).total_seconds() / 60, 1) if previous else 0.0,
            })
            previous = dt
        return {
            "timeline": timeline,
            "start": timeline[0]["time"] if timeline else None,
            "end": timeline[-1]["time"] if timeline else None,
            "duration_minutes": timeline[-1]["minutes_from_start"] if timeline else None,
            "unparsed": unparsed,
        }

    # ---------------------------------------------------------------- similarity

    def _build_similarity_index(self) -> dict[str, Any]:
        docs = []
        for inc in self.past_incidents:
            text = " ".join(str(inc.get(k, "")) for k in ("title", "description", "category", "root_cause"))
            docs.append(Counter(_tokens(text)))
        n = len(docs)
        df: Counter[str] = Counter()
        for doc in docs:
            df.update(doc.keys())
        idf = {term: math.log((n + 1) / (count + 1)) + 1 for term, count in df.items()}
        vectors = [self._tfidf(doc, idf, n) for doc in docs]
        return {"idf": idf, "n": n, "vectors": vectors}

    @staticmethod
    def _tfidf(counts: Counter[str], idf: dict[str, float], n: int) -> dict[str, float]:
        default_idf = math.log(n + 1) + 1
        vector = {t: c * idf.get(t, default_idf) for t, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
        return {t: v / norm for t, v in vector.items()}

    def _similar(self, text: str, top_k: int = 3, min_similarity: float = 0.1) -> list[dict[str, Any]]:
        index = self._similarity_index
        if not index["n"]:
            return []
        query = self._tfidf(Counter(_tokens(text)), index["idf"], index["n"])
        results = []
        for inc, vector in zip(self.past_incidents, index["vectors"]):
            score = sum(w * vector.get(t, 0.0) for t, w in query.items())
            if score >= min_similarity:
                results.append({
                    "id": inc.get("id"),
                    "title": inc.get("title"),
                    "similarity": round(score, 2),
                    "category": inc.get("category"),
                    "root_cause": inc.get("root_cause"),
                    "fix": inc.get("fix"),
                })
        results.sort(key=lambda r: -r["similarity"])
        return results[: max(top_k, 0)]

    # ---------------------------------------------------------------- root cause

    def _rank_causes(self, category: str, text: str) -> list[dict[str, Any]]:
        ranked = []
        for cause in self.causes.get(category) or self.causes["Other"]:
            hits = _find_keywords(text, cause.get("indicators", []) or [])
            ranked.append({
                "cause": cause["cause"],
                "likelihood": "high" if len(hits) >= 2 else "medium" if hits else "low",
                "evidence": hits,
                "check_to_confirm": cause.get("check_to_confirm", ""),
            })
        ranked.sort(key=lambda r: (LIKELIHOOD_ORDER[r["likelihood"]], -len(r["evidence"])))
        return ranked

    def _correlate_changes(
        self, incident_start: str, changes: list[Any], service: str, window_hours: float
    ) -> dict[str, Any]:
        start = _parse_time(incident_start)
        if start is None:
            raise ValueError(f"cannot read incident_start time: {incident_start}")
        risky_words = ["migration", "schema", "config", "configuration", "feature flag", "flag", "upgrade",
                       "hotfix", "database", "network", "firewall", "dns", "certificate", "secret", "rollout"]
        window_minutes = max(window_hours, 0) * 60
        service_l = (service or "").strip().lower()

        results = []
        for change in changes:
            if isinstance(change, dict):
                ts = str(change.get("time") or change.get("timestamp") or "")
                change_service = str(change.get("service") or "")
                description = str(change.get("description") or change.get("summary") or change.get("change") or "")
            else:
                ts, description = _split_event(change)
                change_service = ""
            changed_at = _parse_time(ts)
            entry: dict[str, Any] = {"time": ts, "service": change_service, "description": description}
            if changed_at is None:
                results.append({**entry, "minutes_before_incident": None, "score": 0.0,
                                "reasons": ["Change time could not be read"]})
                continue
            start_aligned = _align(start, changed_at)
            changed_at = _align(changed_at, start_aligned)
            minutes_before = round((start_aligned - changed_at).total_seconds() / 60, 1)
            reasons: list[str] = []

            if minutes_before < 0:
                results.append({**entry, "minutes_before_incident": minutes_before, "score": 0.0,
                                "reasons": ["Change happened after the incident started"]})
                continue
            if minutes_before > window_minutes:
                results.append({**entry, "minutes_before_incident": minutes_before, "score": 0.0,
                                "reasons": [f"Change is older than {window_hours:g} hours"]})
                continue

            time_score = 1 / (1 + minutes_before / 60)
            reasons.append(f"Made {minutes_before:g} minutes before the incident")
            service_score = 0.0
            if service_l:
                if change_service.strip().lower() == service_l:
                    service_score = 1.0
                    reasons.append("Same service as the incident")
                elif service_l in description.lower() or (change_service and change_service.lower() in service_l):
                    service_score = 0.5
                    reasons.append("Mentions the affected service")
            risky = _find_keywords(description, risky_words)
            if risky:
                reasons.append(f"Risky change type: {', '.join(risky)}")
            score = 0.6 * time_score + 0.3 * service_score + (0.1 if risky else 0.0)
            results.append({**entry, "minutes_before_incident": minutes_before, "score": round(score, 2),
                            "reasons": reasons})

        results.sort(key=lambda r: -r["score"])
        top = results[0] if results and results[0]["score"] > 0 else None
        return {"top_suspect": top, "suspect_changes": results}

    def _five_whys(self, incident: str, answers: list[str]) -> dict[str, Any]:
        answers = [str(a).strip() for a in answers if str(a).strip()][:5]
        chain, subject = [], incident.strip().rstrip(".")
        for i, answer in enumerate(answers, start=1):
            chain.append({"why": i, "question": f"Why did this happen? ({subject})", "answer": answer})
            subject = answer.rstrip(".")
        complete = len(answers) >= 5
        next_question = None if complete else f"Why did this happen? ({subject})"

        warnings = []
        for i, answer in enumerate(answers, start=1):
            blame = _find_keywords(answer, _BLAME_WORDS)
            if blame:
                warnings.append(
                    f"Answer {i} blames a person ({', '.join(blame)}). Ask which process or safeguard allowed it to happen."
                )
        if answers and _find_keywords(answers[-1], _SYMPTOM_WORDS):
            warnings.append("The last answer still sounds like a symptom. Ask why once more.")

        category = self._classify(" ".join([incident, *answers]))["category"]
        return {
            "category": category,
            "chain": chain,
            "next_question": next_question,
            "complete": complete,
            "suggested_root_cause": answers[-1] if answers else None,
            "warnings": warnings,
            "hints": [c["cause"] for c in self._rank_causes(category, " ".join([incident, *answers]))],
        }

    # ---------------------------------------------------------------- remediation

    def _match_cause(self, category: str, root_cause: str) -> tuple[str, str] | None:
        """Find (category, cause) with cause-specific steps for a free-text root cause."""
        text = (root_cause or "").strip().lower()
        if not text:
            return None
        categories = [category] + [c for c in self.remediation if c != category]
        for cat in categories:
            for name in (self.remediation.get(cat, {}).get("by_cause") or {}):
                if name.lower() in text or text in name.lower():
                    return cat, name
        ranked = self._rank_causes(category, text)
        if ranked and ranked[0]["evidence"]:
            by_cause = self.remediation.get(category, {}).get("by_cause") or {}
            if ranked[0]["cause"] in by_cause:
                return category, ranked[0]["cause"]
        return None

    def _remediation(self, incident: str, root_cause: str = "") -> dict[str, Any]:
        category = self._classify(f"{incident} {root_cause or ''}")["category"]
        match = self._match_cause(category, root_cause)
        if match:
            category, matched_cause = match
            raw_steps = self.remediation[category]["by_cause"][matched_cause]
        else:
            matched_cause = None
            raw_steps = (self.remediation.get(category) or self.remediation["Other"])["default"]

        ordered = sorted(enumerate(raw_steps), key=lambda p: (PHASE_ORDER.get(p[1].get("phase", "fix"), 2), p[0]))
        steps = []
        for number, (_, step) in enumerate(ordered, start=1):
            risk = step.get("risk", "medium")
            steps.append({
                "order": number,
                "phase": step.get("phase", "fix"),
                "action": step["action"],
                "risk": risk,
                "requires_approval": risk in ("medium", "high"),
                "verification": step.get("verification", ""),
                "rollback": step.get("rollback", "Not applicable"),
            })
        return {
            "category": category,
            "matched_cause": matched_cause,
            "strategy": "mitigate" if any(s["phase"] == "mitigate" for s in steps) else "fix",
            "steps": steps,
            "note": "Recommendations only. Get approval before medium or high risk steps in production.",
        }

    def _find_runbook(self, category: str, root_cause: str) -> dict[str, Any] | None:
        cause = (root_cause or "").strip().lower()
        if cause:
            for rb in self.runbooks:
                for name in rb.get("causes", []) or []:
                    if name.lower() == cause or name.lower() in cause or cause in name.lower():
                        return rb
        if category and category.strip():
            target = self._normalize_category(category)
        elif cause:
            target = self._classify(root_cause)["category"]
        else:
            return None
        return next((rb for rb in self.runbooks if rb.get("category") == target), None)

    # ---------------------------------------------------------------- escalation

    def _escalation(self, category: str, severity: str, minutes_open: int | float | None) -> dict[str, Any]:
        sev = _normalize_severity(severity)
        if sev is None:
            return {"error": f"cannot read severity '{severity}', use SEV1, SEV2, SEV3 or SEV4"}
        minutes = float(minutes_open or 0)
        if minutes < 0:
            return {"error": "minutes_open cannot be negative"}
        cat = self._normalize_category(category)
        esc = self.escalation
        sla = esc["sla_minutes"][sev]
        team = esc["routing"].get(cat, esc["routing"]["Other"])

        if cat in (esc.get("always_escalate_categories") or []):
            escalate, tier = True, "L3" if minutes >= 2 * sla else "L2"
            reason = f"{cat} incidents are always escalated straight away"
        elif minutes >= 2 * sla:
            escalate, tier = True, "L3"
            reason = f"Open {minutes:g} minutes, more than twice the {sev} limit of {sla} minutes"
        elif minutes >= sla:
            escalate, tier = True, "L2"
            reason = f"Open {minutes:g} minutes, past the {sev} limit of {sla} minutes"
        else:
            escalate, tier = False, "L1"
            reason = f"Within the {sev} limit of {sla} minutes"

        return {
            "escalate": escalate,
            "category": cat,
            "severity": sev,
            "team": team,
            "tier": tier,
            "tier_description": esc["tiers"].get(tier, ""),
            "reason": reason,
            "sla_minutes": sla,
            "minutes_until_escalation": 0 if escalate else round(sla - minutes, 1),
            "notify_management": sev in (esc.get("notify_management") or []),
            "next_update_minutes": esc["next_update_minutes"][sev],
        }
